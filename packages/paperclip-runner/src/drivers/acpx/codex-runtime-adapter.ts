import type { ChildProcess } from "node:child_process";

import {
  createAcpRuntime,
  createAgentRegistry,
  createRuntimeStore,
  encodeAcpxRuntimeHandleState,
  type AcpAgentRegistry,
  type AcpRuntime,
  type AcpRuntimeHandle,
  type AcpRuntimeOptions,
  type AcpSessionRecord,
  type AcpSessionStore,
} from "acpx/runtime";

import type {
  AcpxRuntimePort,
  AcpxRuntimePortIdentity,
  AcpxRuntimePortOpenOptions,
} from "./runtime-host.js";
import { decideAcpxPermission } from "./permission-policy.js";

const VERIFIED_COMMAND_SENTINEL = "paperclip-verified-acpx-command";
const DEFAULT_RUNTIME_CLOSE_TIMEOUT_MS = 2_000;
const PROVIDER_TERM_EXIT_TIMEOUT_MS = 2_000;
const PROVIDER_KILL_EXIT_TIMEOUT_MS = 2_000;
const MAX_LATE_RUNTIME_CLEANUP_RECONCILIATION_ATTEMPTS = 3;
// Production shutdown waits for the protocol close bound before beginning the
// sequential TERM/KILL verification windows. Keep this exported package-local
// bound aligned with the implementation so admission can include the complete
// provider cleanup path instead of accounting for only part of it.
export const DEFAULT_CODEX_ACPX_RUNTIME_SHUTDOWN_BOUND_MS =
  DEFAULT_RUNTIME_CLOSE_TIMEOUT_MS +
  PROVIDER_TERM_EXIT_TIMEOUT_MS +
  PROVIDER_KILL_EXIT_TIMEOUT_MS;
// A close may outlive its caller-facing wait bound. Keep every exact attempt
// owned until it settles even after the port releases it for a bounded retry.
// This prevents abandoned protocol work from being garbage-collected without
// letting one permanently pending attempt block all future recovery.
const activeRuntimeCleanupOwners = new Set<Promise<unknown>>();

class AcpxRuntimeCloseTimeoutError extends Error {
  constructor() {
    super("ACPX runtime close exceeded its shutdown timeout");
    this.name = "AcpxRuntimeCloseTimeoutError";
  }
}
const activeCodexRuntimeCleanupOwners = new Set<Promise<unknown>>();

export interface CodexAcpxRuntimeDependencies {
  createRuntime?: (options: AcpRuntimeOptions) => AcpRuntime;
  createRegistry?: (input: {
    overrides: Record<string, string | string[]>;
  }) => AcpAgentRegistry;
  createStore?: (input: { stateDir: string }) => AcpSessionStore;
  runtimeCloseTimeoutMs?: number;
}

/**
 * Adapt the pinned ACPX library to Paperclip's admitted runtime port. The
 * executable, launch environment, and spawn cwd stay host-owned and are never
 * persisted in ACPX's session options.
 */
export async function openCodexAcpxRuntime(
  options: AcpxRuntimePortOpenOptions,
  dependencies: CodexAcpxRuntimeDependencies = {},
): Promise<AcpxRuntimePort> {
  if (options.profile.agent !== "codex") {
    throw new Error(
      "The production ACPX runtime currently supports Codex only",
    );
  }
  options.signal?.throwIfAborted();

  const createRegistry = dependencies.createRegistry ?? createAgentRegistry;
  const createStore = dependencies.createStore ?? createRuntimeStore;
  const createRuntime = dependencies.createRuntime ?? createAcpRuntime;
  const runtimeCloseTimeoutMs =
    dependencies.runtimeCloseTimeoutMs ?? DEFAULT_RUNTIME_CLOSE_TIMEOUT_MS;
  const children = new SpawnedChildSet();
  const baseStore = createStore({ stateDir: options.stateDirectory });
  let failedHandshakeHandle: AcpRuntimeHandle | null = null;
  let admissionCleanup: RuntimeAdmissionCleanup | null = null;
  const rememberHandshakeHandle = (record: AcpSessionRecord): void => {
    const runtimeSessionName = record.name?.trim();
    if (
      typeof record.acpxRecordId !== "string" ||
      record.acpxRecordId.length === 0 ||
      !runtimeSessionName ||
      record.cwd !== options.cwd
    ) {
      return;
    }
    const rememberedHandle: AcpRuntimeHandle = {
      sessionKey: options.providerSessionKey,
      backend: "acpx",
      runtimeSessionName: encodeAcpxRuntimeHandleState({
        name: runtimeSessionName,
        agent: "codex",
        cwd: record.cwd,
        mode: "persistent",
        acpxRecordId: record.acpxRecordId,
        backendSessionId: record.acpSessionId,
        agentSessionId: record.agentSessionId,
      }),
      cwd: record.cwd,
      acpxRecordId: record.acpxRecordId,
      backendSessionId: record.acpSessionId,
      ...(record.agentSessionId
        ? { agentSessionId: record.agentSessionId }
        : {}),
    };
    failedHandshakeHandle = rememberedHandle;
    if (options.signal?.aborted && admissionCleanup !== null) {
      retainCodexRuntimeCleanup(
        admissionCleanup.run(
          rememberedHandle,
          "ACPX runtime admission aborted",
        ),
      );
    }
  };
  const sessionStore: AcpSessionStore = {
    async load(sessionId) {
      const record = await baseStore.load(sessionId);
      if (record !== undefined) rememberHandshakeHandle(record);
      return record;
    },
    async save(record) {
      // ACPX has already created this runtime-owned identity before it asks
      // the store to persist it. Capture cleanup authority first so a storage
      // rejection cannot orphan the live session created by the handshake.
      rememberHandshakeHandle(record);
      await baseStore.save(record);
    },
  };
  const runnerOwnedMcpServerNames = new Set(
    options.mcpServers
      .filter((server) => server.runnerOwned)
      .map((server) => server.name),
  );
  const runtime = createRuntime({
    cwd: options.cwd,
    sessionStore,
    agentRegistry: createRegistry({
      overrides: { codex: [VERIFIED_COMMAND_SENTINEL] },
    }),
    permissionMode: options.permissionMode,
    elicitationModes: ["form"],
    nonInteractivePermissions: "fail",
    permissionPolicy: {
      ...options.permissionPolicy,
      autoApprove: options.permissionPolicy.autoApprove
        ? [...options.permissionPolicy.autoApprove]
        : undefined,
      escalate: options.permissionPolicy.escalate
        ? [...options.permissionPolicy.escalate]
        : undefined,
    },
    mcpServers: options.mcpServers.map((server) => ({
      type: "http" as const,
      name: server.name,
      url: server.url,
      headers: [
        { name: "Authorization", value: `Bearer ${server.bearerToken}` },
      ],
    })),
    onPermissionRequest: async (request) => {
      const disposition = decideAcpxPermission(
        options.profile.agent,
        options.permissionMode,
        request,
        {
          runnerOwnedMcpServerNames,
          allConfiguredMcpServersAreRunnerOwned:
            options.mcpServers.length > 0 &&
            options.mcpServers.every((server) => server.runnerOwned),
        },
      );
      return disposition === "delegate" ? undefined : { outcome: disposition };
    },
    spawnEnvironment: () => definedEnvironment(options.launchEnvironment),
    spawnCwd: options.cwd,
    spawnAgent: (input) => {
      // ACPX can invoke this callback after its handshake caller has already
      // been cancelled. Check at the last host-owned boundary so a late
      // handshake cannot create a provider process after authority is gone.
      options.signal?.throwIfAborted();
      return children.add(
        options.command.spawn(input.args, input.options) as ChildProcess,
      );
    },
  });
  admissionCleanup = new RuntimeAdmissionCleanup(
    runtime,
    children,
    runtimeCloseTimeoutMs,
  );

  let handle: AcpRuntimeHandle | null = null;
  try {
    const handshake = Promise.resolve().then(() =>
      runtime.ensureSession({
        sessionKey: options.providerSessionKey,
        agent: "codex",
        mode: "persistent",
        cwd: options.cwd,
        sessionOptions: {
          model: options.profile.qualificationModel,
          ...(options.systemInstructions
            ? { systemPrompt: { append: options.systemInstructions } }
            : {}),
        },
      }),
    );
    if (options.signal === undefined) {
      handle = await handshake;
    } else {
      try {
        handle = await raceRuntimeHandshakeWithAbort(handshake, options.signal);
      } catch (error) {
        if (options.signal.aborted) {
          retainCodexRuntimeCleanup(
            handshake.then((lateHandle) =>
              admissionCleanup!.run(
                lateHandle,
                "ACPX runtime admission aborted",
              ),
            ),
          );
        }
        throw error;
      }
      // The promise and abort notification can settle in the same turn. Do
      // not admit a handle if cancellation won immediately afterward.
      options.signal.throwIfAborted();
    }
  } catch (error) {
    const cleanupErrors = await admissionCleanup.run(
      handle ?? failedHandshakeHandle,
      options.signal?.aborted
        ? "ACPX runtime admission aborted"
        : "ACPX session handshake failed",
    );
    if (cleanupErrors.length > 0) {
      throw new AggregateError(
        [error, ...cleanupErrors],
        "ACPX session handshake and runtime cleanup failed",
      );
    }
    throw error;
  }

  // Assigned by the successful handshake above. Keeping this assertion at the
  // boundary makes it impossible to construct a port from a cancelled or
  // otherwise absent ACPX session.
  if (handle === null)
    throw new Error("ACPX runtime omitted its session handle");
  try {
    return runtimePort(
      runtime,
      handle,
      requireIdentity(handle),
      children,
      runtimeCloseTimeoutMs,
    );
  } catch (error) {
    const cleanupErrors = await admissionCleanup.run(
      handle,
      "ACPX runtime identity validation failed",
    );
    if (cleanupErrors.length > 0) {
      throw new AggregateError(
        [error, ...cleanupErrors],
        "ACPX runtime identity validation and cleanup failed",
      );
    }
    throw error;
  }
}

function raceRuntimeHandshakeWithAbort<T>(
  handshake: Promise<T>,
  signal: AbortSignal,
): Promise<T> {
  signal.throwIfAborted();
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const settle = (operation: () => void): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      operation();
    };
    const onAbort = (): void => settle(() => reject(signal.reason));
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) {
      onAbort();
      return;
    }
    void handshake.then(
      (value) => settle(() => resolve(value)),
      (error: unknown) => settle(() => reject(error)),
    );
  });
}

function retainCodexRuntimeCleanup(cleanup: Promise<unknown>): void {
  activeCodexRuntimeCleanupOwners.add(cleanup);
  void cleanup
    .finally(() => activeCodexRuntimeCleanupOwners.delete(cleanup))
    .catch(() => undefined);
}

class RuntimeAdmissionCleanup {
  readonly #closedHandles = new Set<string>();
  #tail: Promise<void> = Promise.resolve();

  constructor(
    private readonly runtime: AcpRuntime,
    private readonly children: SpawnedChildSet,
    private readonly runtimeCloseTimeoutMs: number,
  ) {}

  run(handle: AcpRuntimeHandle | null, reason: string): Promise<unknown[]> {
    const cleanup = this.#tail.then(async () => {
      const errors: unknown[] = [];
      if (handle !== null) {
        const key = runtimeHandleCleanupKey(handle);
        if (!this.#closedHandles.has(key)) {
          const runtimeError = await boundedRuntimeClose(
            this.runtime,
            handle,
            reason,
            this.runtimeCloseTimeoutMs,
          );
          // A rejection or timeout does not prove the runtime released this
          // identity. Leave it eligible for the next serialized cleanup pass.
          if (runtimeError === null) {
            this.#closedHandles.add(key);
          } else {
            errors.push(runtimeError);
          }
        }
      }
      errors.push(...(await this.children.terminate()));
      return errors;
    });
    this.#tail = cleanup.then(
      () => undefined,
      () => undefined,
    );
    return cleanup;
  }
}

function runtimeHandleCleanupKey(handle: AcpRuntimeHandle): string {
  return JSON.stringify([
    handle.sessionKey,
    handle.runtimeSessionName,
    handle.acpxRecordId,
    handle.backendSessionId,
    handle.agentSessionId,
  ]);
}

function runtimePort(
  runtime: AcpRuntime,
  handle: AcpRuntimeHandle,
  identity: AcpxRuntimePortIdentity,
  children: SpawnedChildSet,
  runtimeCloseTimeoutMs: number,
): AcpxRuntimePort {
  let runtimeClosed = false;
  let runtimeCloseAttempt: Promise<unknown | null> | undefined;
  let runtimeCloseAttemptReconciliationGeneration = 0;
  let lateReconciliationOwner: Promise<void> | undefined;
  // This is a lifetime budget for the port, not a per-failure-generation
  // budget. A released attempt may settle after a newer close succeeds, so
  // replenishing the counter on success would let each older attempt create a
  // fresh fully budgeted reconciliation loop.
  let lateReconciliationAttempts = 0;
  let lateFailureGeneration = 0;
  let reconciledLateFailureGeneration = 0;
  const watchedReleasedAttempts = new Set<Promise<unknown | null>>();

  const hasUnreconciledLateFailure = (): boolean =>
    reconciledLateFailureGeneration < lateFailureGeneration;

  const scheduleLateFailureReconciliation = (): void => {
    if (
      runtimeCloseAttempt ||
      lateReconciliationOwner ||
      !hasUnreconciledLateFailure() ||
      lateReconciliationAttempts >=
        MAX_LATE_RUNTIME_CLEANUP_RECONCILIATION_ATTEMPTS
    ) {
      return;
    }
    const attemptNumber = lateReconciliationAttempts + 1;
    lateReconciliationAttempts = attemptNumber;
    let retry = false;
    const reconciliation = closeRuntime({
      reason: `ACPX late protocol cleanup reconciliation ${attemptNumber}`,
    }).then(
      () => {
        if (hasUnreconciledLateFailure()) {
          retry =
            attemptNumber < MAX_LATE_RUNTIME_CLEANUP_RECONCILIATION_ATTEMPTS;
        }
      },
      () => {
        retry =
          attemptNumber < MAX_LATE_RUNTIME_CLEANUP_RECONCILIATION_ATTEMPTS;
      },
    );
    const owner = reconciliation.finally(() => {
      if (lateReconciliationOwner === owner) lateReconciliationOwner = undefined;
      if (retry || hasUnreconciledLateFailure()) {
        queueMicrotask(scheduleLateFailureReconciliation);
      }
    });
    lateReconciliationOwner = owner;
    retainRuntimeCleanupOwner(owner);
  };

  const watchReleasedAttempt = (attempt: Promise<unknown | null>): void => {
    if (watchedReleasedAttempts.has(attempt)) return;
    watchedReleasedAttempts.add(attempt);
    void attempt.then((error) => {
      watchedReleasedAttempts.delete(attempt);
      if (error === null) return;
      // A newer successful close cannot erase an older outcome that had not
      // settled yet. Re-open cleanup state and autonomously create a bounded
      // reconciliation generation so the late failure is not suppression-only.
      lateFailureGeneration += 1;
      runtimeClosed = false;
      scheduleLateFailureReconciliation();
    });
  };

  async function closeRuntime(input: { reason: string }): Promise<void> {
    if (runtimeClosed) return;
    if (!runtimeCloseAttempt) {
      // A close can reconcile only failures already known when its protocol
      // attempt begins. A released older attempt may reject while this one is
      // in flight; that later generation must trigger a subsequent close.
      runtimeCloseAttemptReconciliationGeneration = lateFailureGeneration;
      runtimeCloseAttempt = runtimeCloseOutcome(runtime, handle, input.reason);
    }
    const observedAttempt = runtimeCloseAttempt;
    const observedReconciliationGeneration =
      runtimeCloseAttemptReconciliationGeneration;
    const processCleanup = terminateChildrenAfterCloseBound(
      observedAttempt,
      children,
      runtimeCloseTimeoutMs,
    );
    // The caller may stop waiting, but the exact ACPX protocol cleanup stays
    // owned until it settles. Provider termination proceeds at the deadline;
    // after this bounded observation finishes a later close may make a fresh
    // protocol attempt instead of inheriting a permanently pending promise.
    const [closeError, processErrors] = await Promise.all([
      boundedCloseOutcome(observedAttempt, runtimeCloseTimeoutMs),
      processCleanup,
    ]);
    if (closeError instanceof AcpxRuntimeCloseTimeoutError) {
      watchReleasedAttempt(observedAttempt);
    }
    if (runtimeCloseAttempt === observedAttempt) {
      runtimeCloseAttempt = undefined;
    }
    if (processErrors.length === 0 && closeError === null) {
      reconciledLateFailureGeneration = Math.max(
        reconciledLateFailureGeneration,
        observedReconciliationGeneration,
      );
      runtimeClosed = !hasUnreconciledLateFailure();
    } else {
      runtimeClosed = false;
    }
    scheduleLateFailureReconciliation();
    if (closeError !== null || processErrors.length > 0) {
      const errors = [closeError, ...processErrors].filter(
        (error): error is unknown => error !== null,
      );
      throw new AggregateError(
        errors,
        "ACPX runtime and provider cleanup failed",
      );
    }
  }

  const port: AcpxRuntimePort = {
    async identity() {
      return structuredClone(identity);
    },
    async getStatus() {
      if (!runtime.getStatus) {
        throw new Error("The pinned ACPX runtime cannot report session status");
      }
      return structuredClone(await runtime.getStatus({ handle }));
    },
    ...(runtime.setConfigOption
      ? {
          async setModel(model: string) {
            await runtime.setConfigOption?.({
              handle,
              key: "model",
              value: model,
            });
          },
        }
      : {}),
    startTurn(input) {
      return runtime.startTurn({
        handle,
        text: input.text,
        mode: "prompt",
        requestId: input.requestId,
        ...(input.signal ? { signal: input.signal } : {}),
        ...(input.onElicitation
          ? { onElicitation: input.onElicitation }
          : {}),
      });
    },
    close: closeRuntime,
  };
  return port;
}

async function boundedRuntimeClose(
  runtime: AcpRuntime,
  handle: AcpRuntimeHandle,
  reason: string,
  timeoutMs: number,
): Promise<unknown | null> {
  return await boundedCloseOutcome(
    runtimeCloseOutcome(runtime, handle, reason),
    timeoutMs,
  );
}

function runtimeCloseOutcome(
  runtime: AcpRuntime,
  handle: AcpRuntimeHandle,
  reason: string,
): Promise<unknown | null> {
  const cleanup = Promise.resolve()
    .then(() =>
      runtime.close({ handle, reason, discardPersistentState: false }),
    )
    .then(
      () => null,
      (error: unknown) => error,
    );
  return retainRuntimeCleanupOwner(cleanup);
}

function retainRuntimeCleanupOwner<T>(cleanup: Promise<T>): Promise<T> {
  activeRuntimeCleanupOwners.add(cleanup);
  void cleanup
    .finally(() => activeRuntimeCleanupOwners.delete(cleanup))
    .catch(() => undefined);
  return cleanup;
}

async function terminateChildrenAfterCloseBound(
  closeOutcome: Promise<unknown | null>,
  children: SpawnedChildSet,
  timeoutMs: number,
): Promise<unknown[]> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      closeOutcome.then(() => undefined),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, Math.max(1, Math.floor(timeoutMs)));
        timer.unref();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
  return await children.terminate();
}

async function boundedCloseOutcome(
  closeOutcome: Promise<unknown | null>,
  timeoutMs: number,
): Promise<unknown | null> {
  const boundedTimeoutMs = Math.max(1, timeoutMs);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const outcome = await Promise.race([
    closeOutcome.then((error) => ({ error })),
    new Promise<{ error: unknown }>((resolve) => {
      timer = setTimeout(
        () => resolve({ error: new AcpxRuntimeCloseTimeoutError() }),
        boundedTimeoutMs,
      );
      timer.unref();
    }),
  ]);
  if (timer) clearTimeout(timer);
  return outcome.error;
}

class SpawnedChildSet {
  readonly #children = new Set<ChildProcess>();
  readonly #errors = new Set<unknown>();

  add(child: ChildProcess): ChildProcess {
    this.#children.add(child);
    const onError = (error: unknown) => this.#errors.add(error);
    const forget = () => this.#children.delete(child);
    const forgetAndDetach = () => {
      forget();
      child.off("error", onError);
    };
    // ChildProcess reports some spawn and signal-delivery failures through an
    // asynchronous `error` event. Observe those for the child's whole tracked
    // lifetime so cleanup can report them instead of crashing runnerd.
    child.on("error", onError);
    child.once("exit", forget);
    child.once("close", forgetAndDetach);
    return child;
  }

  async terminate(): Promise<unknown[]> {
    const errors: unknown[] = [];
    const children = [...this.#children];
    await Promise.all(
      children.map(async (child) => {
        if (running(child)) {
          const terminateOutcome = await signalAndWaitForExit(
            child,
            "SIGTERM",
            PROVIDER_TERM_EXIT_TIMEOUT_MS,
          );
          if (terminateOutcome.error !== undefined) {
            pushUnique(errors, terminateOutcome.error);
          }
          if (!terminateOutcome.exited && running(child)) {
            const killOutcome = await signalAndWaitForExit(
              child,
              "SIGKILL",
              PROVIDER_KILL_EXIT_TIMEOUT_MS,
            );
            if (killOutcome.error !== undefined) {
              pushUnique(errors, killOutcome.error);
            }
            if (!killOutcome.exited && running(child)) {
              errors.push(
                new Error("ACPX provider did not exit after SIGKILL"),
              );
            }
          }
        }
      }),
    );
    // A failed spawn or signal can emit `error` and then `close` before this
    // method snapshots the live children. Keep those errors independently of
    // child membership, report each object once, and drain them only after all
    // in-flight termination attempts have had a chance to emit.
    for (const error of this.#errors) pushUnique(errors, error);
    this.#errors.clear();
    return errors;
  }
}

function running(child: ChildProcess): boolean {
  return child.exitCode === null && child.signalCode === null;
}

async function signalAndWaitForExit(
  child: ChildProcess,
  signal: NodeJS.Signals,
  timeoutMs: number,
): Promise<{ exited: boolean; error?: unknown }> {
  if (!running(child)) return { exited: true };
  return await new Promise<{ exited: boolean; error?: unknown }>((resolve) => {
    let settled = false;
    const finish = (outcome: { exited: boolean; error?: unknown }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.off("exit", onExit);
      child.off("close", onExit);
      child.off("error", onError);
      resolve(outcome);
    };
    const onExit = () => finish({ exited: true });
    const onError = (error: unknown) => finish({ exited: false, error });
    const timer = setTimeout(() => finish({ exited: false }), timeoutMs);
    timer.unref();
    child.once("exit", onExit);
    child.once("close", onExit);
    child.once("error", onError);
    if (!running(child)) {
      finish({ exited: true });
      return;
    }
    try {
      child.kill(signal);
      if (!running(child)) finish({ exited: true });
    } catch (error) {
      finish({ exited: false, error });
    }
  });
}

function pushUnique(errors: unknown[], error: unknown): void {
  if (!errors.includes(error)) errors.push(error);
}

function requireIdentity(handle: AcpRuntimeHandle): AcpxRuntimePortIdentity {
  const identity = {
    acpxRecordId: handle.acpxRecordId,
    backendSessionId: handle.backendSessionId,
    agentSessionId: handle.agentSessionId,
  };
  for (const [name, value] of Object.entries(identity)) {
    if (typeof value !== "string" || value.length === 0) {
      throw new Error(`ACPX runtime omitted ${name}`);
    }
  }
  return identity as AcpxRuntimePortIdentity;
}

function definedEnvironment(
  environment: Readonly<NodeJS.ProcessEnv>,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(environment).filter(
      (entry): entry is [string, string] => entry[1] !== undefined,
    ),
  );
}

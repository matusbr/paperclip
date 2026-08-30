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
import {
  assertVerifiedAcpxProviderPlatform,
  awaitVerifiedAcpxProviderOwnership,
} from "./installation-integrity.js";
import { decideAcpxPermission } from "./permission-policy.js";

const VERIFIED_COMMAND_SENTINEL = "paperclip-verified-acpx-command";
const DEFAULT_RUNTIME_CLOSE_TIMEOUT_MS = 2_000;
const PROVIDER_TERM_EXIT_TIMEOUT_MS = 2_000;
const PROVIDER_KILL_EXIT_TIMEOUT_MS = 2_000;
const PROVIDER_SHUTDOWN_SCHEDULING_MARGIN_MS = 1_000;
const MAX_LATE_RUNTIME_CLEANUP_RECONCILIATION_ATTEMPTS = 3;
const RUNTIME_ADMISSION_CLEANUP_RETRY_MIN_MS = 10;
const RUNTIME_ADMISSION_CLEANUP_RETRY_MAX_MS = 1_000;
// Production shutdown waits for the protocol close bound before beginning the
// sequential TERM/KILL verification windows plus a finite scheduling margin.
// Keep this exported package-local bound aligned with the complete
// implementation.
export const DEFAULT_CODEX_ACPX_RUNTIME_SHUTDOWN_BOUND_MS =
  DEFAULT_RUNTIME_CLOSE_TIMEOUT_MS +
  PROVIDER_TERM_EXIT_TIMEOUT_MS +
  PROVIDER_KILL_EXIT_TIMEOUT_MS +
  PROVIDER_SHUTDOWN_SCHEDULING_MARGIN_MS;
// A close may outlive its caller-facing wait bound. Keep every exact attempt
// owned until it settles even after the port releases it for a bounded retry.
// This prevents abandoned protocol work from being garbage-collected without
// letting one permanently pending attempt block all future recovery.
const activeRuntimeCleanupOwners = new Set<Promise<unknown>>();
const SESSION_HANDSHAKE_TIMEOUT_MS = 8_000;

class AcpxRuntimeCloseTimeoutError extends Error {
  constructor() {
    super("ACPX runtime close exceeded its shutdown timeout");
    this.name = "AcpxRuntimeCloseTimeoutError";
  }
}
const activeCodexRuntimeCleanupOwners = new Set<Promise<unknown>>();

class AcpxSessionHandshakeTimeoutError extends Error {
  constructor() {
    super("ACPX session handshake exceeded its admission deadline");
    this.name = "AcpxSessionHandshakeTimeoutError";
  }
}

export interface CodexAcpxRuntimeDependencies {
  createRuntime?: (options: AcpRuntimeOptions) => AcpRuntime;
  createRegistry?: (input: {
    overrides: Record<string, string | string[]>;
  }) => AcpAgentRegistry;
  createStore?: (input: { stateDir: string }) => AcpSessionStore;
  runtimeCloseTimeoutMs?: number;
  /** Internal test seam for the provider-session admission deadline. */
  sessionHandshakeTimeoutMs?: number;
  /** Retains autonomous cleanup ownership across the sidecar lifecycle. */
  retainCleanup?: (cleanup: Promise<void>) => void;
  /** Internal test seam for the fail-closed platform admission boundary. */
  platform?: NodeJS.Platform;
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
  // Verified ACPX command admission already fails closed on Windows because
  // Node cannot atomically open the provider executable with O_NOFOLLOW there.
  // Reject at the adapter boundary too: allowing a fabricated command lease to
  // start a provider would create a cleanup state that cannot guarantee both a
  // bounded sidecar exit and retained ownership of an unresponsive process
  // tree when Node cannot safely signal a verified provider process group.
  assertVerifiedAcpxProviderPlatform(
    dependencies.platform ?? process.platform,
  );
  if (options.profile.agent !== "codex") {
    throw new Error(
      "The production ACPX runtime currently supports Codex only",
    );
  }
  options.signal?.throwIfAborted();
  if (
    !Number.isSafeInteger(options.credentialFenceFd) ||
    (options.credentialFenceFd ?? -1) < 0 ||
    typeof options.activateCredentialFenceOwner !== "function"
  ) {
    throw new Error(
      "The production ACPX runtime requires an inherited credential-home fence",
    );
  }

  const createRegistry = dependencies.createRegistry ?? createAgentRegistry;
  const createStore = dependencies.createStore ?? createRuntimeStore;
  const createRuntime = dependencies.createRuntime ?? createAcpRuntime;
  const runtimeCloseTimeoutMs =
    dependencies.runtimeCloseTimeoutMs ?? DEFAULT_RUNTIME_CLOSE_TIMEOUT_MS;
  const children = new SpawnedChildSet(dependencies.retainCleanup);
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
        options.command.spawn(input.args, input.options, {
          credentialFenceFd: options.credentialFenceFd!,
          activateCredentialFenceOwner: options.activateCredentialFenceOwner!,
        }) as ChildProcess,
      );
    },
  });
  admissionCleanup = new RuntimeAdmissionCleanup(
    runtime,
    children,
    runtimeCloseTimeoutMs,
    dependencies.retainCleanup,
  );

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
  let handle: AcpRuntimeHandle | null = null;
  try {
    const boundedHandshake = boundedSessionHandshake(
      handshake,
      dependencies.sessionHandshakeTimeoutMs ?? SESSION_HANDSHAKE_TIMEOUT_MS,
    );
    handle = options.signal
      ? await raceRuntimeHandshakeWithAbort(boundedHandshake, options.signal)
      : await boundedHandshake;
    // A provider can answer only after the verified sentinel is armed, but do
    // not admit the session until the owner has observed that exact handoff.
    await children.verifyLifetimeOwnership();
    // The handshake or lifetime-ownership observation can settle in the same
    // turn as cancellation. Never admit that newly acquired authority.
    options.signal?.throwIfAborted();
  } catch (error) {
    const aborted = options.signal?.aborted === true;
    if (aborted || error instanceof AcpxSessionHandshakeTimeoutError) {
      const lateCleanup = lateHandshakeCleanup(
        handshake,
        admissionCleanup,
        aborted
          ? "ACPX runtime admission aborted"
          : "ACPX session handshake completed after its admission deadline",
      );
      dependencies.retainCleanup?.(lateCleanup);
      retainCodexRuntimeCleanup(lateCleanup);
    }
    const cleanupErrors = await admissionCleanup.run(
      handle ?? failedHandshakeHandle,
      aborted
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
  readonly #handleAttempts = new Map<
    string,
    {
      handle: AcpRuntimeHandle;
      attempt: Promise<unknown | null> | null;
      watchedAttempt: Promise<unknown | null> | null;
    }
  >();
  #tail: Promise<void> = Promise.resolve();
  #retryTimer: ReturnType<typeof setTimeout> | null = null;
  #retryOwner: Promise<void> | null = null;
  #retainedRecoveryOwner: Promise<void> | null = null;
  #resolveRetainedRecovery: (() => void) | null = null;
  readonly #retryTargets = new Map<
    string,
    { handle: AcpRuntimeHandle | null; reason: string }
  >();
  #retryDelayMs = RUNTIME_ADMISSION_CLEANUP_RETRY_MIN_MS;

  constructor(
    private readonly runtime: AcpRuntime,
    private readonly children: SpawnedChildSet,
    private readonly runtimeCloseTimeoutMs: number,
    private readonly retainCleanup?: (cleanup: Promise<void>) => void,
  ) {}

  run(handle: AcpRuntimeHandle | null, reason: string): Promise<unknown[]> {
    const cleanup = this.#runAttempt(handle, reason);
    void cleanup.then(({ errors, retry }) => {
      if (retry) this.#scheduleRetry(handle, reason);
      else if (errors.length === 0) {
        this.#retryDelayMs = RUNTIME_ADMISSION_CLEANUP_RETRY_MIN_MS;
      }
    });
    return cleanup.then(({ errors }) => errors);
  }

  #runAttempt(
    handle: AcpRuntimeHandle | null,
    reason: string,
  ): Promise<{ errors: unknown[]; retry: boolean }> {
    const cleanup = this.#tail.then(async () => {
      const errors: unknown[] = [];
      let retry = false;
      if (handle !== null) {
        const runtimeOutcome = await this.#closeHandle(handle, reason);
        if (runtimeOutcome.error !== null) errors.push(runtimeOutcome.error);
        retry ||= runtimeOutcome.retry;
      }
      const processErrors = await this.children.terminate();
      errors.push(...processErrors);
      retry ||= processErrors.length > 0;
      return { errors, retry };
    });
    this.#tail = cleanup.then(
      () => undefined,
      () => undefined,
    );
    return cleanup;
  }

  async #closeHandle(
    handle: AcpRuntimeHandle,
    reason: string,
  ): Promise<{ error: unknown | null; retry: boolean }> {
    const key = runtimeHandleCleanupKey(handle);
    if (this.#closedHandles.has(key)) return { error: null, retry: false };
    let state = this.#handleAttempts.get(key);
    if (!state) {
      state = { handle, attempt: null, watchedAttempt: null };
      this.#handleAttempts.set(key, state);
    }
    if (state.attempt === null) {
      state.attempt = runtimeCloseOutcome(this.runtime, handle, reason);
    }
    const attempt = state.attempt;
    const outcome = await boundedCloseOutcome(
      attempt,
      this.runtimeCloseTimeoutMs,
    );
    if (outcome instanceof AcpxRuntimeCloseTimeoutError) {
      this.#watchPendingAttempt(key, state, attempt, reason);
      return { error: outcome, retry: false };
    }
    if (state.attempt === attempt) state.attempt = null;
    if (outcome === null) {
      this.#closedHandles.add(key);
      this.#handleAttempts.delete(key);
      return { error: null, retry: false };
    }
    return { error: outcome, retry: true };
  }

  #watchPendingAttempt(
    key: string,
    state: {
      handle: AcpRuntimeHandle;
      attempt: Promise<unknown | null> | null;
      watchedAttempt: Promise<unknown | null> | null;
    },
    attempt: Promise<unknown | null>,
    reason: string,
  ): void {
    if (state.watchedAttempt === attempt) return;
    state.watchedAttempt = attempt;
    const owner = attempt.then((error) => {
      if (state.attempt === attempt) state.attempt = null;
      if (state.watchedAttempt === attempt) state.watchedAttempt = null;
      if (error === null) {
        this.#closedHandles.add(key);
        this.#handleAttempts.delete(key);
        this.#retryDelayMs = RUNTIME_ADMISSION_CLEANUP_RETRY_MIN_MS;
        return;
      }
      this.#scheduleRetry(state.handle, reason);
    });
    this.#retain(owner);
  }

  #scheduleRetry(handle: AcpRuntimeHandle | null, reason: string): void {
    const targetKey =
      handle === null ? "children" : runtimeHandleCleanupKey(handle);
    this.#retryTargets.set(targetKey, { handle, reason });
    this.#ensureRetainedRecoveryOwner();
    if (this.#retryTimer !== null || this.#retryOwner !== null) return;
    const delayMs = this.#retryDelayMs;
    this.#retryDelayMs = Math.min(
      this.#retryDelayMs * 2,
      RUNTIME_ADMISSION_CLEANUP_RETRY_MAX_MS,
    );
    this.#retryTimer = setTimeout(() => {
      this.#retryTimer = null;
      const next = this.#retryTargets.entries().next().value as
        | [string, { handle: AcpRuntimeHandle | null; reason: string }]
        | undefined;
      if (next === undefined) return;
      const [activeTargetKey, target] = next;
      this.#retryTargets.delete(activeTargetKey);
      const attempt = this.#runAttempt(target.handle, target.reason);
      const owner = attempt.then(({ errors, retry }) => {
        if (retry) this.#retryTargets.set(activeTargetKey, target);
        else if (errors.length === 0) {
          this.#retryDelayMs = RUNTIME_ADMISSION_CLEANUP_RETRY_MIN_MS;
        }
      });
      this.#retryOwner = owner;
      void owner
        .finally(() => {
          if (this.#retryOwner === owner) this.#retryOwner = null;
          const queued = this.#retryTargets.values().next().value as
            { handle: AcpRuntimeHandle | null; reason: string } | undefined;
          if (queued !== undefined) {
            this.#scheduleRetry(queued.handle, queued.reason);
          } else {
            this.#completeRetainedRecoveryOwner();
          }
        })
        .catch(() => undefined);
    }, delayMs);
    this.#retryTimer.unref?.();
  }

  #ensureRetainedRecoveryOwner(): void {
    if (this.#retainedRecoveryOwner !== null) return;
    let resolveOwner!: () => void;
    const owner = new Promise<void>((resolve) => {
      resolveOwner = resolve;
    });
    this.#retainedRecoveryOwner = owner;
    this.#resolveRetainedRecovery = resolveOwner;
    this.#retain(owner);
  }

  #completeRetainedRecoveryOwner(): void {
    if (
      this.#retryTargets.size > 0 ||
      this.#retryTimer !== null ||
      this.#retryOwner !== null
    ) {
      return;
    }
    const resolveOwner = this.#resolveRetainedRecovery;
    this.#retainedRecoveryOwner = null;
    this.#resolveRetainedRecovery = null;
    resolveOwner?.();
  }

  #retain(cleanup: Promise<void>): void {
    this.retainCleanup?.(cleanup);
    retainCodexRuntimeCleanup(cleanup);
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

async function boundedSessionHandshake(
  handshake: Promise<AcpRuntimeHandle>,
  timeoutMs: number,
): Promise<AcpRuntimeHandle> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      handshake,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new AcpxSessionHandshakeTimeoutError()),
          timeoutMs,
        );
        timer.unref();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function lateHandshakeCleanup(
  handshake: Promise<AcpRuntimeHandle>,
  cleanup: RuntimeAdmissionCleanup,
  reason: string,
): Promise<void> {
  return handshake.then(
    async (lateHandle) => {
      const errors = await cleanup.run(lateHandle, reason);
      if (errors.length > 0) {
        throw new AggregateError(
          errors,
          "ACPX late-handshake runtime cleanup failed",
        );
      }
    },
    () => undefined,
  );
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
      if (lateReconciliationOwner === owner)
        lateReconciliationOwner = undefined;
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
        ...(input.onElicitation ? { onElicitation: input.onElicitation } : {}),
      });
    },
    close: closeRuntime,
  };
  return port;
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
  readonly #terminations = new Map<ChildProcess, Promise<unknown[]>>();
  readonly #lifetimeOwnership: Promise<void>[] = [];
  #sealed = false;

  constructor(
    private readonly retainCleanup?: (cleanup: Promise<void>) => void,
  ) {}

  add(child: ChildProcess): ChildProcess {
    this.#track(child);
    const ownership = awaitVerifiedAcpxProviderOwnership(child);
    void ownership.catch(() => undefined);
    this.#lifetimeOwnership.push(ownership);
    if (this.#sealed) {
      // Once the stable-empty cleanup point is sealed, ACPX no longer has
      // authority to create provider work. Retain an immediate-kill attempt
      // through exit verification before rejecting the spawn itself.
      const termination = this.#startTermination(child, true);
      const cleanup = termination.then((errors) => {
        if (errors.length > 0) {
          throw new AggregateError(
            errors,
            "ACPX post-seal provider cleanup failed",
          );
        }
      });
      this.retainCleanup?.(cleanup);
      void cleanup.catch(() => undefined);
      throw new Error("ACPX provider spawned after cleanup was sealed");
    }
    return child;
  }

  async verifyLifetimeOwnership(): Promise<void> {
    const ownership = this.#lifetimeOwnership.splice(0);
    await Promise.all(ownership);
  }

  #track(child: ChildProcess): void {
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
  }

  async terminate(): Promise<unknown[]> {
    // Revoke spawn authority synchronously before the first await. Children
    // already owned here receive the normal TERM/KILL sequence; every later
    // spawn is rejected and its independently retained post-seal cleanup
    // cannot extend this caller-facing shutdown without bound.
    this.#sealed = true;
    for (const child of this.#children) this.#startTermination(child);
    const ownedTerminations = [...this.#terminations.values()];
    const errors = (await Promise.all(ownedTerminations)).flat();
    // A failed spawn or signal can emit `error` and then `close` before this
    // method snapshots the live children. Keep those errors independently of
    // child membership and report each object once after all owned attempts.
    for (const error of this.#errors) pushUnique(errors, error);
    this.#errors.clear();
    return errors;
  }

  #startTermination(
    child: ChildProcess,
    immediateKill = false,
  ): Promise<unknown[]> {
    const existing = this.#terminations.get(child);
    if (existing) return existing;
    const termination = (
      immediateKill ? terminatePostSealChild(child) : terminateChild(child)
    ).catch((error: unknown) => [error]);
    this.#terminations.set(child, termination);
    termination.then(() => {
      if (this.#terminations.get(child) === termination) {
        this.#terminations.delete(child);
      }
    });
    return termination;
  }
}

async function terminatePostSealChild(child: ChildProcess): Promise<unknown[]> {
  const errors: unknown[] = [];
  if (!running(child)) return errors;
  // Verified production children override ChildProcess.kill so this one
  // synchronous SIGKILL reaches the whole group while the live guardian still
  // pins its identity. Never copy the numeric PGID into a later signal owner.
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
      new Error("ACPX post-seal provider did not exit after SIGKILL"),
    );
  }
  return errors;
}

async function terminateChild(child: ChildProcess): Promise<unknown[]> {
  const errors: unknown[] = [];
  if (!running(child)) return errors;
  const terminateOutcome = await signalAndWaitForExit(
    child,
    "SIGTERM",
    PROVIDER_TERM_EXIT_TIMEOUT_MS,
  );
  if (terminateOutcome.error !== undefined) {
    pushUnique(errors, terminateOutcome.error);
  }
  if (!terminateOutcome.exited && running(child)) {
    errors.push(new Error("ACPX provider did not exit after SIGTERM"));
    // The verified guardian is still live and pins the PGID. Its protected
    // `kill` override synchronously signals the whole group exactly once.
    const killOutcome = await signalAndWaitForExit(
      child,
      "SIGKILL",
      PROVIDER_KILL_EXIT_TIMEOUT_MS,
    );
    if (killOutcome.error !== undefined) {
      pushUnique(errors, killOutcome.error);
    }
    if (!killOutcome.exited && running(child)) {
      errors.push(new Error("ACPX provider did not exit after SIGKILL"));
    }
  }
  // Never unref a child whose exit was not observed. Its live ChildProcess
  // remains the local cleanup owner instead of transferring a reusable PGID.
  return errors;
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

import type { NativeAcpxPermissionMode } from "../../contracts/native-execution.js";
import {
  stageManagedCodexCredential,
  type ManagedCodexCredentialLease,
} from "./codex-credentials.js";
import {
  verifyQualifiedAcpxInstallation,
  type VerifiedAcpxCommandLease,
  type VerifiedAcpxInstallation,
} from "./installation-integrity.js";
import {
  requireVerifiedAcpxModel,
  type AcpxModelStatus,
} from "./model-verification.js";
import { acpxRuntimePermissionPolicy } from "./permission-policy.js";
import {
  resolveQualifiedAcpxProfile,
  type QualifiedAcpxAgent,
  type QualifiedAcpxProfile,
} from "./qualified-profiles.js";
import {
  createAcpxIdentityRecord,
  createAcpxRecoveryBinding,
  verifyExpectedAcpxIdentity,
  type AcpxIdentityRecord,
  type AcpxRecoveryBinding,
} from "./recovery-identity.js";
import {
  prepareAcpxRuntimeSandbox,
  type AcpxRuntimeSandbox,
} from "./runtime-sandbox.js";
import type { AcpxExpectedSessionIdentity } from "./sidecar-protocol.js";

export interface AcpxRuntimePortIdentity {
  acpxRecordId: string;
  backendSessionId: string;
  agentSessionId: string;
}

/** Minimal third-party ACP runtime surface admitted by the host boundary. */
export interface AcpxRuntimePort {
  identity(): Promise<AcpxRuntimePortIdentity>;
  getStatus(): Promise<AcpxModelStatus>;
  setModel?(model: string): Promise<void>;
  close(input: { reason: string }): Promise<void>;
}

export interface AcpxRuntimePortOpenOptions {
  command: VerifiedAcpxCommandLease;
  profile: QualifiedAcpxProfile;
  cwd: string;
  stateDirectory: string;
  providerSessionKey: string;
  permissionMode: NativeAcpxPermissionMode;
  permissionPolicy: ReturnType<typeof acpxRuntimePermissionPolicy>;
  launchEnvironment: Readonly<NodeJS.ProcessEnv>;
  systemInstructions: string;
  /** Abort provider admission and clean any runtime that resolves too late. */
  signal?: AbortSignal;
}

export interface AcpxRuntimeHostDependencies {
  verifyInstallation?: (
    profile: QualifiedAcpxProfile,
  ) => Promise<VerifiedAcpxInstallation>;
  /** Internal test seam for aborting credential acquisition. */
  stageCredential?: typeof stageManagedCodexCredential;
  openRuntime(options: AcpxRuntimePortOpenOptions): Promise<AcpxRuntimePort>;
}

export interface OpenAcpxRuntimeHostOptions {
  runtimeDirectory: string;
  normalizedSessionId: string;
  workingDirectory: string;
  agent: QualifiedAcpxAgent;
  model: string;
  permissionMode: NativeAcpxPermissionMode;
  systemInstructions?: string;
  environment?: NodeJS.ProcessEnv;
  managedCodexCredentialSourcePath?: string;
  expectedIdentity?: AcpxExpectedSessionIdentity;
  /** Abort admission without admitting resources that resolve afterward. */
  signal?: AbortSignal;
}

const activeRuntimeHostCleanupOwners = new Set<Promise<unknown>>();

export class AcpxRuntimeHost {
  readonly #runtime: AcpxRuntimePort;
  readonly #binding: AcpxRecoveryBinding;
  readonly #identity: AcpxIdentityRecord;
  readonly #sandbox: AcpxRuntimeSandbox;
  readonly #credential: ManagedCodexCredentialLease | null;
  readonly #command: VerifiedAcpxCommandLease;
  #closed = false;

  private constructor(input: {
    runtime: AcpxRuntimePort;
    binding: AcpxRecoveryBinding;
    identity: AcpxIdentityRecord;
    sandbox: AcpxRuntimeSandbox;
    credential: ManagedCodexCredentialLease | null;
    command: VerifiedAcpxCommandLease;
  }) {
    this.#runtime = input.runtime;
    this.#binding = input.binding;
    this.#identity = input.identity;
    this.#sandbox = input.sandbox;
    this.#credential = input.credential;
    this.#command = input.command;
  }

  static async open(
    options: OpenAcpxRuntimeHostOptions,
    dependencies: AcpxRuntimeHostDependencies,
  ): Promise<AcpxRuntimeHost> {
    options.signal?.throwIfAborted();
    const profile = resolveQualifiedAcpxProfile(options.agent, options.model);
    const binding = await runAbortableAdmissionStage(
      options.signal,
      () => createAcpxRecoveryBinding({
        runtimeDirectory: options.runtimeDirectory,
        normalizedSessionId: options.normalizedSessionId,
        workingDirectory: options.workingDirectory,
        profile,
        requestedModel: options.model,
        permissionMode: options.permissionMode,
      }),
    );
    if (options.expectedIdentity) {
      verifyExpectedAcpxIdentity(options.expectedIdentity, binding, null);
    }
    if (
      options.agent !== "codex" &&
      options.managedCodexCredentialSourcePath !== undefined
    ) {
      throw new Error(
        "Managed Codex credentials require the Codex ACPX profile",
      );
    }

    const installation = await runAbortableAdmissionStage(
      options.signal,
      () => (
        dependencies.verifyInstallation ?? verifyQualifiedAcpxInstallation
      )(profile),
    );
    if (installation.commandDigest !== profile.commandDigest) {
      throw new Error("Verified ACPX installation does not match its profile");
    }
    let command: VerifiedAcpxCommandLease | null = null;
    let credential: ManagedCodexCredentialLease | null = null;
    let runtime: AcpxRuntimePort | null = null;
    try {
      const sandbox = await runAbortableAdmissionStage(
        options.signal,
        () => prepareAcpxRuntimeSandbox({
          binding,
          agent: options.agent,
          environment: options.environment,
        }),
      );
      if (options.agent === "codex") {
        credential = await acquireAbortableAdmissionResource({
          signal: options.signal,
          acquire: () => (
            dependencies.stageCredential ?? stageManagedCodexCredential
          )({
            agentHomeDirectory: sandbox.agentHomeDirectory,
            environment: options.environment,
            sourcePath: options.managedCodexCredentialSourcePath,
          }),
          releaseLate: (lateCredential) => lateCredential.close(),
        });
      }
      command = await acquireAbortableAdmissionResource({
        signal: options.signal,
        acquire: () => installation.openCommand(),
        releaseLate: (lateCommand) => lateCommand.close(),
      });
      runtime = await acquireAbortableAdmissionResource({
        signal: options.signal,
        acquire: () => dependencies.openRuntime({
          command: command!,
          profile,
          cwd: binding.workspacePath,
          stateDirectory: sandbox.stateDirectory,
          providerSessionKey: binding.profileSessionKey,
          permissionMode: binding.permissionMode,
          permissionPolicy: acpxRuntimePermissionPolicy(binding.permissionMode),
          launchEnvironment: sandbox.launchEnvironment,
          systemInstructions: boundedInstructions(options.systemInstructions),
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        }),
        releaseLate: (lateRuntime) => lateRuntime.close({
          reason: "ACPX runtime admission aborted",
        }),
      });
      await runAbortableAdmissionStage(
        options.signal,
        () => requireVerifiedAcpxModel(runtime!, profile),
      );
      const runtimeIdentity = await runAbortableAdmissionStage(
        options.signal,
        () => runtime!.identity(),
      );
      const observedIdentity: AcpxExpectedSessionIdentity = {
        kind: "acpx",
        normalizedSessionId: binding.normalizedSessionId,
        ...runtimeIdentity,
        profileDigest: binding.profileDigest,
        workspaceDigest: binding.workspaceDigest,
        requestedModel: binding.requestedModel,
        effectiveModel: binding.effectiveModel,
        permissionMode: binding.permissionMode,
      };
      const identity = createAcpxIdentityRecord(observedIdentity, binding);
      if (options.expectedIdentity) {
        verifyExpectedAcpxIdentity(options.expectedIdentity, binding, identity);
      }
      options.signal?.throwIfAborted();
      return new AcpxRuntimeHost({
        runtime,
        binding,
        identity,
        sandbox,
        credential,
        command,
      });
    } catch (error) {
      const cleanupError = await cleanupRuntimeResources(
        runtime,
        credential,
        command,
        "ACPX runtime initialization failed",
      );
      if (cleanupError) {
        throw new AggregateError(
          [error, ...cleanupError.errors],
          "ACPX runtime initialization and cleanup failed",
        );
      }
      throw error;
    }
  }

  identity(): AcpxIdentityRecord {
    return structuredClone(this.#identity);
  }

  binding(): AcpxRecoveryBinding {
    return structuredClone(this.#binding);
  }

  runtimeRoot(): string {
    return this.#sandbox.root;
  }

  persistedEnvironment(): Readonly<NodeJS.ProcessEnv> {
    return Object.freeze({ ...this.#sandbox.persistedEnvironment });
  }

  async close(input: { reason: string }): Promise<void> {
    if (this.#closed) return;
    const error = await cleanupRuntimeResources(
      this.#runtime,
      this.#credential,
      this.#command,
      boundedReason(input.reason),
    );
    if (error) throw error;
    this.#closed = true;
  }
}

async function runAbortableAdmissionStage<T>(
  signal: AbortSignal | undefined,
  operation: () => Promise<T>,
): Promise<T> {
  if (signal === undefined) return await operation();
  signal.throwIfAborted();
  const pending = Promise.resolve().then(operation);
  return await raceAdmissionWithAbort(pending, signal);
}

async function acquireAbortableAdmissionResource<T>(input: {
  signal: AbortSignal | undefined;
  acquire: () => Promise<T>;
  releaseLate: (resource: T) => Promise<void>;
}): Promise<T> {
  if (input.signal === undefined) return await input.acquire();
  input.signal.throwIfAborted();
  const pending = Promise.resolve().then(input.acquire);
  try {
    return await raceAdmissionWithAbort(pending, input.signal);
  } catch (error) {
    if (input.signal.aborted) {
      retainRuntimeHostCleanup(
        pending.then((resource) => input.releaseLate(resource)),
      );
    }
    throw error;
  }
}

function raceAdmissionWithAbort<T>(
  pending: Promise<T>,
  signal: AbortSignal,
): Promise<T> {
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
    void pending.then(
      (value) => settle(() => resolve(value)),
      (error: unknown) => settle(() => reject(error)),
    );
  });
}

function retainRuntimeHostCleanup(cleanup: Promise<unknown>): void {
  activeRuntimeHostCleanupOwners.add(cleanup);
  void cleanup
    .finally(() => activeRuntimeHostCleanupOwners.delete(cleanup))
    .catch(() => undefined);
}

async function cleanupRuntimeResources(
  runtime: AcpxRuntimePort | null,
  credential: ManagedCodexCredentialLease | null,
  command: VerifiedAcpxCommandLease | null,
  reason: string,
): Promise<AggregateError | null> {
  const errors: unknown[] = [];
  for (const close of [
    runtime ? () => runtime.close({ reason }) : null,
    credential ? () => credential.close() : null,
    command ? () => command.close() : null,
  ]) {
    if (!close) continue;
    try {
      await close();
    } catch (error) {
      errors.push(error);
    }
  }
  return errors.length > 0
    ? new AggregateError(errors, "ACPX runtime cleanup failed")
    : null;
}

function boundedInstructions(value: string | undefined): string {
  const instructions = value ?? "";
  if (Buffer.byteLength(instructions) > 256 * 1024) {
    throw new Error("ACPX system instructions exceed their bounded size");
  }
  return instructions;
}

function boundedReason(value: string): string {
  const reason = value.trim().slice(0, 1_000);
  return reason || "ACPX runtime closed";
}

import { createHash, randomBytes } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  open,
  readdir,
  realpath,
  rename,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import {
  createConnection,
  createServer,
  type Server,
  type Socket,
} from "node:net";
import { isAbsolute, join, resolve } from "node:path";

const MAX_CODEX_CREDENTIAL_BYTES = 256 * 1024;
const PRIVATE_FILE_MODE = 0o600;
const MAX_DIRECTORY_SYNC_ATTEMPTS = 8;
const DIRECTORY_SYNC_OPERATION_TIMEOUT_MS = 1_000;
const MAX_AUTONOMOUS_CREDENTIAL_CLEANUP_ATTEMPTS = 8;
const CREDENTIAL_CLEANUP_INTENT = ".paperclip-auth-cleanup-required";
const CREDENTIAL_LEASE_HOST = "127.0.0.1";
const CREDENTIAL_LEASE_PORT_MIN = 49_152;
const CREDENTIAL_LEASE_PORT_COUNT = 16_384;
const MAX_CREDENTIAL_LEASE_PORT_CANDIDATES = 32;
const CREDENTIAL_LEASE_PROBE_TIMEOUT_MS = 1_000;
const CREDENTIAL_LEASE_PROTOCOL = "paperclip-managed-codex-lease-v1";
const CREDENTIAL_LEASE_FOREIGN_PROBE =
  "GET /__paperclip_credential_lease_probe__ HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
const CREDENTIAL_LEASE_MARKER_PREFIX = ".paperclip-auth-lease-v1-";
const MAX_CREDENTIAL_LEASE_MARKERS = 1_024;

interface CredentialHomeLock {
  assertHeld(): void;
  release(): Promise<void>;
}

interface CredentialLeaseMarker {
  version: 1;
  identity: string;
  pid: number;
  port: number;
  token: string;
}

interface QuarantinedCredentialCleanup {
  path: string;
  home: string;
  intentPath: string;
  lock: CredentialHomeLock;
  recovery: Promise<void> | null;
}

type CredentialLeaseGeneration = number;
type CredentialLeaseProbe =
  | "matching_owner"
  | "different_owner"
  | "unresponsive"
  | "unoccupied";

const quarantinedCredentialCleanups = new Map<
  string,
  QuarantinedCredentialCleanup
>();
const pendingDirectorySyncCleanups = new Map<string, Promise<void>>();
const activeCredentialLeaseGenerations = new Map<
  string,
  CredentialLeaseGeneration
>();
const processCredentialLeaseState = globalThis as typeof globalThis & {
  __paperclipCredentialLeaseIdentitiesV1?: Map<number, string>;
};
const processCredentialLeaseIdentities =
  processCredentialLeaseState.__paperclipCredentialLeaseIdentitiesV1 ??
  new Map<number, string>();
processCredentialLeaseState.__paperclipCredentialLeaseIdentitiesV1 =
  processCredentialLeaseIdentities;
let nextCredentialLeaseGeneration = 0;

export type ManagedCodexCredentialMode =
  "api_key" | "inline_json" | "managed_file";

export interface ManagedCodexCredentialLease {
  readonly path: string;
  readonly mode: ManagedCodexCredentialMode;
  close(): Promise<void>;
}

/** Stage one explicit Codex authentication source in its isolated runtime home. */
export async function stageManagedCodexCredential(input: {
  agentHomeDirectory: string;
  environment?: NodeJS.ProcessEnv;
  sourcePath?: string;
}): Promise<ManagedCodexCredentialLease> {
  const home = await realpath(input.agentHomeDirectory);
  const homeMetadata = await lstat(home);
  if (!homeMetadata.isDirectory() || homeMetadata.isSymbolicLink()) {
    throw new Error("Managed Codex credential home must be a real directory");
  }
  if (
    process.platform !== "win32" &&
    ((homeMetadata.mode & 0o077) !== 0 ||
      (typeof process.getuid === "function" &&
        homeMetadata.uid !== process.getuid()))
  ) {
    throw new Error("Managed Codex credential home permissions are unsafe");
  }
  const ownerGeneration = claimCredentialLeaseGeneration(home);
  let lock: CredentialHomeLock | null = null;
  try {
    await recoverQuarantinedCredentialCleanup(join(home, "auth.json"), home);
    lock = await acquireCredentialHomeLock(home);
    return await stageClaimedManagedCodexCredential(
      input,
      home,
      ownerGeneration,
      lock,
    );
  } catch (error) {
    if (lock !== null && quarantinedCredentialCleanups.get(home)?.lock !== lock) {
      await lock.release().catch(() => undefined);
    }
    releaseCredentialLeaseGeneration(home, ownerGeneration);
    throw error;
  }
}

async function stageClaimedManagedCodexCredential(
  input: {
    environment?: NodeJS.ProcessEnv;
    sourcePath?: string;
  },
  home: string,
  ownerGeneration: CredentialLeaseGeneration,
  lock: CredentialHomeLock,
): Promise<ManagedCodexCredentialLease> {
  const destination = join(home, "auth.json");
  const intentPath = join(home, CREDENTIAL_CLEANUP_INTENT);
  lock.assertHeld();
  await recoverPersistedCredentialCleanup(destination, home, intentPath);
  // The isolated home is itself the durable recovery anchor. Scrub auth.json
  // before every admission, even when a prior cleanup-intent entry was lost
  // with a runner crash. Only after this absence is durable may a new intent
  // be created and a credential installed.
  await removeCredential(destination, home);
  const environment = input.environment ?? {};
  const hasApiKey = Boolean(
    environment.CODEX_API_KEY || environment.OPENAI_API_KEY,
  );
  const inlineJson = environment.PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET;
  const hasInlineJson = typeof inlineJson === "string" && inlineJson.length > 0;
  const hasManagedFile =
    typeof input.sourcePath === "string" && input.sourcePath.length > 0;
  const sourceCount = [hasApiKey, hasInlineJson, hasManagedFile].filter(
    Boolean,
  ).length;
  if (sourceCount === 0) {
    throw new Error(
      "provider_initialize_protocol_error: provider=acpx stage=credential.stage managed Codex credential missing",
    );
  }
  if (sourceCount !== 1) {
    throw new Error("Managed Codex credential source is ambiguous");
  }

  if (
    hasManagedFile &&
    (!isAbsolute(input.sourcePath!) ||
      resolve(input.sourcePath!) === destination)
  ) {
    throw new Error(
      "Managed Codex credential source must be an external absolute path",
    );
  }

  if (hasApiKey) {
    // Codex will read the API key from the launch environment. Persist cleanup
    // intent before admitting the provider and retain it for the lease
    // lifetime, so a replacement runner removes provider-generated auth after
    // a crash before it admits another provider.
    // Failure while publishing the intent cannot strand a staged credential:
    // the unconditional admission scrub above is already durable and this
    // mode has not allowed the provider to create auth.json yet.
    await createCredentialCleanupIntent(intentPath, home);
    return credentialLease(
      destination,
      home,
      intentPath,
      "api_key",
      ownerGeneration,
      lock,
    );
  }

  const credential = hasInlineJson
    ? boundedInlineCredential(inlineJson!)
    : await readManagedCredential(input.sourcePath!);
  try {
    validateCredentialDocument(credential);
    // As with API-key mode, an intent-publication failure occurs before any
    // credential mutation and therefore needs no process-only quarantine.
    await createCredentialCleanupIntent(intentPath, home);
    try {
      await writeCredential(destination, home, credential);
    } catch (error) {
      // Rename may already have installed the credential before directory
      // durability failed. Retain a bounded process owner and the persisted
      // intent so later staging must recover both before admission.
      quarantineCredentialCleanup(destination, home, intentPath, lock);
      throw error;
    }
  } finally {
    credential.fill(0);
  }
  return credentialLease(
    destination,
    home,
    intentPath,
    hasInlineJson ? "inline_json" : "managed_file",
    ownerGeneration,
    lock,
  );
}

function claimCredentialLeaseGeneration(
  home: string,
): CredentialLeaseGeneration {
  if (activeCredentialLeaseGenerations.has(home)) {
    throw new Error(
      "Managed Codex credential home already has an active lease",
    );
  }
  if (nextCredentialLeaseGeneration >= Number.MAX_SAFE_INTEGER) {
    throw new Error("Managed Codex credential lease generation exhausted");
  }
  nextCredentialLeaseGeneration += 1;
  activeCredentialLeaseGenerations.set(home, nextCredentialLeaseGeneration);
  return nextCredentialLeaseGeneration;
}

function releaseCredentialLeaseGeneration(
  home: string,
  ownerGeneration: CredentialLeaseGeneration,
): void {
  if (activeCredentialLeaseGenerations.get(home) === ownerGeneration) {
    activeCredentialLeaseGenerations.delete(home);
  }
}

async function acquireCredentialHomeLock(
  home: string,
): Promise<CredentialHomeLock> {
  // ACPX credential homes are local-runtime resources: every contender for a
  // canonical home runs on the same host and network namespace. A bounded set
  // of deterministic loopback endpoints therefore provides a kernel-owned,
  // process-lifetime lease without making one hash collision authoritative.
  // The local runner also supervises its provider lifetime; a provider cannot
  // remain an authorized writer after this owning process dies. Every
  // Paperclip listener identifies its canonical home, so confirmed unrelated
  // collisions fall through to another candidate while a matching live owner
  // still fences the home. An occupied endpoint that does not answer within
  // the bounded probe is authoritative: it may be a concurrent owner between
  // bind and marker publication, so admission fails closed instead of letting
  // two contenders select different ports. After binding, probing every other
  // candidate closes the race where an earlier unrelated listener disappears
  // while an owner uses a later one.
  const identity = credentialLeaseIdentity(home);
  const ports = credentialLeasePorts(home);
  if (await hasActiveCredentialLeaseMarker(home, identity, ports)) {
    throw new Error(
      "Managed Codex credential home already has an active lease",
    );
  }
  let server: Server | null = null;
  let port: number | null = null;
  let acceptedSockets = new Set<Socket>();
  for (const candidatePort of ports) {
    const candidateSockets = new Set<Socket>();
    const candidate = createCredentialLeaseServer(identity, candidateSockets);
    try {
      await listenForCredentialLease(candidate, candidatePort);
      processCredentialLeaseIdentities.set(candidatePort, identity);
      server = candidate;
      port = candidatePort;
      acceptedSockets = candidateSockets;
      break;
    } catch (error) {
      for (const socket of candidateSockets) socket.destroy();
      if (errorCode(error) !== "EADDRINUSE") {
        throw new Error(
          "Managed Codex credential ownership could not be established",
          { cause: error },
        );
      }
      const probe = await probeCredentialLease(candidatePort, identity);
      if (probe === "matching_owner") {
        throw new Error(
          "Managed Codex credential home already has an active lease",
        );
      }
      if (probe === "unresponsive") {
        throw new Error(
          "Managed Codex credential ownership could not safely bypass an unresponsive lease endpoint",
        );
      }
    }
  }
  if (server === null || port === null) {
    throw new Error(
      "Managed Codex credential ownership could not find a free loopback lease endpoint",
    );
  }

  let invalid: Error | null = null;
  let expectedClose = false;
  server.on("error", (error) => {
    invalid ??= error;
  });
  server.on("close", () => {
    if (processCredentialLeaseIdentities.get(port) === identity) {
      processCredentialLeaseIdentities.delete(port);
    }
    if (!expectedClose) {
      invalid ??= new Error(
        "Managed Codex credential ownership listener closed unexpectedly",
      );
    }
  });
  try {
    const address = server.address();
    if (
      address === null ||
      typeof address === "string" ||
      address.address !== CREDENTIAL_LEASE_HOST ||
      address.family !== "IPv4" ||
      address.port !== port
    ) {
      throw new Error(
        "Managed Codex credential ownership listener bound unexpectedly",
      );
    }
    const competingEndpoints = await Promise.all(
      ports
        .filter((candidatePort) => candidatePort !== port)
        .map((candidatePort) => probeCredentialLease(candidatePort, identity)),
    );
    if (
      competingEndpoints.some(
        (probe) =>
          probe === "matching_owner" || probe === "unresponsive",
      )
    ) {
      throw new Error(
        "Managed Codex credential home already has an active lease",
      );
    }
    if (await hasActiveCredentialLeaseMarker(home, identity, ports)) {
      throw new Error(
        "Managed Codex credential home already has an active lease",
      );
    }
    if (invalid !== null || !server.listening) {
      throw new Error("Managed Codex credential ownership was lost", {
        cause: invalid,
      });
    }
  } catch (error) {
    expectedClose = true;
    for (const socket of acceptedSockets) socket.destroy();
    if (server.listening) await closeCredentialLeaseServer(server);
    throw error;
  }

  const markerPath = await publishCredentialLeaseMarker(home, {
    version: 1,
    identity,
    pid: process.pid,
    port,
    token: randomBytes(16).toString("hex"),
  }).catch(async (error: unknown) => {
    expectedClose = true;
    for (const socket of acceptedSockets) socket.destroy();
    if (server.listening) await closeCredentialLeaseServer(server);
    throw new Error(
      "Managed Codex credential ownership marker could not be established",
      { cause: error },
    );
  });

  let released = false;
  let releaseAttempt: Promise<void> | null = null;
  return Object.freeze({
    assertHeld(): void {
      if (released || invalid !== null || !server.listening) {
        throw new Error("Managed Codex credential ownership was lost", {
          cause: invalid,
        });
      }
    },
    async release(): Promise<void> {
      if (released) return;
      if (releaseAttempt !== null) return await releaseAttempt;
      const attempt = (async () => {
        const ownershipError = invalid;
        // Keep the kernel fence live until its marker is gone. If unlinking
        // the marker fails, quarantine recovery can still assert ownership
        // and retry instead of inheriting a closed, permanently unusable
        // lock.
        await unlink(markerPath).catch((error: unknown) => {
          if (errorCode(error) !== "ENOENT") throw error;
        });
        expectedClose = true;
        for (const socket of acceptedSockets) socket.destroy();
        if (server.listening) await closeCredentialLeaseServer(server);
        released = true;
        if (ownershipError !== null) throw ownershipError;
      })();
      releaseAttempt = attempt;
      try {
        await attempt;
      } finally {
        if (releaseAttempt === attempt) releaseAttempt = null;
      }
    },
  });
}

function credentialLeaseIdentity(home: string): string {
  const scope = `${
    typeof process.getuid === "function" ? process.getuid() : "win32"
  }\0${home}`;
  return createHash("sha256").update(scope).digest("hex");
}

function credentialLeasePorts(home: string): number[] {
  const digest = Buffer.from(credentialLeaseIdentity(home), "hex");
  const start = digest.readUInt16BE(0) % CREDENTIAL_LEASE_PORT_COUNT;
  const stride = digest.readUInt16BE(2) | 1;
  return Array.from(
    { length: MAX_CREDENTIAL_LEASE_PORT_CANDIDATES },
    (_, index) =>
      CREDENTIAL_LEASE_PORT_MIN +
      ((start + index * stride) % CREDENTIAL_LEASE_PORT_COUNT),
  );
}

function createCredentialLeaseServer(
  identity: string,
  acceptedSockets: Set<Socket>,
): Server {
  const response = `${CREDENTIAL_LEASE_PROTOCOL} ${identity}\n`;
  return createServer((socket) => {
    acceptedSockets.add(socket);
    socket.once("close", () => acceptedSockets.delete(socket));
    socket.end(response);
  });
}

async function probeCredentialLease(
  port: number,
  expectedIdentity: string,
): Promise<CredentialLeaseProbe> {
  const processIdentity = processCredentialLeaseIdentities.get(port);
  if (processIdentity !== undefined) {
    return processIdentity === expectedIdentity
      ? "matching_owner"
      : "different_owner";
  }
  const expected = `${CREDENTIAL_LEASE_PROTOCOL} ${expectedIdentity}\n`;
  return await new Promise<CredentialLeaseProbe>((resolveProbe) => {
    const socket = createConnection({ host: CREDENTIAL_LEASE_HOST, port });
    let settled = false;
    let response = "";
    let foreignProbe: NodeJS.Timeout | null = null;
    const finish = (result: CredentialLeaseProbe): void => {
      if (settled) return;
      settled = true;
      if (foreignProbe !== null) clearTimeout(foreignProbe);
      socket.destroy();
      resolveProbe(result);
    };
    socket.setEncoding("utf8");
    socket.setTimeout(CREDENTIAL_LEASE_PROBE_TIMEOUT_MS, () =>
      finish("unresponsive"),
    );
    socket.once("connect", () => {
      foreignProbe = setTimeout(() => {
        if (!settled) socket.write(CREDENTIAL_LEASE_FOREIGN_PROBE);
      }, 10);
      foreignProbe.unref();
    });
    socket.on("data", (chunk: string) => {
      response += chunk;
      if (response === expected) finish("matching_owner");
      else if (
        response.length >= expected.length ||
        !expected.startsWith(response)
      ) {
        finish("different_owner");
      }
    });
    socket.once("error", (error) =>
      finish(
        errorCode(error) === "ECONNREFUSED"
          ? "unoccupied"
          : "unresponsive",
      ),
    );
    socket.once("end", () =>
      finish(response === expected ? "matching_owner" : "different_owner"),
    );
    socket.once("close", () =>
      finish(response === expected ? "matching_owner" : "different_owner"),
    );
  });
}

async function hasActiveCredentialLeaseMarker(
  home: string,
  expectedIdentity: string,
  candidatePorts: readonly number[],
): Promise<boolean> {
  const entries = (await readdir(home, { withFileTypes: true })).filter(
    (entry) =>
      entry.isFile() &&
      entry.name.startsWith(CREDENTIAL_LEASE_MARKER_PREFIX) &&
      entry.name.endsWith(".json"),
  );
  if (entries.length > MAX_CREDENTIAL_LEASE_MARKERS) {
    throw new Error("Managed Codex credential lease marker limit exceeded");
  }
  for (const entry of entries) {
    const markerPath = join(home, entry.name);
    const marker = await readCredentialLeaseMarker(markerPath);
    if (
      marker === null ||
      marker.identity !== expectedIdentity ||
      !candidatePorts.includes(marker.port)
    ) {
      continue;
    }
    if (
      (await probeCredentialLease(marker.port, expectedIdentity)) ===
      "matching_owner"
    ) {
      return true;
    }
    if (
      credentialLeaseProcessIsAlive(marker.pid) &&
      (await credentialLeasePortIsOccupied(marker.port))
    ) {
      return true;
    }
    await unlink(markerPath).catch((error: unknown) => {
      if (errorCode(error) !== "ENOENT") throw error;
    });
  }
  return false;
}

async function readCredentialLeaseMarker(
  markerPath: string,
): Promise<CredentialLeaseMarker | null> {
  let handle: FileHandle;
  try {
    handle = await open(
      markerPath,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
  } catch (error) {
    if (errorCode(error) === "ENOENT" || errorCode(error) === "ELOOP") {
      return null;
    }
    throw error;
  }
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size < 1 || metadata.size > 4_096) {
      return null;
    }
    const bytes = await readHandle(handle, metadata.size);
    const value = JSON.parse(bytes.toString("utf8")) as Partial<CredentialLeaseMarker>;
    if (
      value.version !== 1 ||
      typeof value.identity !== "string" ||
      !/^[0-9a-f]{64}$/.test(value.identity) ||
      !Number.isInteger(value.pid) ||
      (value.pid ?? 0) < 1 ||
      !Number.isInteger(value.port) ||
      (value.port ?? 0) < 1 ||
      (value.port ?? 0) > 65_535 ||
      typeof value.token !== "string" ||
      !/^[0-9a-f]{32}$/.test(value.token)
    ) {
      return null;
    }
    return value as CredentialLeaseMarker;
  } catch {
    return null;
  } finally {
    await handle.close();
  }
}

async function publishCredentialLeaseMarker(
  home: string,
  marker: CredentialLeaseMarker,
): Promise<string> {
  const markerPath = join(
    home,
    `${CREDENTIAL_LEASE_MARKER_PREFIX}${marker.token}.json`,
  );
  const handle = await open(
    markerPath,
    constants.O_WRONLY |
      constants.O_CREAT |
      constants.O_EXCL |
      (constants.O_NOFOLLOW ?? 0),
    PRIVATE_FILE_MODE,
  );
  try {
    await handle.writeFile(`${JSON.stringify(marker)}\n`, "utf8");
    await handle.sync();
  } catch (error) {
    await handle.close().catch(() => undefined);
    await unlink(markerPath).catch(() => undefined);
    throw error;
  }
  await handle.close();
  return markerPath;
}

function credentialLeaseProcessIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return errorCode(error) !== "ESRCH";
  }
}

async function credentialLeasePortIsOccupied(port: number): Promise<boolean> {
  const probe = createServer();
  try {
    await listenForCredentialLease(probe, port);
    await closeCredentialLeaseServer(probe);
    return false;
  } catch (error) {
    if (errorCode(error) === "EADDRINUSE") return true;
    throw error;
  }
}

async function listenForCredentialLease(
  server: Server,
  port: number,
): Promise<void> {
  await new Promise<void>((resolveListen, rejectListen) => {
    const onError = (error: Error): void => rejectListen(error);
    server.once("error", onError);
    server.listen(
      {
        host: CREDENTIAL_LEASE_HOST,
        port,
        exclusive: true,
        reusePort: false,
      },
      () => {
        server.off("error", onError);
        resolveListen();
      },
    );
  });
}

async function closeCredentialLeaseServer(server: Server): Promise<void> {
  await new Promise<void>((resolveClose, rejectClose) => {
    server.close((error) => {
      if (error) rejectClose(error);
      else resolveClose();
    });
  });
}

function quarantineCredentialCleanup(
  path: string,
  home: string,
  intentPath: string,
  lock: CredentialHomeLock,
): void {
  const existing = quarantinedCredentialCleanups.get(home);
  if (existing !== undefined) return;
  const cleanup: QuarantinedCredentialCleanup = {
    path,
    home,
    intentPath,
    lock,
    recovery: null,
  };
  quarantinedCredentialCleanups.set(home, cleanup);
  startCredentialCleanupRecovery(
    cleanup,
    MAX_AUTONOMOUS_CREDENTIAL_CLEANUP_ATTEMPTS,
  );
}

function startCredentialCleanupRecovery(
  cleanup: QuarantinedCredentialCleanup,
  maxAttempts: number,
): Promise<void> {
  if (cleanup.recovery) return cleanup.recovery;
  const recovery = (async () => {
    let retryDelayMs = 10;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        // Never let a stale cleanup callback mutate a successor's credential
        // after kernel ownership has been lost.
        cleanup.lock.assertHeld();
        await removeReplaceableCredential(cleanup.path);
        await syncDirectory(cleanup.home);
        await removeCredentialCleanupIntent(
          cleanup.intentPath,
          cleanup.home,
        );
        await cleanup.lock.release();
        quarantinedCredentialCleanups.delete(cleanup.home);
        return;
      } catch {
        if (attempt === maxAttempts) return;
        await new Promise<void>((resolveRetry) => {
          const timer = setTimeout(resolveRetry, retryDelayMs);
          timer.unref?.();
        });
        retryDelayMs = Math.min(retryDelayMs * 2, 1_000);
      }
    }
  })();
  cleanup.recovery = recovery;
  void recovery.finally(() => {
    if (cleanup.recovery === recovery) cleanup.recovery = null;
  }).catch(() => undefined);
  return recovery;
}

async function recoverQuarantinedCredentialCleanup(
  path: string,
  home: string,
): Promise<void> {
  const cleanup = quarantinedCredentialCleanups.get(home);
  if (cleanup === undefined) return;
  await (cleanup.recovery ?? startCredentialCleanupRecovery(cleanup, 1));
  if (!quarantinedCredentialCleanups.has(home)) return;
  const admissionRecovery = startCredentialCleanupRecovery(cleanup, 1);
  await admissionRecovery;
  if (quarantinedCredentialCleanups.has(home)) {
    throw new Error(
      `Managed Codex credential cleanup remains non-durable for ${path}`,
    );
  }
}

async function recoverPersistedCredentialCleanup(
  path: string,
  home: string,
  intentPath: string,
): Promise<void> {
  if (!(await pathExists(intentPath))) return;
  await removeCredential(path, home);
  await removeCredentialCleanupIntent(intentPath, home);
}

function credentialLease(
  path: string,
  home: string,
  intentPath: string,
  mode: ManagedCodexCredentialMode,
  ownerGeneration: CredentialLeaseGeneration,
  lock: CredentialHomeLock,
): ManagedCodexCredentialLease {
  // Do not admit a provider if kernel ownership was lost while its credential
  // was being staged.
  lock.assertHeld();
  let closed = false;
  let closeAttempt: Promise<void> | null = null;
  return Object.freeze({
    path,
    mode,
    async close(): Promise<void> {
      if (closed) return;
      if (closeAttempt !== null) return await closeAttempt;
      const attempt = (async () => {
        const activeGeneration = activeCredentialLeaseGenerations.get(home);
        if (activeGeneration !== ownerGeneration) {
          // A failed close releases its generation only after publishing a
          // quarantine owner. If no successor exists, synchronously join that
          // cleanup before acknowledging the retry. If a successor does
          // exist, this stale lease has no authority over its credential.
          if (activeGeneration === undefined) {
            await recoverQuarantinedCredentialCleanup(path, home);
            await lock.release();
          }
          closed = true;
          return;
        }
        try {
          lock.assertHeld();
          await removeCredential(path, home);
          await removeCredentialCleanupIntent(intentPath, home);
          await lock.release();
          closed = true;
        } catch (error) {
          quarantineCredentialCleanup(path, home, intentPath, lock);
          throw error;
        } finally {
          releaseCredentialLeaseGeneration(home, ownerGeneration);
        }
      })();
      closeAttempt = attempt;
      try {
        await attempt;
      } finally {
        if (closeAttempt === attempt) closeAttempt = null;
      }
    },
  });
}

async function createCredentialCleanupIntent(
  intentPath: string,
  home: string,
): Promise<void> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(
      intentPath,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        (constants.O_NOFOLLOW ?? 0),
      PRIVATE_FILE_MODE,
    );
    await handle.chmod(PRIVATE_FILE_MODE);
    await handle.writeFile("paperclip-managed-codex-cleanup-v1\n", "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await syncDirectoryDurably(home);
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function removeCredentialCleanupIntent(
  intentPath: string,
  home: string,
): Promise<void> {
  await removeReplaceableCredential(intentPath);
  await syncDirectoryDurably(home);
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (errorCode(error) === "ENOENT") return false;
    throw error;
  }
}

function boundedInlineCredential(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length < 1 || bytes.length > MAX_CODEX_CREDENTIAL_BYTES) {
    bytes.fill(0);
    throw new Error(
      "Managed Codex credential document exceeds its bounded size",
    );
  }
  return bytes;
}

async function readManagedCredential(sourcePath: string): Promise<Buffer> {
  let handle: FileHandle;
  try {
    handle = await open(
      sourcePath,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
  } catch {
    throw new Error(
      "provider_initialize_protocol_error: provider=acpx stage=credential.stage managed Codex credential missing",
    );
  }
  try {
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile() ||
      before.size < 1n ||
      before.size > BigInt(MAX_CODEX_CREDENTIAL_BYTES)
    ) {
      throw new Error(
        "Managed Codex credential source is not a bounded regular file",
      );
    }
    if (process.platform !== "win32" && (before.mode & 0o077n) !== 0n) {
      throw new Error("Managed Codex credential source permissions are unsafe");
    }
    if (
      process.platform !== "win32" &&
      typeof process.getuid === "function" &&
      before.uid !== BigInt(process.getuid())
    ) {
      throw new Error("Managed Codex credential source ownership is unsafe");
    }
    const bytes = await readHandle(handle, Number(before.size));
    const after = await handle.stat({ bigint: true });
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs ||
      after.size !== BigInt(bytes.length)
    ) {
      bytes.fill(0);
      throw new Error("Managed Codex credential source changed while read");
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

async function readHandle(handle: FileHandle, size: number): Promise<Buffer> {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const result = await handle.read(bytes, offset, size - offset, offset);
    if (result.bytesRead === 0) break;
    offset += result.bytesRead;
  }
  if (offset !== size) {
    bytes.fill(0);
    throw new Error("Managed Codex credential source ended while read");
  }
  return bytes;
}

function validateCredentialDocument(bytes: Buffer): void {
  let value: unknown;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("Managed Codex credential source is malformed");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Managed Codex credential source is malformed");
  }
}

async function writeCredential(
  destination: string,
  home: string,
  bytes: Buffer,
): Promise<void> {
  const temporaryPath = join(
    home,
    `.auth.json.tmp-${randomBytes(12).toString("hex")}`,
  );
  let handle: FileHandle;
  try {
    handle = await open(
      temporaryPath,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        (constants.O_NOFOLLOW ?? 0),
      PRIVATE_FILE_MODE,
    );
  } catch {
    throw new Error("Managed Codex credential destination could not be opened");
  }
  try {
    await handle.chmod(PRIVATE_FILE_MODE);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    try {
      await rename(temporaryPath, destination);
    } catch (error) {
      if (
        process.platform !== "win32" ||
        !["EACCES", "EEXIST", "ENOTEMPTY", "EPERM"].includes(
          errorCode(error) ?? "",
        )
      ) {
        throw error;
      }
      // Win32 rename does not replace an existing destination. Remove only
      // the already-conflicting pathname (never a real directory), then move
      // the fully synced private temporary file into place.
      await removeReplaceableCredential(destination);
      await rename(temporaryPath, destination);
    }
  } finally {
    await handle.close().catch(() => undefined);
    await unlink(temporaryPath).catch(() => undefined);
  }
  // Do not acknowledge the lease until the namespace update is durable. A
  // directory-sync failure is a fail-closed admission condition: retry here so
  // neither a returned lease nor a thrown pre-lease error can lose ownership
  // of auth.json across a crash.
  await syncDirectoryDurably(home);
}

async function removeReplaceableCredential(path: string): Promise<void> {
  try {
    const metadata = await lstat(path);
    if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
      throw new Error("Managed Codex credential destination is a directory");
    }
    await unlink(path);
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error;
  }
}

async function removeCredential(path: string, home: string): Promise<void> {
  try {
    const metadata = await lstat(path);
    if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
      throw new Error("Managed Codex credential destination is a directory");
    }
    await unlink(path);
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error;
  }
  // Sync even after ENOENT: a previous unlink may have succeeded before its
  // directory sync failed. Never report cleanup or finish preflight while the
  // removal can still be rolled back by a crash.
  await syncDirectoryDurably(home);
}

async function syncDirectoryDurably(directory: string): Promise<void> {
  let retryDelayMs = 10;
  let lastError: unknown;
  let attempts = 0;
  for (let attempt = 1; attempt <= MAX_DIRECTORY_SYNC_ATTEMPTS; attempt += 1) {
    attempts = attempt;
    try {
      await syncDirectory(directory);
      return;
    } catch (error) {
      lastError = error;
      if (
        attempt === MAX_DIRECTORY_SYNC_ATTEMPTS ||
        error instanceof DirectorySyncOperationTimeoutError
      ) {
        break;
      }
      // Keep admission closed during transient failures, while bounding total
      // startup/shutdown latency for a persistently unhealthy filesystem.
      await new Promise<void>((resolveRetry) => {
        setTimeout(resolveRetry, retryDelayMs);
      });
      retryDelayMs = Math.min(retryDelayMs * 2, 1_000);
    }
  }
  const attemptNoun = attempts === 1 ? "attempt" : "attempts";
  throw new Error(
    `Managed Codex credential directory remained non-durable after ${attempts} ${attemptNoun}`,
    { cause: lastError },
  );
}

async function syncDirectory(directory: string): Promise<void> {
  if (process.platform === "win32") return;
  // A timed-out fsync cannot be cancelled, and FileHandle.close() cannot
  // finish ahead of it. Do not open another handle for this directory until
  // the one outstanding operation and its close have settled.
  if (pendingDirectorySyncCleanups.has(directory)) {
    throw new DirectorySyncOperationTimeoutError("fsync", directory);
  }
  const openAttempt = open(
    directory,
    constants.O_RDONLY | (constants.O_DIRECTORY ?? 0),
  );
  let handle: FileHandle;
  try {
    handle = await waitForDirectorySyncOperation(
      openAttempt,
      "open",
      directory,
    );
  } catch (error) {
    if (error instanceof DirectorySyncOperationTimeoutError) {
      // open(2) cannot be cancelled. If the kernel eventually returns a
      // handle after our retry budget has advanced, close it without keeping
      // credential admission or cleanup pending.
      void openAttempt
        .then((lateHandle) => closeDirectoryHandle(lateHandle, directory))
        .catch(() => undefined);
    }
    throw error;
  }

  let syncAttempt: Promise<void>;
  try {
    syncAttempt = handle.sync();
  } catch (error) {
    await closeDirectoryHandle(handle, directory);
    throw error;
  }
  let syncTimedOut = false;
  try {
    await waitForDirectorySyncOperation(syncAttempt, "fsync", directory);
  } catch (error) {
    syncTimedOut = error instanceof DirectorySyncOperationTimeoutError;
    if (syncTimedOut) {
      // FileHandle.close() waits for outstanding operations. Retain one
      // process-wide cleanup barrier for this directory so retries fail
      // closed without accumulating handles or filesystem requests. Use the
      // actual close promise here: the barrier must remain until the resource
      // is really released, not merely until the bounded close observer gives
      // up waiting.
      const cleanupAttempt = syncAttempt.then(
        () => handle.close().catch(() => undefined),
        () => handle.close().catch(() => undefined),
      );
      retainDirectorySyncCleanup(directory, cleanupAttempt);
    }
    throw error;
  } finally {
    // A completed fsync is the durability boundary. Close is resource cleanup:
    // bound and detach it rather than turning durable state into a failure or
    // masking the original fsync error.
    if (!syncTimedOut) await closeDirectoryHandle(handle, directory);
  }
}

async function closeDirectoryHandle(
  handle: FileHandle,
  directory: string,
): Promise<void> {
  try {
    const closeAttempt = handle.close();
    try {
      await waitForDirectorySyncOperation(closeAttempt, "close", directory);
    } catch (error) {
      // close(2) cannot be cancelled. Keep observing a late rejection without
      // leaking additional directory handles. Admission remains closed until
      // the real close settles, while a completed fsync stays successful.
      if (error instanceof DirectorySyncOperationTimeoutError) {
        retainDirectorySyncCleanup(directory, closeAttempt);
      } else {
        void closeAttempt.catch(() => undefined);
      }
    }
  } catch {
    // Closing cannot invalidate an fsync that already completed, and callers
    // with a failed fsync must retain that original durability error.
  }
}

function retainDirectorySyncCleanup(
  directory: string,
  attempt: Promise<unknown>,
): void {
  const observed = attempt.then(
    () => undefined,
    () => undefined,
  );
  const prior = pendingDirectorySyncCleanups.get(directory);
  const barrier =
    prior === undefined
      ? observed
      : Promise.allSettled([prior, observed]).then(() => undefined);
  pendingDirectorySyncCleanups.set(directory, barrier);
  void barrier
    .finally(() => {
      if (pendingDirectorySyncCleanups.get(directory) === barrier) {
        pendingDirectorySyncCleanups.delete(directory);
      }
    })
    .catch(() => undefined);
}

class DirectorySyncOperationTimeoutError extends Error {
  constructor(operation: "open" | "fsync" | "close", directory: string) {
    super(
      `Managed Codex credential directory ${operation} timed out after ${DIRECTORY_SYNC_OPERATION_TIMEOUT_MS}ms for ${directory}`,
    );
    this.name = "DirectorySyncOperationTimeoutError";
  }
}

async function waitForDirectorySyncOperation<T>(
  operationAttempt: Promise<T>,
  operation: "open" | "fsync" | "close",
  directory: string,
): Promise<T> {
  let timeout: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      operationAttempt,
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => {
          reject(new DirectorySyncOperationTimeoutError(operation, directory));
        }, DIRECTORY_SYNC_OPERATION_TIMEOUT_MS);
        timeout.unref?.();
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

function errorCode(error: unknown): string | null {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code?: unknown }).code)
    : null;
}

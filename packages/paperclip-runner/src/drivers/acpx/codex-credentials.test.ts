import { fork, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  open,
  readFile,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
  type FileHandle,
} from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { stageManagedCodexCredential } from "./codex-credentials.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  vi.useRealTimers();
  vi.doUnmock("node:fs/promises");
  vi.resetModules();
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("managed Codex credentials", () => {
  it("stages inline JSON privately and removes it idempotently", async () => {
    const fixture = await credentialFixture();
    const lease = await stageManagedCodexCredential({
      agentHomeDirectory: fixture.home,
      environment: {
        PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: JSON.stringify({
          tokens: { access_token: "inline-canary" },
        }),
      },
    });

    expect(lease.mode).toBe("inline_json");
    const cleanupIntent = join(
      fixture.home,
      ".paperclip-auth-cleanup-required",
    );
    await expect(readFile(lease.path, "utf8")).resolves.toContain(
      "inline-canary",
    );
    await expect(readFile(cleanupIntent, "utf8")).resolves.toBe(
      "paperclip-managed-codex-cleanup-v1\n",
    );
    if (process.platform !== "win32") {
      expect((await stat(lease.path)).mode & 0o777).toBe(0o600);
    }
    await lease.close();
    await lease.close();
    await expect(readFile(lease.path)).rejects.toMatchObject({
      code: "ENOENT",
    });
    await expect(readFile(cleanupIntent)).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it("fences overlapping leases for the same isolated home", async () => {
    const fixture = await credentialFixture();
    const firstLease = await stageManagedCodexCredential({
      agentHomeDirectory: fixture.home,
      environment: {
        PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"first"}',
      },
    });

    await expect(
      stageManagedCodexCredential({
        agentHomeDirectory: fixture.home,
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"second"}',
        },
      }),
    ).rejects.toThrow("already has an active lease");
    await expect(readFile(firstLease.path, "utf8")).resolves.toBe(
      '{"owner":"first"}',
    );

    await firstLease.close();
    const secondLease = await stageManagedCodexCredential({
      agentHomeDirectory: fixture.home,
      environment: {
        PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"second"}',
      },
    });
    await expect(readFile(secondLease.path, "utf8")).resolves.toBe(
      '{"owner":"second"}',
    );
    await secondLease.close();
  });

  it("falls through when an unrelated listener occupies the primary lease port", async () => {
    const fixture = await credentialFixture();
    const canonicalHome = await realpath(fixture.home);
    const primaryPort = credentialLeasePrimaryPort(canonicalHome);
    const unrelated = createServer((socket) => {
      socket.end("unrelated-loopback-service\n");
    });
    await new Promise<void>((resolveListen, rejectListen) => {
      unrelated.once("error", rejectListen);
      unrelated.listen(primaryPort, "127.0.0.1", resolveListen);
    });

    try {
      const lease = await stageManagedCodexCredential({
        agentHomeDirectory: fixture.home,
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"paperclip"}',
        },
      });
      await expect(readFile(lease.path, "utf8")).resolves.toBe(
        '{"owner":"paperclip"}',
      );
      vi.resetModules();
      const freshCredentials = await import("./codex-credentials.js");
      await expect(
        freshCredentials.stageManagedCodexCredential({
          agentHomeDirectory: fixture.home,
          environment: {
            PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"contender"}',
          },
        }),
      ).rejects.toThrow("already has an active lease");
      await lease.close();

      const successor = await freshCredentials.stageManagedCodexCredential({
        agentHomeDirectory: fixture.home,
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"successor"}',
        },
      });
      await expect(readFile(successor.path, "utf8")).resolves.toBe(
        '{"owner":"successor"}',
      );
      await successor.close();
    } finally {
      await new Promise<void>((resolveClose, rejectClose) => {
        unrelated.close((error) => {
          if (error) rejectClose(error);
          else resolveClose();
        });
      });
    }
  });

  it("fails closed while the primary lease owner is not yet responsive", async () => {
    const fixture = await credentialFixture();
    const canonicalHome = await realpath(fixture.home);
    const primaryPort = credentialLeasePrimaryPort(canonicalHome);
    const acceptedSockets = new Set<import("node:net").Socket>();
    const publishingOwner = createServer((socket) => {
      acceptedSockets.add(socket);
      socket.once("close", () => acceptedSockets.delete(socket));
      socket.pause();
    });
    await new Promise<void>((resolveListen, rejectListen) => {
      publishingOwner.once("error", rejectListen);
      publishingOwner.listen(primaryPort, "127.0.0.1", resolveListen);
    });

    try {
      await expect(
        stageManagedCodexCredential({
          agentHomeDirectory: fixture.home,
          environment: {
            PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"contender"}',
          },
        }),
      ).rejects.toThrow(
        "could not safely bypass an unresponsive lease endpoint",
      );
      await expect(
        readFile(join(fixture.home, "auth.json")),
      ).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      for (const socket of acceptedSockets) socket.destroy();
      await new Promise<void>((resolveClose, rejectClose) => {
        publishingOwner.close((error) => {
          if (error) rejectClose(error);
          else resolveClose();
        });
      });
    }
  });

  it("fails closed when a competing candidate is unresponsive after bind", async () => {
    const fixture = await credentialFixture();
    const canonicalHome = await realpath(fixture.home);
    const competingPort = credentialLeasePort(canonicalHome, 1);
    const acceptedSockets = new Set<import("node:net").Socket>();
    const publishingOwner = createServer((socket) => {
      acceptedSockets.add(socket);
      socket.once("close", () => acceptedSockets.delete(socket));
      socket.pause();
    });
    await new Promise<void>((resolveListen, rejectListen) => {
      publishingOwner.once("error", rejectListen);
      publishingOwner.listen(competingPort, "127.0.0.1", resolveListen);
    });

    try {
      await expect(
        stageManagedCodexCredential({
          agentHomeDirectory: fixture.home,
          environment: {
            PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"contender"}',
          },
        }),
      ).rejects.toThrow("already has an active lease");
      await expect(
        readFile(join(fixture.home, "auth.json")),
      ).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      for (const socket of acceptedSockets) socket.destroy();
      await new Promise<void>((resolveClose, rejectClose) => {
        publishingOwner.close((error) => {
          if (error) rejectClose(error);
          else resolveClose();
        });
      });
    }
  });

  it(
    "fences another process and recovers only after its kernel lease dies",
    async () => {
      const fixture = await credentialFixture();
      const destination = join(fixture.home, "auth.json");
      const childScript = join(fixture.root, "credential-owner.mjs");
      const credentialModule = new URL(
        "./codex-credentials.ts",
        import.meta.url,
      ).href;
      await writeFile(
        childScript,
        [
          `const { stageManagedCodexCredential } = await import(${JSON.stringify(credentialModule)});`,
          "const lease = await stageManagedCodexCredential({",
          "  agentHomeDirectory: process.argv[2],",
          '  environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: \'{"owner":"first"}\' },',
          "});",
          'process.send?.({ type: "ready", path: lease.path });',
          "process.on('message', async (message) => {",
          "  if (message?.type !== 'close') return;",
          "  await lease.close();",
          "  process.exit(0);",
          "});",
        ].join("\n"),
      );
      const owner = fork(childScript, [fixture.home], {
        execArgv: ["--import", "tsx"],
        stdio: ["ignore", "pipe", "pipe", "ipc"],
      });
      try {
        await waitForChildMessage(owner, "ready");
        await expect(readFile(destination, "utf8")).resolves.toBe(
          '{"owner":"first"}',
        );

        if (process.platform !== "win32") {
          owner.kill("SIGSTOP");
          await new Promise<void>((resolveSignal) =>
            setTimeout(resolveSignal, 50),
          );
        }
        await expect(
          stageManagedCodexCredential({
            agentHomeDirectory: fixture.home,
            environment: {
              PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"second"}',
            },
          }),
        ).rejects.toThrow("already has an active lease");
        await expect(readFile(destination, "utf8")).resolves.toBe(
          '{"owner":"first"}',
        );

        if (process.platform !== "win32") owner.kill("SIGCONT");
        owner.kill(process.platform === "win32" ? undefined : "SIGKILL");
        await waitForChildExit(owner);

        const successor = await stageManagedCodexCredential({
          agentHomeDirectory: fixture.home,
          environment: {
            PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"second"}',
          },
        });
        await expect(readFile(destination, "utf8")).resolves.toBe(
          '{"owner":"second"}',
        );
        await successor.close();
      } finally {
        if (owner.exitCode === null && owner.signalCode === null) {
          if (process.platform !== "win32") owner.kill("SIGCONT");
          owner.kill(process.platform === "win32" ? undefined : "SIGKILL");
          await waitForChildExit(owner).catch(() => undefined);
        }
      }
    },
  );

  it.runIf(process.platform !== "win32")(
    "holds kernel ownership until credential cleanup is durable",
    async () => {
      const fixture = await credentialFixture();
      const lease = await stageManagedCodexCredential({
        agentHomeDirectory: fixture.home,
        environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
      });
      const probe = await open(fixture.home, "r");
      const prototype = Object.getPrototypeOf(probe) as {
        sync(this: FileHandle): Promise<void>;
      };
      await probe.close();
      const originalSync = prototype.sync;
      let releaseCleanup!: () => void;
      const cleanupGate = new Promise<void>((resolveCleanup) => {
        releaseCleanup = resolveCleanup;
      });
      let signalCleanupStarted!: () => void;
      const cleanupStarted = new Promise<void>((resolveStarted) => {
        signalCleanupStarted = resolveStarted;
      });
      let heldCleanup = false;
      const syncSpy = vi.spyOn(prototype, "sync").mockImplementation(
        async function (this: FileHandle): Promise<void> {
          if (!heldCleanup && (await this.stat()).isDirectory()) {
            heldCleanup = true;
            signalCleanupStarted();
            await cleanupGate;
          }
          await originalSync.call(this);
        },
      );
      try {
        const closing = lease.close();
        await cleanupStarted;
        vi.resetModules();
        const freshCredentials = await import("./codex-credentials.js");
        await expect(
          freshCredentials.stageManagedCodexCredential({
            agentHomeDirectory: fixture.home,
            environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
          }),
        ).rejects.toThrow("already has an active lease");

        releaseCleanup();
        await expect(closing).resolves.toBeUndefined();
        const successor = await freshCredentials.stageManagedCodexCredential({
          agentHomeDirectory: fixture.home,
          environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
        });
        await successor.close();
      } finally {
        releaseCleanup();
        syncSpy.mockRestore();
      }
    },
  );

  it("does not let an older failed close remove a successor credential", async () => {
    const fixture = await credentialFixture();
    const firstLease = await stageManagedCodexCredential({
      agentHomeDirectory: fixture.home,
      environment: {
        PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"first"}',
      },
    });
    await rm(firstLease.path, { force: true });
    await mkdir(firstLease.path);

    await expect(firstLease.close()).rejects.toThrow(
      "credential destination is a directory",
    );
    await rm(firstLease.path, { force: true, recursive: true });

    const secondLease = await stageManagedCodexCredential({
      agentHomeDirectory: fixture.home,
      environment: {
        PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"second"}',
      },
    });
    await expect(firstLease.close()).resolves.toBeUndefined();
    await expect(readFile(secondLease.path, "utf8")).resolves.toBe(
      '{"owner":"second"}',
    );
    await secondLease.close();
  });

  it("keeps ownership live while retrying lease-marker removal", async () => {
    const fixture = await credentialFixture();
    const actualFs = await vi.importActual<typeof import("node:fs/promises")>(
      "node:fs/promises",
    );
    let markerUnlinkAttempts = 0;
    vi.doMock("node:fs/promises", () => ({
      ...actualFs,
      unlink: async (path: Parameters<typeof actualFs.unlink>[0]) => {
        if (String(path).includes(".paperclip-auth-lease-v1-")) {
          markerUnlinkAttempts += 1;
          if (markerUnlinkAttempts === 1) {
            throw Object.assign(new Error("injected marker unlink failure"), {
              code: "EACCES",
            });
          }
        }
        await actualFs.unlink(path);
      },
    }));
    vi.resetModules();
    const freshCredentials = await import("./codex-credentials.js");
    const lease = await freshCredentials.stageManagedCodexCredential({
      agentHomeDirectory: fixture.home,
      environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
    });

    await expect(lease.close()).rejects.toThrow(
      "injected marker unlink failure",
    );
    const successor = await freshCredentials.stageManagedCodexCredential({
      agentHomeDirectory: fixture.home,
      environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
    });
    await successor.close();
    expect(markerUnlinkAttempts).toBeGreaterThanOrEqual(3);
  });

  it("recovers a persisted cleanup intent before admitting another provider", async () => {
    const fixture = await credentialFixture();
    const destination = join(fixture.home, "auth.json");
    const cleanupIntent = join(
      fixture.home,
      ".paperclip-auth-cleanup-required",
    );
    await writeFile(destination, '{"crash_stale":true}', { mode: 0o600 });
    await writeFile(
      cleanupIntent,
      "paperclip-managed-codex-cleanup-v1\n",
      { mode: 0o600 },
    );

    const lease = await stageManagedCodexCredential({
      agentHomeDirectory: fixture.home,
      environment: { OPENAI_API_KEY: "launch-only-key" },
    });
    await expect(readFile(destination)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(readFile(cleanupIntent, "utf8")).resolves.toBe(
      "paperclip-managed-codex-cleanup-v1\n",
    );
    await lease.close();
    await expect(readFile(cleanupIntent)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.runIf(process.platform !== "win32")(
    "retries the directory sync after unlink already succeeded",
    async () => {
      const fixture = await credentialFixture();
      const lease = await stageManagedCodexCredential({
        agentHomeDirectory: fixture.home,
        environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
      });
      const probe = await open(fixture.home, "r");
      const prototype = Object.getPrototypeOf(probe) as {
        sync(this: FileHandle): Promise<void>;
      };
      await probe.close();
      const originalSync = prototype.sync;
      let syncAttempts = 0;
      const syncSpy = vi.spyOn(prototype, "sync").mockImplementation(
        async function (this: FileHandle): Promise<void> {
          if ((await this.stat()).isDirectory()) {
            syncAttempts += 1;
            if (syncAttempts === 1) {
              throw new Error("injected directory sync failure");
            }
          }
          await originalSync.call(this);
        },
      );
      try {
        await expect(lease.close()).resolves.toBeUndefined();
        await expect(readFile(lease.path)).rejects.toMatchObject({ code: "ENOENT" });
        expect(syncAttempts).toBe(3);
      } finally {
        syncSpy.mockRestore();
      }
    },
  );

  it.runIf(process.platform !== "win32")(
    "retries preflight, installation, and removal until each is durable",
    async () => {
      const fixture = await credentialFixture();
      const probe = await open(fixture.home, "r");
      const prototype = Object.getPrototypeOf(probe) as {
        sync(this: FileHandle): Promise<void>;
      };
      await probe.close();
      const originalSync = prototype.sync;
      let directorySyncAttempts = 0;
      const syncSpy = vi.spyOn(prototype, "sync").mockImplementation(
        async function (this: FileHandle): Promise<void> {
          if ((await this.stat()).isDirectory()) {
            directorySyncAttempts += 1;
          }
          // The first attempt at each namespace boundary fails; the durable
          // helper must retry before staging or cleanup reports success.
          if ([1, 3, 5].includes(directorySyncAttempts)) {
            throw new Error("injected directory sync failure");
          }
          await originalSync.call(this);
        },
      );
      try {
        const lease = await stageManagedCodexCredential({
          agentHomeDirectory: fixture.home,
          environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
        });
        await expect(readFile(lease.path, "utf8")).resolves.toBe("{}");
        await expect(lease.close()).resolves.toBeUndefined();
        await expect(readFile(lease.path)).rejects.toMatchObject({ code: "ENOENT" });
        expect(directorySyncAttempts).toBe(8);
      } finally {
        syncSpy.mockRestore();
      }
    },
  );

  it("copies an explicit private source without changing the source", async () => {
    const fixture = await credentialFixture();
    const source = join(fixture.root, "managed-auth.json");
    await writeFile(
      source,
      JSON.stringify({ tokens: { access_token: "managed-canary" } }),
      { mode: 0o600 },
    );
    await chmod(source, 0o600);

    const lease = await stageManagedCodexCredential({
      agentHomeDirectory: fixture.home,
      sourcePath: source,
    });
    expect(lease.mode).toBe("managed_file");
    await expect(readFile(lease.path, "utf8")).resolves.toContain(
      "managed-canary",
    );
    await lease.close();
    await expect(readFile(source, "utf8")).resolves.toContain("managed-canary");
  });

  it("replaces a stale regular auth destination in JSON modes", async () => {
    const fixture = await credentialFixture();
    const destination = join(fixture.home, "auth.json");
    await writeFile(destination, '{"stale":true}', { mode: 0o600 });

    const lease = await stageManagedCodexCredential({
      agentHomeDirectory: fixture.home,
      environment: {
        PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"fresh":true}',
      },
    });
    await expect(readFile(destination, "utf8")).resolves.toBe(
      '{"fresh":true}',
    );
    await lease.close();
  });

  it("cleans stale and provider-generated auth in API-key mode", async () => {
    const fixture = await credentialFixture();
    const destination = join(fixture.home, "auth.json");
    await writeFile(destination, '{"stale":true}');

    const lease = await stageManagedCodexCredential({
      agentHomeDirectory: fixture.home,
      environment: { OPENAI_API_KEY: "launch-only-key" },
    });
    expect(lease.mode).toBe("api_key");
    await expect(readFile(destination)).rejects.toMatchObject({
      code: "ENOENT",
    });
    await writeFile(destination, '{"provider_generated":true}');
    await lease.close();
    await expect(readFile(destination)).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it.runIf(process.platform !== "win32")(
    "keeps API-key staging pending until stale removal is durable",
    async () => {
      const fixture = await credentialFixture();
      const destination = join(fixture.home, "auth.json");
      await writeFile(destination, '{"stale":true}', { mode: 0o600 });
      const probe = await open(fixture.home, "r");
      const prototype = Object.getPrototypeOf(probe) as {
        sync(this: FileHandle): Promise<void>;
      };
      await probe.close();
      const originalSync = prototype.sync;
      let syncAttempts = 0;
      const syncSpy = vi.spyOn(prototype, "sync").mockImplementation(
        async function (this: FileHandle): Promise<void> {
          if ((await this.stat()).isDirectory()) {
            syncAttempts += 1;
            if (syncAttempts === 1) {
              throw new Error("injected directory sync failure");
            }
          }
          await originalSync.call(this);
        },
      );
      try {
        const lease = await stageManagedCodexCredential({
          agentHomeDirectory: fixture.home,
          environment: { OPENAI_API_KEY: "launch-only-key" },
        });
        await expect(readFile(destination)).rejects.toMatchObject({ code: "ENOENT" });
        await expect(lease.close()).resolves.toBeUndefined();
        expect(syncAttempts).toBe(5);
      } finally {
        syncSpy.mockRestore();
      }
    },
  );

  it.runIf(process.platform !== "win32")(
    "fails a non-durable admission within a bound and scrubs again on retry",
    async () => {
      const fixture = await credentialFixture();
      const probe = await open(fixture.home, "r");
      const prototype = Object.getPrototypeOf(probe) as {
        sync(this: FileHandle): Promise<void>;
      };
      await probe.close();
      const originalSync = prototype.sync;
      const syncSpy = vi.spyOn(prototype, "sync").mockImplementation(
        async function (this: FileHandle): Promise<void> {
          if ((await this.stat()).isDirectory()) {
            throw new Error("persistent directory sync failure");
          }
          await originalSync.call(this);
        },
      );
      try {
        const staging = stageManagedCodexCredential({
          agentHomeDirectory: fixture.home,
          environment: { OPENAI_API_KEY: "launch-only-key" },
        });
        await expect(staging).rejects.toThrow(
          "remained non-durable after 8 attempts",
        );
        expect(syncSpy.mock.calls.length).toBeGreaterThanOrEqual(8);
        syncSpy.mockRestore();
        const lease = await stageManagedCodexCredential({
          agentHomeDirectory: fixture.home,
          environment: { OPENAI_API_KEY: "launch-only-key" },
        });
        await expect(lease.close()).resolves.toBeUndefined();
      } finally {
        syncSpy.mockRestore();
      }
    },
  );

  it.runIf(process.platform !== "win32")(
    "bounds a directory open that never settles",
    async () => {
      const fixture = await credentialFixture();
      const actualFs = await vi.importActual<typeof import("node:fs/promises")>(
        "node:fs/promises",
      );
      let directoryOpenAttempts = 0;
      let observeFirstOpen!: () => void;
      const firstOpen = new Promise<void>((resolveOpen) => {
        observeFirstOpen = resolveOpen;
      });
      vi.doMock("node:fs/promises", () => ({
        ...actualFs,
        open: async (
          path: Parameters<typeof open>[0],
          flags: Parameters<typeof open>[1],
          mode?: Parameters<typeof open>[2],
        ): Promise<FileHandle> => {
          if (String(path) === fixture.home) {
            directoryOpenAttempts += 1;
            observeFirstOpen();
            return await new Promise<FileHandle>(() => undefined);
          }
          return await actualFs.open(path, flags, mode);
        },
      }));
      vi.resetModules();
      const freshCredentials = await import("./codex-credentials.js");
      vi.useFakeTimers();

      const staging = freshCredentials.stageManagedCodexCredential({
        agentHomeDirectory: fixture.home,
        environment: { OPENAI_API_KEY: "launch-only-key" },
      });
      const rejection = expect(staging).rejects.toThrow(
        "remained non-durable after 1 attempt",
      );
      await firstOpen;
      await vi.advanceTimersByTimeAsync(20_000);
      await rejection;
      expect(directoryOpenAttempts).toBe(1);
    },
  );

  it.runIf(process.platform !== "win32")(
    "bounds a directory fsync without accumulating pending handles",
    async () => {
      const fixture = await credentialFixture();
      const actualFs = await vi.importActual<typeof import("node:fs/promises")>(
        "node:fs/promises",
      );
      let directorySyncAttempts = 0;
      let observeFirstSync!: () => void;
      const firstSync = new Promise<void>((resolveSync) => {
        observeFirstSync = resolveSync;
      });
      const stalledDirectoryHandle = {
        close: async (): Promise<void> => undefined,
        sync: async (): Promise<void> => {
          directorySyncAttempts += 1;
          observeFirstSync();
          return await new Promise<void>(() => undefined);
        },
      } as FileHandle;
      vi.doMock("node:fs/promises", () => ({
        ...actualFs,
        open: async (
          path: Parameters<typeof open>[0],
          flags: Parameters<typeof open>[1],
          mode?: Parameters<typeof open>[2],
        ): Promise<FileHandle> => {
          if (String(path) === fixture.home) return stalledDirectoryHandle;
          return await actualFs.open(path, flags, mode);
        },
      }));
      vi.resetModules();
      const freshCredentials = await import("./codex-credentials.js");
      vi.useFakeTimers();

      const staging = freshCredentials.stageManagedCodexCredential({
        agentHomeDirectory: fixture.home,
        environment: { OPENAI_API_KEY: "launch-only-key" },
      });
      const rejection = expect(staging).rejects.toThrow(
        "remained non-durable after 1 attempt",
      );
      await firstSync;
      await vi.advanceTimersByTimeAsync(20_000);
      await rejection;
      await expect(
        freshCredentials.stageManagedCodexCredential({
          agentHomeDirectory: fixture.home,
          environment: { OPENAI_API_KEY: "launch-only-key" },
        }),
      ).rejects.toThrow("remained non-durable after 1 attempt");
      expect(directorySyncAttempts).toBe(1);
    },
  );

  it.runIf(process.platform !== "win32")(
    "bounds a directory close that never settles after a durable fsync",
    async () => {
      const fixture = await credentialFixture();
      const actualFs = await vi.importActual<typeof import("node:fs/promises")>(
        "node:fs/promises",
      );
      let directoryCloseAttempts = 0;
      let observeFirstClose!: () => void;
      let settleFirstClose!: () => void;
      const firstClose = new Promise<void>((resolveClose) => {
        observeFirstClose = resolveClose;
      });
      const retainedClose = new Promise<void>((resolveClose) => {
        settleFirstClose = resolveClose;
      });
      vi.doMock("node:fs/promises", () => ({
        ...actualFs,
        open: async (
          path: Parameters<typeof open>[0],
          flags: Parameters<typeof open>[1],
          mode?: Parameters<typeof open>[2],
        ): Promise<FileHandle> => {
          if (String(path) === fixture.home) {
            return {
              close: async (): Promise<void> => {
                directoryCloseAttempts += 1;
                if (directoryCloseAttempts === 1) {
                  observeFirstClose();
                  return await retainedClose;
                }
              },
              sync: async (): Promise<void> => undefined,
            } as FileHandle;
          }
          return await actualFs.open(path, flags, mode);
        },
      }));
      vi.resetModules();
      const freshCredentials = await import("./codex-credentials.js");
      vi.useFakeTimers();

      const staging = freshCredentials.stageManagedCodexCredential({
        agentHomeDirectory: fixture.home,
        environment: { OPENAI_API_KEY: "launch-only-key" },
      });
      const rejection = expect(staging).rejects.toThrow(
        "remained non-durable after 1 attempt",
      );
      await firstClose;
      await vi.advanceTimersByTimeAsync(20_000);
      await rejection;
      expect(directoryCloseAttempts).toBe(1);

      settleFirstClose();
      await vi.advanceTimersByTimeAsync(20_000);
      const lease = await freshCredentials.stageManagedCodexCredential({
        agentHomeDirectory: fixture.home,
        environment: { OPENAI_API_KEY: "launch-only-key" },
      });
      await expect(lease.close()).resolves.toBeUndefined();
      expect(directoryCloseAttempts).toBeGreaterThan(1);
    },
  );

  it.runIf(process.platform !== "win32")(
    "keeps intent-publication failure before credential mutation and scrubs without process memory",
    async () => {
      const fixture = await credentialFixture();
      const destination = join(fixture.home, "auth.json");
      const cleanupIntent = join(
        fixture.home,
        ".paperclip-auth-cleanup-required",
      );
      const probe = await open(fixture.home, "r");
      const prototype = Object.getPrototypeOf(probe) as {
        sync(this: FileHandle): Promise<void>;
      };
      await probe.close();
      const originalSync = prototype.sync;
      let directorySyncAttempts = 0;
      const syncSpy = vi.spyOn(prototype, "sync").mockImplementation(
        async function (this: FileHandle): Promise<void> {
          if ((await this.stat()).isDirectory()) {
            directorySyncAttempts += 1;
            if (directorySyncAttempts > 1) {
              throw new Error("persistent intent sync failure");
            }
          }
          await originalSync.call(this);
        },
      );
      try {
        await expect(stageManagedCodexCredential({
          agentHomeDirectory: fixture.home,
          environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
        })).rejects.toThrow("remained non-durable after 8 attempts");
        await expect(readFile(destination)).rejects.toMatchObject({ code: "ENOENT" });

        // Model a crash losing the unsynced intent directory entry and the
        // next process finding an unexpected auth file. A fresh module has no
        // quarantine map from the failed process, so admission must rely on
        // the isolated-home scrub rather than process memory.
        syncSpy.mockRestore();
        await rm(cleanupIntent, { force: true });
        await writeFile(destination, '{"orphaned":true}', { mode: 0o600 });
        vi.resetModules();
        const freshCredentials = await import("./codex-credentials.js");
        const persistentSyncFailure = vi.spyOn(prototype, "sync").mockImplementation(
          async function (this: FileHandle): Promise<void> {
            if ((await this.stat()).isDirectory()) {
              throw new Error("persistent recovery sync failure");
            }
            await originalSync.call(this);
          },
        );
        try {
          await expect(freshCredentials.stageManagedCodexCredential({
            agentHomeDirectory: fixture.home,
            environment: { OPENAI_API_KEY: "launch-only-key" },
          })).rejects.toThrow("remained non-durable after 8 attempts");
          await expect(readFile(destination)).rejects.toMatchObject({ code: "ENOENT" });
        } finally {
          persistentSyncFailure.mockRestore();
        }
      } finally {
        syncSpy.mockRestore();
      }
    },
  );

  it.runIf(process.platform !== "win32")(
    "owns cleanup when post-rename directory durability fails",
    async () => {
      const fixture = await credentialFixture();
      const destination = join(fixture.home, "auth.json");
      const probe = await open(fixture.home, "r");
      const prototype = Object.getPrototypeOf(probe) as {
        sync(this: FileHandle): Promise<void>;
      };
      await probe.close();
      const originalSync = prototype.sync;
      let directorySyncAttempts = 0;
      const syncSpy = vi.spyOn(prototype, "sync").mockImplementation(
        async function (this: FileHandle): Promise<void> {
          if ((await this.stat()).isDirectory()) {
            directorySyncAttempts += 1;
            if (directorySyncAttempts > 2) {
              throw new Error("persistent post-rename sync failure");
            }
          }
          await originalSync.call(this);
        },
      );
      try {
        await expect(stageManagedCodexCredential({
          agentHomeDirectory: fixture.home,
          environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
        })).rejects.toThrow("remained non-durable after 8 attempts");
        await expect(readFile(destination, "utf8")).resolves.toBe("{}");

        syncSpy.mockRestore();
        const lease = await stageManagedCodexCredential({
          agentHomeDirectory: fixture.home,
          environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
        });
        await expect(readFile(destination, "utf8")).resolves.toBe("{}");
        await lease.close();
      } finally {
        syncSpy.mockRestore();
      }
    },
  );

  it("rejects missing, ambiguous, malformed, and unsafe sources", async () => {
    const fixture = await credentialFixture();
    await expect(
      stageManagedCodexCredential({ agentHomeDirectory: fixture.home }),
    ).rejects.toThrow(/credential missing/);
    await expect(
      stageManagedCodexCredential({
        agentHomeDirectory: fixture.home,
        environment: {
          OPENAI_API_KEY: "key",
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}",
        },
      }),
    ).rejects.toThrow(/ambiguous/);
    await expect(
      stageManagedCodexCredential({
        agentHomeDirectory: fixture.home,
        environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "[]" },
      }),
    ).rejects.toThrow(/malformed/);

    const source = join(fixture.root, "unsafe-auth.json");
    await writeFile(source, "{}", { mode: 0o644 });
    await chmod(source, 0o644);
    if (process.platform !== "win32") {
      await expect(
        stageManagedCodexCredential({
          agentHomeDirectory: fixture.home,
          sourcePath: source,
        }),
      ).rejects.toThrow(/permissions are unsafe/);
    }
  });

  it.runIf(process.platform !== "win32")(
    "rejects a credential home that is not private",
    async () => {
      const fixture = await credentialFixture();
      await chmod(fixture.home, 0o755);

      await expect(
        stageManagedCodexCredential({
          agentHomeDirectory: fixture.home,
          environment: { OPENAI_API_KEY: "launch-only-key" },
        }),
      ).rejects.toThrow(/home permissions are unsafe/);
    },
  );

  it.runIf(process.platform !== "win32")(
    "rejects a symbolic-link source",
    async () => {
      const fixture = await credentialFixture();
      const target = join(fixture.root, "auth-target.json");
      const source = join(fixture.root, "auth-link.json");
      await writeFile(target, "{}", { mode: 0o600 });
      await symlink(target, source);

      await expect(
        stageManagedCodexCredential({
          agentHomeDirectory: fixture.home,
          sourcePath: source,
        }),
      ).rejects.toThrow(/credential missing/);
    },
  );

  it.runIf(process.platform !== "win32")(
    "replaces a stale destination link without touching its target",
    async () => {
      const fixture = await credentialFixture();
      const target = join(fixture.root, "outside.json");
      const destination = join(fixture.home, "auth.json");
      await writeFile(target, '{"outside":true}', { mode: 0o600 });
      await symlink(target, destination);

      const lease = await stageManagedCodexCredential({
        agentHomeDirectory: fixture.home,
        environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
      });
      await expect(readFile(target, "utf8")).resolves.toBe('{"outside":true}');
      expect((await stat(lease.path)).isFile()).toBe(true);
      await lease.close();
    },
  );
});

async function credentialFixture(): Promise<{ root: string; home: string }> {
  const root = await mkdtemp(join(tmpdir(), "paperclip-acpx-credential-"));
  temporaryDirectories.push(root);
  const home = join(root, "codex-home");
  await mkdir(home, { mode: 0o700 });
  await chmod(home, 0o700);
  return { root, home };
}

function credentialLeasePrimaryPort(home: string): number {
  return credentialLeasePort(home, 0);
}

function credentialLeasePort(home: string, index: number): number {
  const scope = `${
    typeof process.getuid === "function" ? process.getuid() : "win32"
  }\0${home}`;
  const digest = createHash("sha256").update(scope).digest();
  const start = digest.readUInt16BE(0) % 16_384;
  const stride = digest.readUInt16BE(2) | 1;
  return 49_152 + ((start + index * stride) % 16_384);
}

async function waitForChildMessage(
  child: ChildProcess,
  type: string,
): Promise<void> {
  let diagnostic = "";
  child.stderr?.on("data", (chunk: Buffer) => {
    diagnostic = `${diagnostic}${chunk.toString("utf8")}`.slice(-4_096);
  });
  await new Promise<void>((resolveMessage, rejectMessage) => {
    const timeout = setTimeout(() => {
      rejectMessage(new Error(`child message timed out: ${diagnostic}`));
    }, 10_000);
    const finish = (error?: Error): void => {
      clearTimeout(timeout);
      child.off("message", onMessage);
      child.off("exit", onExit);
      if (error) rejectMessage(error);
      else resolveMessage();
    };
    const onMessage = (message: unknown): void => {
      if (
        typeof message === "object" &&
        message !== null &&
        "type" in message &&
        (message as { type?: unknown }).type === type
      ) {
        finish();
      }
    };
    const onExit = (code: number | null): void => {
      finish(
        new Error(
          `credential owner exited before ${type} (code ${String(code)}): ${diagnostic}`,
        ),
      );
    };
    child.on("message", onMessage);
    child.once("exit", onExit);
  });
}

async function waitForChildExit(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolveExit, rejectExit) => {
    const timeout = setTimeout(
      () => rejectExit(new Error("credential owner exit timed out")),
      10_000,
    );
    child.once("exit", () => {
      clearTimeout(timeout);
      resolveExit();
    });
  });
}

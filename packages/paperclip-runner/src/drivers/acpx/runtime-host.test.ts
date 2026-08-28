import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  VerifiedAcpxCommandLease,
  VerifiedAcpxInstallation,
} from "./installation-integrity.js";
import { resolveQualifiedAcpxProfile } from "./qualified-profiles.js";
import {
  AcpxRuntimeHost,
  type AcpxRuntimeHostDependencies,
  type AcpxRuntimePort,
} from "./runtime-host.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("ACPX runtime host", () => {
  it("rejects a pre-aborted admission before acquiring provider resources", async () => {
    const fixture = await hostFixture();
    const controller = new AbortController();
    const cancellation = new Error("admission cancelled before start");
    controller.abort(cancellation);
    const openRuntime = vi.fn(async () => runtimePort());
    const verifyInstallation = vi.fn(
      fixture.dependencies({ openRuntime }).verifyInstallation!,
    );

    await expect(
      AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "claude",
          model: "claude-sonnet-5",
          permissionMode: "deny-all",
          signal: controller.signal,
        },
        {
          ...fixture.dependencies({ openRuntime }),
          verifyInstallation,
        },
      ),
    ).rejects.toBe(cancellation);

    expect(verifyInstallation).not.toHaveBeenCalled();
    expect(openRuntime).not.toHaveBeenCalled();
    expect(fixture.commandClose).not.toHaveBeenCalled();
  });

  it("composes admission, isolation, model verification, and cleanup", async () => {
    const fixture = await hostFixture();
    let capturedEnvironment: Readonly<NodeJS.ProcessEnv> = {};
    const runtime = runtimePort({
      onClose: vi.fn(async () => undefined),
    });
    const dependencies = fixture.dependencies({
      openRuntime: async (options) => {
        capturedEnvironment = options.launchEnvironment;
        await writeFile(
          join(options.launchEnvironment.CODEX_HOME!, "auth.json"),
          '{"provider_generated":true}',
        );
        return runtime;
      },
    });

    const host = await AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "approve-reads",
        environment: {
          PATH: process.env.PATH,
          OPENAI_API_KEY: "launch-secret",
          HTTPS_PROXY: "https://proxy-user:proxy-secret@example.test",
        },
        systemInstructions: "Use the supplied runtime context.",
      },
      dependencies,
    );
    expect(host.identity()).toMatchObject({
      schema: "paperclip.runner.acpx-identity.v1",
      acpxRecordId: "record-1",
      requestedModel: "gpt-5.6-sol",
      permissionMode: "approve-reads",
    });
    expect(capturedEnvironment.OPENAI_API_KEY).toBe("launch-secret");
    expect(host.persistedEnvironment().OPENAI_API_KEY).toBeUndefined();
    expect(host.persistedEnvironment().HTTPS_PROXY).toBeUndefined();
    const authPath = join(host.runtimeRoot(), "codex-home", "auth.json");
    await expect(readFile(authPath, "utf8")).resolves.toContain(
      "provider_generated",
    );

    await host.close({ reason: "test complete" });
    await expect(readFile(authPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(runtime.close).toHaveBeenCalledOnce();
    expect(fixture.commandClose).toHaveBeenCalledOnce();
  });

  it("selects and verifies Claude's qualified reported model", async () => {
    const fixture = await hostFixture();
    let selected = false;
    const setModel = vi.fn(async (model: string) => {
      expect(model).toBe("claude-sonnet-5");
      selected = true;
    });
    const runtime = runtimePort({
      getStatus: async () => ({
        models: {
          currentModelId: selected ? "sonnet" : "default",
          availableModelIds: ["default", "sonnet"],
        },
      }),
      setModel,
    });
    const host = await AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "claude",
        model: "claude-sonnet-5",
        permissionMode: "deny-all",
      },
      fixture.dependencies({ openRuntime: async () => runtime }),
    );

    expect(setModel).toHaveBeenCalledOnce();
    expect(host.identity().effectiveModel).toBe("claude-sonnet-5");
    await host.close({ reason: "verified" });
  });

  it("rejects recovery drift before opening the provider", async () => {
    const fixture = await hostFixture();
    const openRuntime = vi.fn(async () => runtimePort());

    await expect(
      AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "claude",
          model: "claude-sonnet-5",
          permissionMode: "approve-reads",
          expectedIdentity: {
            kind: "acpx",
            normalizedSessionId: fixture.options.normalizedSessionId,
            acpxRecordId: "record-1",
            backendSessionId: "backend-1",
            agentSessionId: "agent-1",
            profileDigest: resolveQualifiedAcpxProfile(
              "claude",
              "claude-sonnet-5",
            ).commandDigest,
            workspaceDigest: `sha256:${"0".repeat(64)}`,
            requestedModel: "claude-sonnet-5",
            effectiveModel: "claude-sonnet-5",
            permissionMode: "approve-reads",
          },
        },
        fixture.dependencies({ openRuntime }),
      ),
    ).rejects.toThrow(/immutable session configuration/);
    expect(openRuntime).not.toHaveBeenCalled();
  });

  it("rejects an injected installation that does not match the profile", async () => {
    const fixture = await hostFixture();
    const openRuntime = vi.fn(async () => runtimePort());
    const dependencies = fixture.dependencies({ openRuntime });
    dependencies.verifyInstallation = async () => ({
      commandDigest: `sha256:${"f".repeat(64)}`,
      agentServerPackageJsonPath: join(fixture.root, "package.json"),
      agentRuntimePackageJsonPath: null,
      openCommand: async () => {
        throw new Error("mismatched installation must not open");
      },
    });

    await expect(
      AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "claude",
          model: "claude-sonnet-5",
          permissionMode: "approve-all",
        },
        dependencies,
      ),
    ).rejects.toThrow(/does not match its profile/);
    expect(openRuntime).not.toHaveBeenCalled();
  });

  it("cleans credentials and command leases when provider open fails", async () => {
    const fixture = await hostFixture();
    let authPath = "";
    await expect(
      AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "codex",
          model: "gpt-5.6-sol",
          permissionMode: "approve-all",
          environment: {
            PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET:
              '{"tokens":{"access_token":"canary"}}',
          },
        },
        fixture.dependencies({
          openRuntime: async (options) => {
            authPath = join(options.launchEnvironment.CODEX_HOME!, "auth.json");
            throw new Error("provider failed");
          },
        }),
      ),
    ).rejects.toThrow("provider failed");
    await expect(readFile(authPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(fixture.commandClose).toHaveBeenCalledOnce();
  });

  it("attempts every cleanup when runtime shutdown fails", async () => {
    const fixture = await hostFixture();
    let failClose = true;
    const runtime = runtimePort({
      onClose: vi.fn(async () => {
        if (failClose) throw new Error("runtime close failed");
      }),
    });
    const host = await AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "approve-all",
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}",
        },
      },
      fixture.dependencies({ openRuntime: async () => runtime }),
    );
    const authPath = join(host.runtimeRoot(), "codex-home", "auth.json");

    await expect(host.close({ reason: "first close" })).rejects.toThrow(
      /cleanup failed/,
    );
    await expect(readFile(authPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(fixture.commandClose).toHaveBeenCalledOnce();
    failClose = false;
    await expect(
      host.close({ reason: "retry close" }),
    ).resolves.toBeUndefined();
  });

  it("closes a command lease that resolves after admission is aborted", async () => {
    const fixture = await hostFixture();
    const commandAdmission = deferred<VerifiedAcpxCommandLease>();
    const lateCommandClose = vi.fn(async () => undefined);
    const openCommand = vi.fn(() => commandAdmission.promise);
    const openRuntime = vi.fn(async () => runtimePort());
    const controller = new AbortController();
    const cancellation = new Error("command admission cancelled");
    const profile = resolveQualifiedAcpxProfile("claude", "claude-sonnet-5");
    const opening = AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "claude",
        model: "claude-sonnet-5",
        permissionMode: "deny-all",
        signal: controller.signal,
      },
      {
        verifyInstallation: async () => ({
          commandDigest: profile.commandDigest,
          agentServerPackageJsonPath: join(fixture.root, "package.json"),
          agentRuntimePackageJsonPath: null,
          openCommand,
        }),
        openRuntime,
      },
    );
    await vi.waitFor(() => expect(openCommand).toHaveBeenCalledOnce());

    controller.abort(cancellation);
    await expect(opening).rejects.toBe(cancellation);
    commandAdmission.resolve({
      spawn: () => {
        throw new Error("late command must not spawn");
      },
      close: lateCommandClose,
    });

    await vi.waitFor(() => expect(lateCommandClose).toHaveBeenCalledOnce());
    expect(openRuntime).not.toHaveBeenCalled();
  });

  it("closes a credential lease that resolves after admission is aborted", async () => {
    const fixture = await hostFixture();
    const credentialAdmission = deferred<{
      path: string;
      mode: "inline_json";
      close(): Promise<void>;
    }>();
    const lateCredentialClose = vi.fn(async () => undefined);
    const stageCredential = vi.fn(() => credentialAdmission.promise);
    const openRuntime = vi.fn(async () => runtimePort());
    const controller = new AbortController();
    const cancellation = new Error("credential admission cancelled");
    const opening = AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "deny-all",
        signal: controller.signal,
      },
      {
        ...fixture.dependencies({ openRuntime }),
        stageCredential,
      },
    );
    await vi.waitFor(() => expect(stageCredential).toHaveBeenCalledOnce());

    controller.abort(cancellation);
    await expect(opening).rejects.toBe(cancellation);
    credentialAdmission.resolve({
      path: join(fixture.root, "late-auth.json"),
      mode: "inline_json",
      close: lateCredentialClose,
    });

    await vi.waitFor(() => expect(lateCredentialClose).toHaveBeenCalledOnce());
    expect(openRuntime).not.toHaveBeenCalled();
    expect(fixture.commandClose).not.toHaveBeenCalled();
  });

  it("forwards cancellation and closes a runtime that resolves after abort", async () => {
    const fixture = await hostFixture();
    const runtimeAdmission = deferred<AcpxRuntimePort>();
    const lateRuntime = runtimePort();
    let receivedSignal: AbortSignal | undefined;
    const openRuntime = vi.fn((options) => {
      receivedSignal = options.signal;
      return runtimeAdmission.promise;
    });
    const controller = new AbortController();
    const cancellation = new Error("runtime admission cancelled");
    const opening = AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "deny-all",
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}",
        },
        signal: controller.signal,
      },
      fixture.dependencies({ openRuntime }),
    );
    await vi.waitFor(() => expect(openRuntime).toHaveBeenCalledOnce());
    expect(receivedSignal).toBe(controller.signal);

    controller.abort(cancellation);
    await expect(opening).rejects.toBe(cancellation);
    expect(fixture.commandClose).toHaveBeenCalledOnce();
    runtimeAdmission.resolve(lateRuntime);

    await vi.waitFor(() => expect(lateRuntime.close).toHaveBeenCalledWith({
      reason: "ACPX runtime admission aborted",
    }));
  });
});

function runtimePort(
  input: {
    getStatus?: AcpxRuntimePort["getStatus"];
    setModel?: NonNullable<AcpxRuntimePort["setModel"]>;
    onClose?: AcpxRuntimePort["close"];
  } = {},
): AcpxRuntimePort & { close: ReturnType<typeof vi.fn> } {
  return {
    identity: async () => ({
      acpxRecordId: "record-1",
      backendSessionId: "backend-1",
      agentSessionId: "agent-1",
    }),
    getStatus:
      input.getStatus ??
      (async () => ({
        models: {
          currentModelId: "gpt-5.6-sol",
          availableModelIds: ["gpt-5.6-sol"],
        },
      })),
    ...(input.setModel ? { setModel: input.setModel } : {}),
    close: vi.fn(input.onClose ?? (async () => undefined)),
  };
}

async function hostFixture() {
  const root = await mkdtemp(join(tmpdir(), "paperclip-acpx-host-"));
  temporaryDirectories.push(root);
  const runtimeDirectory = join(root, "runtime");
  const workingDirectory = join(root, "workspace");
  await Promise.all([mkdir(runtimeDirectory), mkdir(workingDirectory)]);
  const commandClose = vi.fn(async () => undefined);
  const command: VerifiedAcpxCommandLease = {
    spawn: () => {
      throw new Error("test command is not spawnable");
    },
    close: commandClose,
  };
  return {
    root,
    commandClose,
    options: {
      runtimeDirectory,
      normalizedSessionId: "normalized-session-1",
      workingDirectory,
    },
    dependencies(
      input: Pick<AcpxRuntimeHostDependencies, "openRuntime">,
    ): AcpxRuntimeHostDependencies {
      return {
        verifyInstallation: async (profile) =>
          ({
            commandDigest: profile.commandDigest,
            agentServerPackageJsonPath: join(root, "package.json"),
            agentRuntimePackageJsonPath: null,
            openCommand: async () => command,
          }) satisfies VerifiedAcpxInstallation,
        openRuntime: input.openRuntime,
      };
    },
  };
}

function deferred<T>(): {
  promise: Promise<T>;
  resolve(value: T): void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

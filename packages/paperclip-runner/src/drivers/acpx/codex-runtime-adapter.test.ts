import type { ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";

import type {
  AcpAgentRegistry,
  AcpRuntime,
  AcpRuntimeHandle,
  AcpRuntimeOptions,
  AcpSessionStore,
} from "acpx/runtime";
import { decodeAcpxRuntimeHandleState } from "acpx/runtime";
import { describe, expect, it, vi } from "vitest";

import type { VerifiedAcpxCommandLease } from "./installation-integrity.js";
import { openCodexAcpxRuntime } from "./codex-runtime-adapter.js";
import type { AcpxRuntimePortOpenOptions } from "./runtime-host.js";

const HANDLE: AcpRuntimeHandle = {
  sessionKey: "session-key",
  backend: "acpx",
  runtimeSessionName: "runtime-name",
  cwd: "/workspace",
  acpxRecordId: "record-1",
  backendSessionId: "backend-1",
  agentSessionId: "agent-1",
};

describe("Codex ACPX runtime adapter", () => {
  it("rejects a pre-aborted admission before constructing or spawning ACPX", async () => {
    const cancellation = new Error("runtime admission cancelled");
    const controller = new AbortController();
    controller.abort(cancellation);
    const command = fakeCommand();
    const createRuntime = vi.fn();

    await expect(
      openCodexAcpxRuntime(
        { ...openOptions(command), signal: controller.signal },
        { createRuntime },
      ),
    ).rejects.toBe(cancellation);

    expect(createRuntime).not.toHaveBeenCalled();
    expect(command.spawn).not.toHaveBeenCalled();
  });

  it("opens a persistent Codex session without persisting launch secrets", async () => {
    const runtime = fakeRuntime();
    let runtimeOptions: AcpRuntimeOptions | undefined;
    const command = fakeCommand();
    const port = await openCodexAcpxRuntime(openOptions(command), {
      createRegistry: ({ overrides }) => {
        expect(overrides).toEqual({
          codex: ["paperclip-verified-acpx-command"],
        });
        return registry();
      },
      createStore: ({ stateDir }) => {
        expect(stateDir).toBe("/runtime/state");
        return store();
      },
      createRuntime: (options) => {
        runtimeOptions = options;
        return runtime;
      },
    });

    expect(runtime.ensureSession).toHaveBeenCalledWith({
      sessionKey: "provider-key",
      agent: "codex",
      mode: "persistent",
      cwd: "/workspace",
      sessionOptions: {
        model: "gpt-5.6-sol",
        systemPrompt: { append: "Use Paperclip tools." },
      },
    });
    expect(
      JSON.stringify(vi.mocked(runtime.ensureSession).mock.calls[0]?.[0]),
    ).not.toContain("credential-secret");
    expect(runtimeOptions?.spawnEnvironment?.()).toEqual({
      CODEX_HOME: "/runtime/agent-home",
      OPENAI_API_KEY: "credential-secret",
    });
    expect(runtimeOptions?.spawnCwd).toBe("/workspace");
    expect(runtimeOptions?.elicitationModes).toEqual(["form"]);
    expect(await port.identity()).toEqual({
      acpxRecordId: "record-1",
      backendSessionId: "backend-1",
      agentSessionId: "agent-1",
    });
  });

  it("launches only through the verified command lease", async () => {
    const runtime = fakeRuntime();
    let runtimeOptions: AcpRuntimeOptions | undefined;
    const command = fakeCommand();
    await openCodexAcpxRuntime(openOptions(command), {
      createRegistry: () => registry(),
      createStore: () => store(),
      createRuntime: (options) => {
        runtimeOptions = options;
        return runtime;
      },
    });
    const child = fakeChild();
    vi.mocked(command.spawn).mockReturnValue(child);
    const spawnOptions = { cwd: "/runtime/spawn" };

    expect(
      runtimeOptions?.spawnAgent?.({
        command: "/attacker/replacement",
        args: ["--stdio"],
        options: spawnOptions,
      }),
    ).toBe(child);
    expect(command.spawn).toHaveBeenCalledWith(["--stdio"], spawnOptions);
  });

  it("maps status, model selection, and state-preserving close", async () => {
    const runtime = fakeRuntime();
    vi.mocked(runtime.getStatus!).mockResolvedValue({
      models: {
        currentModelId: "gpt-5.6-sol",
        availableModelIds: ["gpt-5.6-sol"],
      },
    });
    const port = await openCodexAcpxRuntime(openOptions(fakeCommand()), {
      createRegistry: () => registry(),
      createStore: () => store(),
      createRuntime: () => runtime,
    });

    expect(await port.getStatus()).toEqual({
      models: {
        currentModelId: "gpt-5.6-sol",
        availableModelIds: ["gpt-5.6-sol"],
      },
    });
    await port.setModel?.("gpt-5.6-sol");
    expect(runtime.setConfigOption).toHaveBeenCalledWith({
      handle: HANDLE,
      key: "model",
      value: "gpt-5.6-sol",
    });
    await port.close({ reason: "test complete" });
    expect(runtime.close).toHaveBeenCalledWith({
      handle: HANDLE,
      reason: "test complete",
      discardPersistentState: false,
    });
  });

  it("retries protocol cleanup after a retained attempt never settles", async () => {
    vi.useFakeTimers();
    try {
      const runtime = fakeRuntime();
      const runtimeClose = new Promise<void>(() => {});
      vi.mocked(runtime.close)
        .mockReturnValueOnce(runtimeClose)
        .mockResolvedValueOnce(undefined);
      const child = fakeChild();
      const command = fakeCommand();
      vi.mocked(command.spawn).mockReturnValue(child);
      let runtimeOptions: AcpRuntimeOptions | undefined;
      const port = await openCodexAcpxRuntime(openOptions(command), {
        createRegistry: () => registry(),
        createStore: () => store(),
        createRuntime: (options) => {
          runtimeOptions = options;
          return runtime;
        },
      });
      runtimeOptions?.spawnAgent?.({
        command: "ignored",
        args: ["--stdio"],
        options: {},
      });

      const firstClose = expect(
        port.close({ reason: "runtime close stalled" }),
      ).rejects.toThrow("ACPX runtime and provider cleanup failed");
      await Promise.resolve();
      expect(runtime.close).toHaveBeenCalledOnce();
      await vi.advanceTimersByTimeAsync(2_000);
      expect(child.kill).toHaveBeenCalledWith("SIGTERM");
      await firstClose;

      // The first exact cleanup remains owned, but it cannot become the retry
      // barrier after its bounded observation and provider termination finish.
      expect(runtime.close).toHaveBeenCalledOnce();
      await expect(port.close({ reason: "idempotent terminal close" }))
        .resolves.toBeUndefined();
      expect(runtime.close).toHaveBeenCalledTimes(2);
      expect(runtime.close).toHaveBeenLastCalledWith({
        handle: HANDLE,
        reason: "idempotent terminal close",
        discardPersistentState: false,
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("allows a fresh close after a retained attempt rejects late", async () => {
    vi.useFakeTimers();
    try {
      const runtime = fakeRuntime();
      let rejectRuntimeClose!: (error: unknown) => void;
      const runtimeClose = new Promise<void>((_resolve, reject) => {
        rejectRuntimeClose = reject;
      });
      vi.mocked(runtime.close)
        .mockReturnValueOnce(runtimeClose)
        .mockResolvedValueOnce(undefined);
      const child = fakeChild();
      const command = fakeCommand();
      vi.mocked(command.spawn).mockReturnValue(child);
      let runtimeOptions: AcpRuntimeOptions | undefined;
      const port = await openCodexAcpxRuntime(openOptions(command), {
        createRegistry: () => registry(),
        createStore: () => store(),
        createRuntime: (options) => {
          runtimeOptions = options;
          return runtime;
        },
      });
      runtimeOptions?.spawnAgent?.({
        command: "ignored",
        args: ["--stdio"],
        options: {},
      });

      const firstClose = expect(
        port.close({ reason: "runtime close stalled" }),
      ).rejects.toThrow("ACPX runtime and provider cleanup failed");
      await Promise.resolve();
      await vi.advanceTimersByTimeAsync(2_000);
      await firstClose;
      expect(child.kill).toHaveBeenCalledWith("SIGTERM");

      const protocolFailure = new Error("late protocol close failure");
      rejectRuntimeClose(protocolFailure);
      await Promise.resolve();
      await expect(port.close({ reason: "retry after retained failure" }))
        .resolves.toBeUndefined();
      await vi.waitFor(() => expect(runtime.close).toHaveBeenCalledTimes(3));
      expect(runtime.close).toHaveBeenLastCalledWith({
        handle: HANDLE,
        reason: "ACPX late protocol cleanup reconciliation 1",
        discardPersistentState: false,
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("reconciles an older close that fails after a fresh close succeeds", async () => {
    vi.useFakeTimers();
    try {
      const runtime = fakeRuntime();
      let rejectFirstClose!: (error: unknown) => void;
      const firstRuntimeClose = new Promise<void>((_resolve, reject) => {
        rejectFirstClose = reject;
      });
      vi.mocked(runtime.close)
        .mockReturnValueOnce(firstRuntimeClose)
        .mockResolvedValueOnce(undefined)
        .mockResolvedValueOnce(undefined);
      const child = fakeChild();
      const command = fakeCommand();
      vi.mocked(command.spawn).mockReturnValue(child);
      let runtimeOptions: AcpRuntimeOptions | undefined;
      const port = await openCodexAcpxRuntime(openOptions(command), {
        createRegistry: () => registry(),
        createStore: () => store(),
        createRuntime: (options) => {
          runtimeOptions = options;
          return runtime;
        },
      });
      runtimeOptions?.spawnAgent?.({
        command: "ignored",
        args: ["--stdio"],
        options: {},
      });

      const firstClose = expect(
        port.close({ reason: "first protocol close stalls" }),
      ).rejects.toThrow("ACPX runtime and provider cleanup failed");
      await Promise.resolve();
      await vi.advanceTimersByTimeAsync(2_000);
      await firstClose;

      await expect(port.close({ reason: "fresh protocol close succeeds" }))
        .resolves.toBeUndefined();
      expect(runtime.close).toHaveBeenCalledTimes(2);

      rejectFirstClose(new Error("older protocol close failed late"));
      await vi.waitFor(() => expect(runtime.close).toHaveBeenCalledTimes(3));
      expect(runtime.close).toHaveBeenLastCalledWith({
        handle: HANDLE,
        reason: "ACPX late protocol cleanup reconciliation 1",
        discardPersistentState: false,
      });
      await expect(port.close({ reason: "observe reconciled cleanup" }))
        .resolves.toBeUndefined();
      expect(runtime.close).toHaveBeenCalledTimes(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it("reconciles an older late failure that settles during a fresh close", async () => {
    vi.useFakeTimers();
    try {
      const runtime = fakeRuntime();
      let rejectFirstClose!: (error: unknown) => void;
      const firstRuntimeClose = new Promise<void>((_resolve, reject) => {
        rejectFirstClose = reject;
      });
      let resolveFreshClose!: () => void;
      const freshRuntimeClose = new Promise<void>((resolve) => {
        resolveFreshClose = resolve;
      });
      vi.mocked(runtime.close)
        .mockReturnValueOnce(firstRuntimeClose)
        .mockReturnValueOnce(freshRuntimeClose)
        .mockResolvedValueOnce(undefined);
      const child = fakeChild();
      const command = fakeCommand();
      vi.mocked(command.spawn).mockReturnValue(child);
      let runtimeOptions: AcpRuntimeOptions | undefined;
      const port = await openCodexAcpxRuntime(openOptions(command), {
        createRegistry: () => registry(),
        createStore: () => store(),
        createRuntime: (options) => {
          runtimeOptions = options;
          return runtime;
        },
      });
      runtimeOptions?.spawnAgent?.({
        command: "ignored",
        args: ["--stdio"],
        options: {},
      });

      const firstClose = expect(
        port.close({ reason: "first protocol close stalls" }),
      ).rejects.toThrow("ACPX runtime and provider cleanup failed");
      await Promise.resolve();
      await vi.advanceTimersByTimeAsync(2_000);
      await firstClose;

      const freshClose = port.close({
        reason: "fresh protocol close remains in flight",
      });
      await vi.waitFor(() => expect(runtime.close).toHaveBeenCalledTimes(2));
      rejectFirstClose(new Error("older protocol close failed during retry"));
      await vi.advanceTimersByTimeAsync(0);
      expect(runtime.close).toHaveBeenCalledTimes(2);

      resolveFreshClose();
      await freshClose;
      await vi.waitFor(() => expect(runtime.close).toHaveBeenCalledTimes(3));
      expect(runtime.close).toHaveBeenLastCalledWith({
        handle: HANDLE,
        reason: "ACPX late protocol cleanup reconciliation 1",
        discardPersistentState: false,
      });
      await expect(port.close({ reason: "observe reconciled cleanup" }))
        .resolves.toBeUndefined();
      expect(runtime.close).toHaveBeenCalledTimes(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not let late settlements bypass the reconciliation retry bound", async () => {
    vi.useFakeTimers();
    try {
      const runtime = fakeRuntime();
      const deferred = Array.from({ length: 4 }, () => {
        let resolve!: () => void;
        let reject!: (error: unknown) => void;
        const promise = new Promise<void>((resolvePromise, rejectPromise) => {
          resolve = resolvePromise;
          reject = rejectPromise;
        });
        return { promise, reject, resolve };
      });
      vi.mocked(runtime.close)
        .mockReturnValueOnce(deferred[0]!.promise)
        .mockResolvedValueOnce(undefined)
        .mockReturnValueOnce(deferred[1]!.promise)
        .mockReturnValueOnce(deferred[2]!.promise)
        .mockReturnValueOnce(deferred[3]!.promise);
      const port = await openCodexAcpxRuntime(openOptions(fakeCommand()), {
        createRegistry: () => registry(),
        createStore: () => store(),
        createRuntime: () => runtime,
      });

      const firstClose = expect(
        port.close({ reason: "first protocol close stalls" }),
      ).rejects.toThrow("ACPX runtime and provider cleanup failed");
      await Promise.resolve();
      await vi.advanceTimersByTimeAsync(2_000);
      await firstClose;
      await expect(port.close({ reason: "fresh protocol close succeeds" }))
        .resolves.toBeUndefined();

      deferred[0]!.reject(new Error("older protocol close failed late"));
      await vi.waitFor(() => expect(runtime.close).toHaveBeenCalledTimes(3));
      await vi.advanceTimersByTimeAsync(2_000);
      await vi.waitFor(() => expect(runtime.close).toHaveBeenCalledTimes(4));
      await vi.advanceTimersByTimeAsync(2_000);
      await vi.waitFor(() => expect(runtime.close).toHaveBeenCalledTimes(5));
      await vi.advanceTimersByTimeAsync(2_000);

      // The third automatic attempt has exhausted the budget. Its eventual
      // late rejection must not manufacture an unbounded fourth generation.
      deferred[3]!.reject(new Error("final reconciliation failed late"));
      await vi.advanceTimersByTimeAsync(0);
      expect(runtime.close).toHaveBeenCalledTimes(5);
      deferred[1]!.resolve();
      deferred[2]!.resolve();
      await Promise.resolve();
    } finally {
      vi.useRealTimers();
    }
  });

  it("shares one reconciliation budget across sequential late failures", async () => {
    vi.useFakeTimers();
    try {
      const runtime = fakeRuntime();
      const releasedAttempts = Array.from({ length: 4 }, () => {
        let reject!: (error: unknown) => void;
        const promise = new Promise<void>((_resolve, rejectPromise) => {
          reject = rejectPromise;
        });
        return { promise, reject };
      });
      vi.mocked(runtime.close)
        .mockReturnValueOnce(releasedAttempts[0]!.promise)
        .mockReturnValueOnce(releasedAttempts[1]!.promise)
        .mockReturnValueOnce(releasedAttempts[2]!.promise)
        .mockReturnValueOnce(releasedAttempts[3]!.promise)
        .mockResolvedValue(undefined);
      const port = await openCodexAcpxRuntime(openOptions(fakeCommand()), {
        createRegistry: () => registry(),
        createStore: () => store(),
        createRuntime: () => runtime,
        runtimeCloseTimeoutMs: 1,
      });

      for (const reason of [
        "first released close",
        "second released close",
        "third released close",
        "fourth released close",
      ]) {
        const close = expect(port.close({ reason })).rejects.toThrow(
          "ACPX runtime and provider cleanup failed",
        );
        await Promise.resolve();
        await vi.advanceTimersByTimeAsync(1);
        await close;
      }
      await expect(port.close({ reason: "newer close succeeds" }))
        .resolves.toBeUndefined();
      expect(runtime.close).toHaveBeenCalledTimes(5);

      for (let index = 0; index < 3; index += 1) {
        releasedAttempts[index]!.reject(
          new Error(`released close ${index + 1} failed late`),
        );
        await vi.advanceTimersByTimeAsync(0);
        expect(runtime.close).toHaveBeenCalledTimes(6 + index);
      }

      // Three automatic attempts exhaust the one port-lifetime budget. The
      // fourth watched attempt cannot replenish it merely by failing after
      // the preceding reconciliation closes succeeded.
      releasedAttempts[3]!.reject(
        new Error("released close 4 failed after the global budget"),
      );
      await vi.advanceTimersByTimeAsync(0);
      expect(runtime.close).toHaveBeenCalledTimes(8);
    } finally {
      vi.useRealTimers();
    }
  });

  it("rechecks late failures when a reconciliation owner finalizes", async () => {
    vi.useFakeTimers();
    let releaseOwnerFinalizer: (() => void) | undefined;
    try {
      const runtime = fakeRuntime();
      const deferred = Array.from({ length: 3 }, () => {
        let resolve!: () => void;
        let reject!: (error: unknown) => void;
        const promise = new Promise<void>((resolvePromise, rejectPromise) => {
          resolve = resolvePromise;
          reject = rejectPromise;
        });
        return { promise, reject, resolve };
      });
      vi.mocked(runtime.close)
        .mockReturnValueOnce(deferred[0]!.promise)
        .mockReturnValueOnce(deferred[1]!.promise)
        .mockReturnValueOnce(deferred[2]!.promise)
        .mockResolvedValueOnce(undefined);
      const port = await openCodexAcpxRuntime(openOptions(fakeCommand()), {
        createRegistry: () => registry(),
        createStore: () => store(),
        createRuntime: () => runtime,
        runtimeCloseTimeoutMs: 1,
      });

      for (const reason of ["first close stalls", "second close stalls"]) {
        const close = expect(port.close({ reason })).rejects.toThrow(
          "ACPX runtime and provider cleanup failed",
        );
        await Promise.resolve();
        await vi.advanceTimersByTimeAsync(1);
        await close;
      }

      const originalFinally = Promise.prototype.finally;
      let finalizerRegistrations = 0;
      const ownerFinalizerGate = new Promise<void>((resolve) => {
        releaseOwnerFinalizer = resolve;
      });
      const finallySpy = vi
        .spyOn(Promise.prototype, "finally")
        .mockImplementation(function (onFinally) {
          finalizerRegistrations += 1;
          // closeRuntime first retains its protocol outcome; the next new
          // finalizer owns the reconciliation generation. Hold that owner
          // after its retry decision while the second released attempt fails.
          if (finalizerRegistrations !== 2) {
            return originalFinally.call(this, onFinally);
          }
          return originalFinally.call(this, () => {
            deferred[1]!.reject(new Error("second retained close failed"));
            return ownerFinalizerGate.then(() => onFinally?.());
          });
        });
      try {
        deferred[0]!.reject(new Error("first retained close failed"));
        await vi.advanceTimersByTimeAsync(0);
        expect(runtime.close).toHaveBeenCalledTimes(3);
        expect(finalizerRegistrations).toBeGreaterThanOrEqual(2);
      } finally {
        finallySpy.mockRestore();
      }

      deferred[2]!.resolve();
      await vi.advanceTimersByTimeAsync(0);
      expect(runtime.close).toHaveBeenCalledTimes(3);
      releaseOwnerFinalizer();
      releaseOwnerFinalizer = undefined;
      await vi.advanceTimersByTimeAsync(0);

      expect(runtime.close).toHaveBeenCalledTimes(4);
      expect(runtime.close).toHaveBeenLastCalledWith({
        handle: HANDLE,
        reason: "ACPX late protocol cleanup reconciliation 2",
        discardPersistentState: false,
      });
      await vi.advanceTimersByTimeAsync(0);
      expect(runtime.close).toHaveBeenCalledTimes(4);
      await expect(port.close({ reason: "observe reconciled cleanup" }))
        .resolves.toBeUndefined();
      expect(runtime.close).toHaveBeenCalledTimes(4);
    } finally {
      releaseOwnerFinalizer?.();
      vi.useRealTimers();
    }
  });

  it("maps prompt turns to the admitted ACPX handle", async () => {
    const runtime = fakeRuntime();
    const turn = {
      requestId: "turn-1",
      promptStarted: Promise.resolve(),
      events: { async *[Symbol.asyncIterator]() {} },
      result: Promise.resolve({ status: "completed" as const }),
      cancel: vi.fn(),
      closeStream: vi.fn(),
    };
    vi.mocked(runtime.startTurn).mockReturnValue(turn);
    const port = await openCodexAcpxRuntime(openOptions(fakeCommand()), {
      createRegistry: () => registry(),
      createStore: () => store(),
      createRuntime: () => runtime,
    });
    const signal = new AbortController().signal;
    const onElicitation = vi.fn();

    expect(
      port.startTurn({
        text: "Complete the task.",
        requestId: "turn-1",
        signal,
        onElicitation,
      }),
    ).toBe(turn);
    expect(runtime.startTurn).toHaveBeenCalledWith({
      handle: HANDLE,
      text: "Complete the task.",
      mode: "prompt",
      requestId: "turn-1",
      signal,
      onElicitation,
    });
  });

  it("projects only ephemeral MCP bindings and applies fail-closed permissions", async () => {
    const runtime = fakeRuntime();
    let runtimeOptions: AcpRuntimeOptions | undefined;
    const port = await openCodexAcpxRuntime(
      {
        ...openOptions(fakeCommand()),
        permissionMode: "deny-all",
        mcpServers: [
          {
            name: "paperclip",
            url: "http://127.0.0.1:3210/mcp",
            bearerToken: "bridge-secret",
            runnerOwned: true,
          },
        ],
      },
      {
        createRegistry: () => registry(),
        createStore: () => store(),
        createRuntime: (options) => {
          runtimeOptions = options;
          return runtime;
        },
      },
    );

    expect(runtimeOptions?.mcpServers).toEqual([
      {
        type: "http",
        name: "paperclip",
        url: "http://127.0.0.1:3210/mcp",
        headers: [{ name: "Authorization", value: "Bearer bridge-secret" }],
      },
    ]);
    await expect(
      runtimeOptions?.onPermissionRequest?.(
        {
          sessionId: "session-1",
          inferredKind: "execute",
          raw: { _meta: { is_mcp_tool_approval: true } },
        },
        { signal: new AbortController().signal },
      ),
    ).resolves.toEqual({ outcome: "reject_once" });
    await expect(
      runtimeOptions?.onPermissionRequest?.(
        {
          sessionId: "session-1",
          inferredKind: "execute",
          raw: {},
        },
        { signal: new AbortController().signal },
      ),
    ).resolves.toEqual({ outcome: "reject_once" });
    expect(
      JSON.stringify(vi.mocked(runtime.ensureSession).mock.calls),
    ).not.toContain("bridge-secret");
    await port.close({ reason: "complete" });
  });

  it("delegates permissions that require an unavailable coordinator", async () => {
    const runtime = fakeRuntime();
    let runtimeOptions: AcpRuntimeOptions | undefined;
    const port = await openCodexAcpxRuntime(openOptions(fakeCommand()), {
      createRegistry: () => registry(),
      createStore: () => store(),
      createRuntime: (options) => {
        runtimeOptions = options;
        return runtime;
      },
    });

    await expect(
      runtimeOptions?.onPermissionRequest?.(
        {
          sessionId: "session-1",
          inferredKind: "write",
          raw: {},
        },
        { signal: new AbortController().signal },
      ),
    ).resolves.toBeUndefined();
    await port.close({ reason: "complete" });
  });

  it("fails closed and closes the session when ACPX omits recovery identity", async () => {
    const runtime = fakeRuntime({ ...HANDLE, agentSessionId: undefined });
    await expect(
      openCodexAcpxRuntime(openOptions(fakeCommand()), {
        createRegistry: () => registry(),
        createStore: () => store(),
        createRuntime: () => runtime,
      }),
    ).rejects.toThrow("ACPX runtime omitted agentSessionId");
    expect(runtime.close).toHaveBeenCalledWith({
      handle: { ...HANDLE, agentSessionId: undefined },
      reason: "ACPX runtime identity validation failed",
      discardPersistentState: false,
    });
  });

  it("terminates a provider spawned before the session handshake rejects", async () => {
    const child = fakeChild();
    const command = fakeCommand();
    vi.mocked(command.spawn).mockReturnValue(child);
    const failure = new Error("ACP handshake rejected");
    const runtime = fakeRuntime();

    await expect(
      openCodexAcpxRuntime(openOptions(command), {
        createRegistry: () => registry(),
        createStore: () => store(),
        createRuntime: (options) => {
          vi.mocked(runtime.ensureSession).mockImplementation(async () => {
            options.spawnAgent?.({
              command: "ignored",
              args: ["--stdio"],
              options: {},
            });
            throw failure;
          });
          return runtime;
        },
      }),
    ).rejects.toBe(failure);
    expect(runtime.close).not.toHaveBeenCalled();
    expect(child.kill).toHaveBeenCalledWith("SIGTERM");
  });

  it("aborts a blocked handshake, reaps its provider, and closes a late session", async () => {
    let resolveHandshake: ((handle: AcpRuntimeHandle) => void) | undefined;
    const blockedHandshake = new Promise<AcpRuntimeHandle>((resolve) => {
      resolveHandshake = resolve;
    });
    const child = fakeChild();
    const command = fakeCommand();
    vi.mocked(command.spawn).mockReturnValue(child);
    const runtime = fakeRuntime();
    const controller = new AbortController();
    const cancellation = new Error("runtime admission cancelled");

    const opening = openCodexAcpxRuntime(
      { ...openOptions(command), signal: controller.signal },
      {
        createRegistry: () => registry(),
        createStore: () => store(),
        createRuntime: (runtimeOptions) => {
          vi.mocked(runtime.ensureSession).mockImplementation(async () => {
            runtimeOptions.spawnAgent?.({
              command: "ignored",
              args: ["--stdio"],
              options: {},
            });
            return await blockedHandshake;
          });
          return runtime;
        },
      },
    );
    await vi.waitFor(() => expect(command.spawn).toHaveBeenCalledOnce());

    controller.abort(cancellation);
    await expect(opening).rejects.toBe(cancellation);
    expect(child.kill).toHaveBeenCalledWith("SIGTERM");

    resolveHandshake?.(HANDLE);
    await vi.waitFor(() => expect(runtime.close).toHaveBeenCalledOnce());
    expect(runtime.close).toHaveBeenCalledWith({
      handle: HANDLE,
      reason: "ACPX runtime admission aborted",
      discardPersistentState: false,
    });
  });

  it("retries retained admission cleanup after the first close times out", async () => {
    let rejectHandshake: ((error: Error) => void) | undefined;
    const blockedHandshake = new Promise<AcpRuntimeHandle>(
      (_resolve, reject) => {
        rejectHandshake = reject;
      },
    );
    const runtime = fakeRuntime();
    vi.mocked(runtime.ensureSession).mockReturnValue(blockedHandshake);
    vi.mocked(runtime.close)
      .mockImplementationOnce(() => new Promise<void>(() => undefined))
      .mockResolvedValueOnce(undefined);
    const controller = new AbortController();
    const cancellation = new Error("runtime admission cancelled");
    let runtimeOptions: AcpRuntimeOptions | undefined;

    const opening = openCodexAcpxRuntime(
      {
        ...openOptions(fakeCommand()),
        signal: controller.signal,
      },
      {
        createRegistry: () => registry(),
        createStore: () => store(),
        createRuntime: (options) => {
          runtimeOptions = options;
          return runtime;
        },
        runtimeCloseTimeoutMs: 5,
      },
    );
    await vi.waitFor(() =>
      expect(runtime.ensureSession).toHaveBeenCalledOnce(),
    );

    controller.abort(cancellation);
    await runtimeOptions!.sessionStore.save({
      acpxRecordId: "late-record",
      acpSessionId: "late-backend-session",
      agentSessionId: "late-agent-session",
      name: "late-runtime-name",
      cwd: "/workspace",
    } as never);

    await expect(opening).rejects.toBe(cancellation);
    expect(runtime.close).toHaveBeenCalledTimes(2);
    expect(vi.mocked(runtime.close).mock.calls[1]?.[0]).toEqual(
      vi.mocked(runtime.close).mock.calls[0]?.[0],
    );
    rejectHandshake?.(new Error("test handshake stopped"));
  });

  it("surfaces the retry error when both retained admission closes fail", async () => {
    let rejectHandshake: ((error: Error) => void) | undefined;
    const blockedHandshake = new Promise<AcpRuntimeHandle>(
      (_resolve, reject) => {
        rejectHandshake = reject;
      },
    );
    const runtime = fakeRuntime();
    const firstCloseFailure = new Error("first close failed");
    const retryCloseFailure = new Error("retry close failed");
    vi.mocked(runtime.ensureSession).mockReturnValue(blockedHandshake);
    vi.mocked(runtime.close)
      .mockRejectedValueOnce(firstCloseFailure)
      .mockRejectedValueOnce(retryCloseFailure);
    const controller = new AbortController();
    const cancellation = new Error("runtime admission cancelled");
    let runtimeOptions: AcpRuntimeOptions | undefined;

    const opening = openCodexAcpxRuntime(
      {
        ...openOptions(fakeCommand()),
        signal: controller.signal,
      },
      {
        createRegistry: () => registry(),
        createStore: () => store(),
        createRuntime: (options) => {
          runtimeOptions = options;
          return runtime;
        },
      },
    );
    await vi.waitFor(() =>
      expect(runtime.ensureSession).toHaveBeenCalledOnce(),
    );

    controller.abort(cancellation);
    await runtimeOptions!.sessionStore.save({
      acpxRecordId: "late-record",
      acpSessionId: "late-backend-session",
      agentSessionId: "late-agent-session",
      name: "late-runtime-name",
      cwd: "/workspace",
    } as never);

    await expect(opening).rejects.toMatchObject({
      errors: [cancellation, retryCloseFailure],
    });
    expect(runtime.close).toHaveBeenCalledTimes(2);
    expect(vi.mocked(runtime.close).mock.calls[1]?.[0]).toEqual(
      vi.mocked(runtime.close).mock.calls[0]?.[0],
    );
    rejectHandshake?.(new Error("test handshake stopped"));
  });

  it("aggregates asynchronous provider signal errors after a failed handshake", async () => {
    const child = failingSignalChild();
    const command = fakeCommand();
    vi.mocked(command.spawn).mockReturnValue(child.child);
    const handshakeError = new Error("ACP handshake rejected");
    const runtime = fakeRuntime();

    const result = openCodexAcpxRuntime(openOptions(command), {
      createRegistry: () => registry(),
      createStore: () => store(),
      createRuntime: (options) => {
        vi.mocked(runtime.ensureSession).mockImplementation(async () => {
          options.spawnAgent?.({
            command: "ignored",
            args: ["--stdio"],
            options: {},
          });
          throw handshakeError;
        });
        return runtime;
      },
    });

    await expect(result).rejects.toMatchObject({
      errors: [
        handshakeError,
        ...child.errors,
        expect.objectContaining({
          message: "ACPX provider did not exit after SIGKILL",
        }),
      ],
    });
    expect(child.child.kill).toHaveBeenNthCalledWith(1, "SIGTERM");
    expect(child.child.kill).toHaveBeenNthCalledWith(2, "SIGKILL");
  });

  it("closes a recovered session when its handshake rejects before another save", async () => {
    const runtime = fakeRuntime();
    const recoveredStore = store();
    vi.mocked(recoveredStore.load).mockResolvedValue({
      acpxRecordId: "recovered-record",
      acpSessionId: "recovered-backend-session",
      agentSessionId: "recovered-agent-session",
      name: "recovered-runtime-name",
      cwd: "/workspace",
    } as never);
    const failure = new Error("recovered ACP handshake rejected");

    await expect(
      openCodexAcpxRuntime(openOptions(fakeCommand()), {
        createRegistry: () => registry(),
        createStore: () => recoveredStore,
        createRuntime: (runtimeOptions) => {
          vi.mocked(runtime.ensureSession).mockImplementation(async () => {
            await runtimeOptions.sessionStore.load("provider-key");
            throw failure;
          });
          return runtime;
        },
      }),
    ).rejects.toBe(failure);
    expect(runtime.close).toHaveBeenCalledOnce();
    const recoveredClose = vi.mocked(runtime.close).mock.calls[0]![0];
    expect(recoveredClose).toMatchObject({
      handle: {
        sessionKey: "provider-key",
        backend: "acpx",
        cwd: "/workspace",
        acpxRecordId: "recovered-record",
        backendSessionId: "recovered-backend-session",
        agentSessionId: "recovered-agent-session",
      },
      reason: "ACPX session handshake failed",
      discardPersistentState: false,
    });
    expect(
      decodeAcpxRuntimeHandleState(recoveredClose.handle.runtimeSessionName),
    ).toEqual({
      name: "recovered-runtime-name",
      agent: "codex",
      cwd: "/workspace",
      mode: "persistent",
      acpxRecordId: "recovered-record",
      backendSessionId: "recovered-backend-session",
      agentSessionId: "recovered-agent-session",
    });
    expect(recoveredStore.save).not.toHaveBeenCalled();
  });

  it("closes a newly created session when its record save rejects", async () => {
    const runtime = fakeRuntime();
    const failingStore = store();
    const failure = new Error("session store unavailable");
    vi.mocked(failingStore.save).mockRejectedValue(failure);

    await expect(
      openCodexAcpxRuntime(openOptions(fakeCommand()), {
        createRegistry: () => registry(),
        createStore: () => failingStore,
        createRuntime: (runtimeOptions) => {
          vi.mocked(runtime.ensureSession).mockImplementation(async () => {
            await runtimeOptions.sessionStore.save({
              acpxRecordId: "new-record",
              acpSessionId: "new-backend-session",
              agentSessionId: "new-agent-session",
              name: "new-runtime-name",
              cwd: "/workspace",
            } as never);
            return HANDLE;
          });
          return runtime;
        },
      }),
    ).rejects.toBe(failure);
    expect(runtime.close).toHaveBeenCalledOnce();
    const failedSaveClose = vi.mocked(runtime.close).mock.calls[0]![0];
    expect(failedSaveClose).toMatchObject({
      handle: {
        sessionKey: "provider-key",
        backend: "acpx",
        cwd: "/workspace",
        acpxRecordId: "new-record",
        backendSessionId: "new-backend-session",
        agentSessionId: "new-agent-session",
      },
      reason: "ACPX session handshake failed",
      discardPersistentState: false,
    });
    expect(
      decodeAcpxRuntimeHandleState(failedSaveClose.handle.runtimeSessionName),
    ).toMatchObject({ name: "new-runtime-name", agent: "codex" });
  });

  it("bounds a stalled runtime close before terminating a failed-handshake provider", async () => {
    const child = fakeChild();
    const command = fakeCommand();
    vi.mocked(command.spawn).mockReturnValue(child);
    const runtime = fakeRuntime();
    vi.mocked(runtime.close).mockImplementation(
      () => new Promise<void>(() => undefined),
    );

    await expect(
      openCodexAcpxRuntime(openOptions(command), {
        createRegistry: () => registry(),
        createStore: () => store(),
        createRuntime: (runtimeOptions) => {
          vi.mocked(runtime.ensureSession).mockImplementation(async () => {
            await runtimeOptions.sessionStore.save({
              acpxRecordId: "actual-record",
              acpSessionId: "backend-session",
              agentSessionId: "agent-session",
              name: "actual-runtime-name",
              cwd: "/workspace",
            } as never);
            runtimeOptions.spawnAgent?.({
              command: "ignored",
              args: ["--stdio"],
              options: {},
            });
            throw new Error("ACP handshake rejected");
          });
          return runtime;
        },
        runtimeCloseTimeoutMs: 5,
      }),
    ).rejects.toThrow("ACPX session handshake and runtime cleanup failed");
    expect(runtime.close).toHaveBeenCalledOnce();
    const stalledClose = vi.mocked(runtime.close).mock.calls[0]![0];
    expect(stalledClose).toMatchObject({
      handle: {
        sessionKey: "provider-key",
        backend: "acpx",
        cwd: "/workspace",
        acpxRecordId: "actual-record",
        backendSessionId: "backend-session",
        agentSessionId: "agent-session",
      },
      reason: "ACPX session handshake failed",
      discardPersistentState: false,
    });
    expect(
      decodeAcpxRuntimeHandleState(stalledClose.handle.runtimeSessionName),
    ).toMatchObject({ name: "actual-runtime-name", agent: "codex" });
    expect(child.kill).toHaveBeenCalledWith("SIGTERM");
  });

  it("rejects close with asynchronous provider signal errors", async () => {
    const runtime = fakeRuntime();
    const command = fakeCommand();
    const child = failingSignalChild();
    let runtimeOptions: AcpRuntimeOptions | undefined;
    vi.mocked(command.spawn).mockReturnValue(child.child);
    const port = await openCodexAcpxRuntime(openOptions(command), {
      createRegistry: () => registry(),
      createStore: () => store(),
      createRuntime: (options) => {
        runtimeOptions = options;
        return runtime;
      },
    });
    runtimeOptions?.spawnAgent?.({
      command: "ignored",
      args: ["--stdio"],
      options: {},
    });

    await expect(port.close({ reason: "test complete" })).rejects.toMatchObject(
      {
        errors: [
          ...child.errors,
          expect.objectContaining({
            message: "ACPX provider did not exit after SIGKILL",
          }),
        ],
      },
    );
    expect(child.child.kill).toHaveBeenNthCalledWith(1, "SIGTERM");
    expect(child.child.kill).toHaveBeenNthCalledWith(2, "SIGKILL");
  });

  it("retains a provider error after close removes the child", async () => {
    const runtime = fakeRuntime();
    const command = fakeCommand();
    const child = fakeChild();
    const providerError = new Error("provider spawn failed");
    let runtimeOptions: AcpRuntimeOptions | undefined;
    vi.mocked(command.spawn).mockReturnValue(child);
    const port = await openCodexAcpxRuntime(openOptions(command), {
      createRegistry: () => registry(),
      createStore: () => store(),
      createRuntime: (options) => {
        runtimeOptions = options;
        return runtime;
      },
    });
    runtimeOptions?.spawnAgent?.({
      command: "ignored",
      args: ["--stdio"],
      options: {},
    });

    child.emit("error", providerError);
    child.emit("close", 1, null);

    await expect(port.close({ reason: "test complete" })).rejects.toMatchObject(
      {
        errors: [providerError],
      },
    );
    expect(child.kill).not.toHaveBeenCalled();
  });

  it("rejects non-Codex profiles before constructing ACPX", async () => {
    const createRuntime = vi.fn();
    await expect(
      openCodexAcpxRuntime(
        {
          ...openOptions(fakeCommand()),
          profile: {
            ...openOptions(fakeCommand()).profile,
            agent: "claude",
          },
        },
        { createRuntime },
      ),
    ).rejects.toThrow("currently supports Codex only");
    expect(createRuntime).not.toHaveBeenCalled();
  });
});

function openOptions(
  command: VerifiedAcpxCommandLease,
): AcpxRuntimePortOpenOptions {
  return {
    command,
    profile: {
      driverKind: "acpx_runtime",
      protocolVersion: 1,
      acpxVersion: "0.13.1",
      agent: "codex",
      agentProfileVersion: 1,
      agentServerPackage: "@agentclientprotocol/codex-acp",
      agentServerVersion: "1.6.2",
      agentRuntimePackage: null,
      agentRuntimeVersion: null,
      commandDigest: "sha256:test",
      qualificationModel: "gpt-5.6-sol",
      reportedModelId: "gpt-5.6-sol",
      permissionPolicy: "interactive",
    },
    cwd: "/workspace",
    stateDirectory: "/runtime/state",
    providerSessionKey: "provider-key",
    permissionMode: "approve-reads",
    permissionPolicy: {
      autoApprove: ["read"],
      escalate: ["write"],
      defaultAction: "escalate",
    },
    launchEnvironment: {
      CODEX_HOME: "/runtime/agent-home",
      OPENAI_API_KEY: "credential-secret",
      OMITTED: undefined,
    },
    systemInstructions: "Use Paperclip tools.",
    mcpServers: [],
  };
}

function fakeRuntime(handle: AcpRuntimeHandle = HANDLE): AcpRuntime {
  return {
    ensureSession: vi.fn().mockResolvedValue(handle),
    startTurn: vi.fn(),
    runTurn: vi.fn(),
    getStatus: vi.fn(),
    setConfigOption: vi.fn(),
    cancel: vi.fn(),
    close: vi.fn(),
  };
}

function fakeCommand(): VerifiedAcpxCommandLease {
  return { spawn: vi.fn(), close: vi.fn() };
}

function fakeChild(): ChildProcess {
  const child = new EventEmitter() as ChildProcess;
  Object.defineProperties(child, {
    exitCode: { value: null, writable: true },
    signalCode: { value: null, writable: true },
  });
  child.kill = vi.fn(() => {
    child.signalCode = "SIGTERM";
    queueMicrotask(() => child.emit("exit", null, "SIGTERM"));
    return true;
  });
  return child;
}

function failingSignalChild(): {
  child: ChildProcess;
  errors: [Error, Error];
} {
  const child = new EventEmitter() as ChildProcess;
  const errors: [Error, Error] = [
    new Error("SIGTERM delivery failed"),
    new Error("SIGKILL delivery failed"),
  ];
  Object.defineProperties(child, {
    exitCode: { value: null, writable: true },
    signalCode: { value: null, writable: true },
  });
  child.kill = vi.fn((signal) => {
    const error = signal === "SIGTERM" ? errors[0] : errors[1];
    queueMicrotask(() => child.emit("error", error));
    return true;
  });
  return { child, errors };
}

function registry(): AcpAgentRegistry {
  return { resolve: vi.fn(), list: vi.fn() };
}

function store(): AcpSessionStore {
  return { load: vi.fn(), save: vi.fn() };
}

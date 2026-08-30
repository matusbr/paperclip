import { createHash } from "node:crypto";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, parse } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { resolveQualifiedAcpxProfile } from "./qualified-profiles.js";
import {
  ACPX_IDENTITY_RECORD_SCHEMA,
  createAcpxIdentityRecord,
  createAcpxRecoveryBinding,
  verifyExpectedAcpxIdentity,
} from "./recovery-identity.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("ACPX recovery identity", () => {
  it("binds the canonical workspace, profile, model, policy, and session", async () => {
    const fixture = await recoveryFixture();
    expect(fixture.binding.runtimeRoot).toContain("session-1-");
    expect(fixture.binding.workspaceDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(fixture.binding.profileSessionKey).toMatch(
      /^paperclip-[0-9a-f]{64}$/,
    );
    expect(fixture.binding.workspacePath).toBe(
      await realpath(fixture.workspace),
    );

    const record = createAcpxIdentityRecord(fixture.expected, fixture.binding);
    expect(record).toMatchObject({
      schema: ACPX_IDENTITY_RECORD_SCHEMA,
      normalizedSessionId: "session-1",
      permissionMode: "approve-reads",
    });
    expect(() =>
      verifyExpectedAcpxIdentity(fixture.expected, fixture.binding, record),
    ).not.toThrow();
  });

  it("uses collision-resistant roots and policy-bound provider keys", async () => {
    const fixture = await recoveryFixture();
    const otherSession = await createAcpxRecoveryBinding({
      ...fixture.input,
      normalizedSessionId: "session/1",
    });
    const otherPolicy = await createAcpxRecoveryBinding({
      ...fixture.input,
      permissionMode: "deny-all",
    });
    const otherRuntimePackage = await createAcpxRecoveryBinding({
      ...fixture.input,
      profile: {
        ...fixture.input.profile,
        agentRuntimePackage: "@paperclip/test-runtime",
      },
    });
    const otherRuntimeVersion = await createAcpxRecoveryBinding({
      ...fixture.input,
      profile: {
        ...fixture.input.profile,
        agentRuntimeVersion: "99.0.0",
      },
    });

    expect(otherSession.runtimeRoot).not.toBe(fixture.binding.runtimeRoot);
    expect(otherPolicy.profileSessionKey).not.toBe(
      fixture.binding.profileSessionKey,
    );
    expect(otherRuntimePackage.profileDigest).not.toBe(
      fixture.binding.profileDigest,
    );
    expect(otherRuntimePackage.profileSessionKey).not.toBe(
      fixture.binding.profileSessionKey,
    );
    expect(otherRuntimeVersion.profileDigest).not.toBe(
      fixture.binding.profileDigest,
    );
    expect(otherRuntimeVersion.profileSessionKey).not.toBe(
      fixture.binding.profileSessionKey,
    );
  });

  it("rejects immutable workspace, profile, model, and policy drift", async () => {
    const fixture = await recoveryFixture();
    for (const changed of [
      { ...fixture.expected, workspaceDigest: digest("different") },
      { ...fixture.expected, profileDigest: digest("different") },
      { ...fixture.expected, requestedModel: "other" },
      { ...fixture.expected, permissionMode: "deny-all" as const },
    ]) {
      expect(() =>
        verifyExpectedAcpxIdentity(changed, fixture.binding, null),
      ).toThrow(/immutable session configuration/);
    }
  });

  it("reads a legacy record only under its historical policy default", async () => {
    const fixture = await recoveryFixture();
    const legacyExpected = { ...fixture.expected, permissionMode: undefined };
    const legacy = {
      acpxRecordId: fixture.expected.acpxRecordId,
      backendSessionId: fixture.expected.backendSessionId,
      agentSessionId: fixture.expected.agentSessionId,
      requestedModel: fixture.expected.requestedModel,
      effectiveModel: fixture.expected.effectiveModel,
      profileDigest: fixture.input.profile.commandDigest,
    };
    expect(() =>
      verifyExpectedAcpxIdentity(legacyExpected, fixture.binding, legacy),
    ).not.toThrow();
    expect(() =>
      verifyExpectedAcpxIdentity({
        ...legacyExpected,
        profileDigest: fixture.binding.legacyProfileDigest,
      }, fixture.binding, legacy),
    ).not.toThrow();

    expect(() =>
      verifyExpectedAcpxIdentity(legacyExpected, fixture.binding, {
        ...legacy,
        profileDigest: fixture.binding.profileDigest,
      }),
    ).toThrow(/persisted runtime record/);

    expect(() =>
      verifyExpectedAcpxIdentity(legacyExpected, fixture.binding, {
        ...legacy,
        permissionMode: null,
      }),
    ).toThrow(/historical approve-reads policy/);

    const permissive = {
      ...fixture.binding,
      permissionMode: "approve-all" as const,
    };
    expect(() =>
      verifyExpectedAcpxIdentity(legacyExpected, permissive, legacy),
    ).toThrow(/immutable session configuration/);

    expect(() =>
      verifyExpectedAcpxIdentity(
        { ...fixture.expected, permissionMode: "approve-all" },
        permissive,
        { ...legacy, permissionMode: "approve-all" },
      ),
    ).toThrow(/historical approve-reads policy/);

    const restrictive = {
      ...fixture.binding,
      permissionMode: "deny-all" as const,
    };
    expect(() =>
      verifyExpectedAcpxIdentity(
        { ...fixture.expected, permissionMode: "deny-all" },
        restrictive,
        { ...legacy, permissionMode: "deny-all" },
      ),
    ).toThrow(/historical approve-reads policy/);
  });

  it("rejects early v1 command digests across qualified-profile drift", async () => {
    const fixture = await recoveryFixture();
    const earlyV1 = {
      ...createAcpxIdentityRecord(fixture.expected, fixture.binding),
      profileDigest: fixture.binding.legacyProfileDigest,
    };

    expect(() =>
      verifyExpectedAcpxIdentity(fixture.expected, fixture.binding, earlyV1),
    ).toThrow(/persisted runtime record/);
    expect(() =>
      verifyExpectedAcpxIdentity(
        {
          ...fixture.expected,
          profileDigest: fixture.binding.legacyProfileDigest,
        },
        fixture.binding,
        earlyV1,
      ),
    ).toThrow(/immutable session configuration/);

    const changedBinding = await createAcpxRecoveryBinding({
      ...fixture.input,
      profile: {
        ...fixture.input.profile,
        agentRuntimeVersion: "99.0.0",
      },
    });
    expect(changedBinding.legacyProfileDigest).toBe(
      fixture.binding.legacyProfileDigest,
    );
    expect(changedBinding.profileDigest).not.toBe(
      fixture.binding.profileDigest,
    );
    expect(() =>
      verifyExpectedAcpxIdentity(
        {
          ...fixture.expected,
          profileDigest: changedBinding.profileDigest,
        },
        changedBinding,
        earlyV1,
      ),
    ).toThrow(/persisted runtime record/);
  });

  it("rejects malformed records and unsafe workspace roots", async () => {
    const fixture = await recoveryFixture();
    expect(() =>
      verifyExpectedAcpxIdentity(fixture.expected, fixture.binding, {
        ...createAcpxIdentityRecord(fixture.expected, fixture.binding),
        unexpected: true,
      }),
    ).toThrow(/unknown field/);

    await expect(
      createAcpxRecoveryBinding({
        ...fixture.input,
        workingDirectory: parse(fixture.workspace).root,
      }),
    ).rejects.toThrow(/non-root directory/);
    const file = join(fixture.root, "file");
    await writeFile(file, "not a directory");
    await expect(
      createAcpxRecoveryBinding({
        ...fixture.input,
        workingDirectory: file,
      }),
    ).rejects.toThrow(/non-root directory/);
  });
});

async function recoveryFixture() {
  const root = await mkdtemp(join(tmpdir(), "paperclip-acpx-recovery-"));
  temporaryDirectories.push(root);
  const workspace = join(root, "workspace");
  const runtimeDirectory = join(root, "runtime");
  await Promise.all([mkdir(workspace), mkdir(runtimeDirectory)]);
  const profile = resolveQualifiedAcpxProfile("claude", "claude-sonnet-5");
  const input = {
    runtimeDirectory,
    normalizedSessionId: "session-1",
    workingDirectory: workspace,
    profile,
    requestedModel: "claude-sonnet-5",
    permissionMode: "approve-reads" as const,
  };
  const binding = await createAcpxRecoveryBinding(input);
  const expected = {
    kind: "acpx" as const,
    normalizedSessionId: input.normalizedSessionId,
    acpxRecordId: "record-1",
    backendSessionId: "backend-1",
    agentSessionId: "agent-1",
    profileDigest: binding.profileDigest,
    workspaceDigest: binding.workspaceDigest,
    requestedModel: binding.requestedModel,
    effectiveModel: binding.effectiveModel,
    permissionMode: binding.permissionMode,
  };
  return { root, workspace, input, binding, expected };
}

function digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

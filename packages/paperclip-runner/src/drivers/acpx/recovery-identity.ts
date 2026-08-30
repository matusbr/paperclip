import { createHash } from "node:crypto";
import { realpath, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

import type { NativeAcpxPermissionMode } from "../../contracts/native-execution.js";
import type { AcpxExpectedSessionIdentity } from "./sidecar-protocol.js";
import type { QualifiedAcpxProfile } from "./qualified-profiles.js";

export const ACPX_IDENTITY_RECORD_SCHEMA =
  "paperclip.runner.acpx-identity.v1" as const;

export interface AcpxRecoveryBinding {
  normalizedSessionId: string;
  workspacePath: string;
  workspaceDigest: string;
  runtimeRoot: string;
  profileDigest: string;
  legacyProfileDigest: string;
  requestedModel: string;
  effectiveModel: string;
  permissionMode: NativeAcpxPermissionMode;
  profileSessionKey: string;
}

export interface AcpxIdentityRecord {
  schema: typeof ACPX_IDENTITY_RECORD_SCHEMA;
  normalizedSessionId: string;
  acpxRecordId: string;
  backendSessionId: string;
  agentSessionId: string;
  profileDigest: string;
  workspaceDigest: string;
  requestedModel: string;
  effectiveModel: string;
  permissionMode: NativeAcpxPermissionMode;
}

export async function createAcpxRecoveryBinding(input: {
  runtimeDirectory: string;
  normalizedSessionId: string;
  workingDirectory: string;
  profile: QualifiedAcpxProfile;
  requestedModel: string;
  permissionMode: NativeAcpxPermissionMode;
}): Promise<AcpxRecoveryBinding> {
  validateIdentity(input.normalizedSessionId, "normalized session");
  if (input.requestedModel !== input.profile.qualificationModel) {
    throw new Error("ACPX recovery requested an unqualified model");
  }
  if (!isDigest(input.profile.commandDigest)) {
    throw new Error("ACPX recovery profile command digest is invalid");
  }
  const workspacePath = await resolveWorkspace(input.workingDirectory);
  const workspaceDigest = digest(workspacePath);
  const runtimeRoot = await acpxRuntimeRoot(
    input.runtimeDirectory,
    input.normalizedSessionId,
  );
  const profileDigest = digest(
    canonicalJson({
      driverKind: input.profile.driverKind,
      protocolVersion: input.profile.protocolVersion,
      acpxVersion: input.profile.acpxVersion,
      agent: input.profile.agent,
      agentProfileVersion: input.profile.agentProfileVersion,
      agentServerPackage: input.profile.agentServerPackage,
      agentServerVersion: input.profile.agentServerVersion,
      agentRuntimePackage: input.profile.agentRuntimePackage,
      agentRuntimeVersion: input.profile.agentRuntimeVersion,
      commandDigest: input.profile.commandDigest,
      qualificationModel: input.profile.qualificationModel,
      reportedModelId: input.profile.reportedModelId,
      permissionPolicy: input.profile.permissionPolicy,
    }),
  );
  const profileSessionKey = digest(
    canonicalJson({
      normalizedSessionId: input.normalizedSessionId,
      workspacePath,
      workspaceDigest,
      requestedModel: input.requestedModel,
      profileDigest,
      permissionMode: input.permissionMode,
    }),
  ).replace("sha256:", "paperclip-");
  return {
    normalizedSessionId: input.normalizedSessionId,
    workspacePath,
    workspaceDigest,
    runtimeRoot,
    profileDigest,
    legacyProfileDigest: input.profile.commandDigest,
    requestedModel: input.requestedModel,
    effectiveModel: input.requestedModel,
    permissionMode: input.permissionMode,
    profileSessionKey,
  };
}

export function createAcpxIdentityRecord(
  expected: AcpxExpectedSessionIdentity,
  binding: AcpxRecoveryBinding,
): AcpxIdentityRecord {
  verifyExpectedAcpxIdentity(expected, binding, null);
  return {
    schema: ACPX_IDENTITY_RECORD_SCHEMA,
    normalizedSessionId: binding.normalizedSessionId,
    acpxRecordId: expected.acpxRecordId,
    backendSessionId: expected.backendSessionId,
    agentSessionId: expected.agentSessionId,
    profileDigest: binding.profileDigest,
    workspaceDigest: binding.workspaceDigest,
    requestedModel: binding.requestedModel,
    effectiveModel: binding.effectiveModel,
    permissionMode: binding.permissionMode,
  };
}

/**
 * Verify both the controller-provided identity and a persisted runtime record.
 * A legacy record remains readable only under its historical approve-reads
 * default; fresh records always use the versioned schema.
 */
export function verifyExpectedAcpxIdentity(
  expected: AcpxExpectedSessionIdentity,
  binding: AcpxRecoveryBinding,
  persisted: unknown,
): void {
  validateExpected(expected);
  const parsed = persisted === null
    ? null
    : parsePersistedRecord(persisted, binding);
  const expectedPermissionMode = expected.permissionMode ?? "approve-reads";
  const acceptedControllerProfileDigests = parsed?.schemaLessLegacy
    ? [binding.profileDigest, binding.legacyProfileDigest]
    : [binding.profileDigest];
  if (
    expected.normalizedSessionId !== binding.normalizedSessionId ||
    !acceptedControllerProfileDigests.includes(expected.profileDigest) ||
    expected.workspaceDigest !== binding.workspaceDigest ||
    expected.requestedModel !== binding.requestedModel ||
    expected.effectiveModel !== binding.effectiveModel ||
    expectedPermissionMode !== binding.permissionMode
  ) {
    throw new Error(
      "ACPX recovery identity conflicts with the immutable session configuration",
    );
  }
  if (persisted === null) return;

  const persistedRecord = parsed!;
  const { record } = persistedRecord;
  const persistedProfileDigest = persistedRecord.schemaLessLegacy
    ? binding.legacyProfileDigest
    : binding.profileDigest;
  if (
    record.acpxRecordId !== expected.acpxRecordId ||
    record.backendSessionId !== expected.backendSessionId ||
    record.agentSessionId !== expected.agentSessionId ||
    record.normalizedSessionId !== binding.normalizedSessionId ||
    record.profileDigest !== persistedProfileDigest ||
    record.workspaceDigest !== binding.workspaceDigest ||
    record.requestedModel !== binding.requestedModel ||
    record.effectiveModel !== binding.effectiveModel ||
    record.permissionMode !== binding.permissionMode
  ) {
    throw new Error(
      "ACPX recovery identity does not match the persisted runtime record",
    );
  }
}

function parsePersistedRecord(
  value: unknown,
  binding: AcpxRecoveryBinding,
): { record: AcpxIdentityRecord; schemaLessLegacy: boolean } {
  const record = object(value);
  if (record.schema === undefined) {
    rejectUnknownKeys(record, [
      "acpxRecordId",
      "backendSessionId",
      "agentSessionId",
      "requestedModel",
      "effectiveModel",
      "permissionMode",
      "profileDigest",
    ]);
    const legacyPermissionMode =
      record.permissionMode === undefined
        ? "approve-reads"
        : record.permissionMode;
    if (legacyPermissionMode !== "approve-reads") {
      throw new Error(
        "Legacy ACPX identity records must use the historical approve-reads policy",
      );
    }
    return {
      record: validatedRecord({
        ...record,
        schema: ACPX_IDENTITY_RECORD_SCHEMA,
        normalizedSessionId: binding.normalizedSessionId,
        workspaceDigest: binding.workspaceDigest,
        permissionMode: legacyPermissionMode,
      }),
      schemaLessLegacy: true,
    };
  }
  rejectUnknownKeys(record, [
    "schema",
    "normalizedSessionId",
    "acpxRecordId",
    "backendSessionId",
    "agentSessionId",
    "profileDigest",
    "workspaceDigest",
    "requestedModel",
    "effectiveModel",
    "permissionMode",
  ]);
  const validated = validatedRecord(record);
  return {
    record: validated,
    // A schema-bearing v1 record must prove the complete qualified-profile
    // binding. A command digest cannot distinguish an early writer from
    // immutable metadata drift, so it is never a safe downgrade signal.
    schemaLessLegacy: false,
  };
}

function validatedRecord(value: Record<string, unknown>): AcpxIdentityRecord {
  if (value.schema !== ACPX_IDENTITY_RECORD_SCHEMA) {
    throw new Error("Unsupported ACPX identity record schema");
  }
  for (const field of [
    "normalizedSessionId",
    "acpxRecordId",
    "backendSessionId",
    "agentSessionId",
    "requestedModel",
    "effectiveModel",
  ] as const) {
    validateIdentity(value[field], field);
  }
  for (const field of ["profileDigest", "workspaceDigest"] as const) {
    if (!isDigest(value[field]))
      throw new Error(`ACPX identity ${field} is invalid`);
  }
  if (!isPermissionMode(value.permissionMode)) {
    throw new Error("ACPX identity permission mode is invalid");
  }
  return value as unknown as AcpxIdentityRecord;
}

function validateExpected(expected: AcpxExpectedSessionIdentity): void {
  if (expected.kind !== "acpx") throw new Error("Expected ACPX identity kind");
  for (const value of [
    expected.normalizedSessionId,
    expected.acpxRecordId,
    expected.backendSessionId,
    expected.agentSessionId,
    expected.requestedModel,
    expected.effectiveModel,
  ]) {
    validateIdentity(value, "expected ACPX");
  }
  if (
    !isDigest(expected.profileDigest) ||
    !isDigest(expected.workspaceDigest)
  ) {
    throw new Error("Expected ACPX identity digest is invalid");
  }
  if (
    expected.permissionMode !== undefined &&
    !isPermissionMode(expected.permissionMode)
  ) {
    throw new Error("Expected ACPX permission mode is invalid");
  }
}

async function resolveWorkspace(value: string): Promise<string> {
  if (!value.trim()) throw new Error("ACPX working directory is required");
  const workspacePath = await realpath(value);
  const metadata = await stat(workspacePath);
  if (!metadata.isDirectory() || workspacePath === dirname(workspacePath)) {
    throw new Error("ACPX working directory must be a non-root directory");
  }
  return workspacePath;
}

async function acpxRuntimeRoot(
  runtimeDirectory: string,
  sessionId: string,
): Promise<string> {
  if (!runtimeDirectory.trim())
    throw new Error("ACPX runtime directory is required");
  const root = await realpath(runtimeDirectory);
  const metadata = await stat(root);
  if (!metadata.isDirectory())
    throw new Error("ACPX runtime directory must be a directory");
  if (root === dirname(root))
    throw new Error("ACPX runtime directory must not be a filesystem root");
  const readable = sessionId
    .replace(/[^a-zA-Z0-9._-]/g, "_")
    .replace(/^\.+$/, "session")
    .slice(0, 80);
  const suffix = createHash("sha256")
    .update(sessionId)
    .digest("hex")
    .slice(0, 16);
  return join(resolve(root), "acpx", `${readable || "session"}-${suffix}`);
}

function validateIdentity(
  value: unknown,
  label: string,
): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 240 ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error(`${label} identity is missing or invalid`);
  }
}

function isDigest(value: unknown): value is string {
  return typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
}

function isPermissionMode(value: unknown): value is NativeAcpxPermissionMode {
  return (
    typeof value === "string" &&
    ["approve-all", "approve-reads", "deny-all"].includes(value)
  );
}

function rejectUnknownKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
): void {
  const names = new Set(allowed);
  if (Object.keys(value).some((key) => !names.has(key))) {
    throw new Error("ACPX identity record contains an unknown field");
  }
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("ACPX identity record must be an object");
  }
  return value as Record<string, unknown>;
}

function digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function canonicalJson(value: Record<string, unknown>): string {
  return JSON.stringify(
    Object.fromEntries(
      Object.entries(value).sort(([left], [right]) =>
        left < right ? -1 : left > right ? 1 : 0,
      ),
    ),
  );
}

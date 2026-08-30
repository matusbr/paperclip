import { describe, expect, it } from "vitest";
import { REDACTED_COMMAND_TEXT_VALUE, redactCommandText, redactDiagnosticText } from "./command-redaction.js";

describe("redactDiagnosticText", () => {
  it("redacts a JSON secret field value", () => {
    const input = '{"token":"opaque-value","status":"error"}';
    const output = redactDiagnosticText(input);
    expect(output).not.toContain("opaque-value");
    expect(output).toContain(`"token":"${REDACTED_COMMAND_TEXT_VALUE}"`);
    // The non-secret field keeps its value.
    expect(output).toContain('"status":"error"');
  });

  it("redacts an api_key JSON field with whitespace around the colon", () => {
    const input = '{ "api_key" : "sk-secret-123" }';
    const output = redactDiagnosticText(input);
    expect(output).not.toContain("sk-secret-123");
    expect(output).toContain(REDACTED_COMMAND_TEXT_VALUE);
  });

  it("redacts an escaped-JSON secret field value", () => {
    // A diagnostic can carry a JSON string, so the double quotes appear as `\"`.
    const input = '{\\"token\\":\\"opaque-value\\"}';
    const output = redactDiagnosticText(input);
    expect(output).not.toContain("opaque-value");
    expect(output).toContain(`\\"token\\":\\"${REDACTED_COMMAND_TEXT_VALUE}\\"`);
  });

  it("still redacts a shell KEY=value secret", () => {
    const input = "ANTHROPIC_API_KEY=super-secret-value claude --print";
    const output = redactDiagnosticText(input);
    expect(output).not.toContain("super-secret-value");
    expect(output).toContain(REDACTED_COMMAND_TEXT_VALUE);
  });

  it("keeps non-secret text and non-secret JSON fields intact", () => {
    const input = '{"status":"ok","message":"probe finished"}';
    expect(redactDiagnosticText(input)).toBe(input);
  });

  it("redacts the secret but keeps a non-secret marker in the same string", () => {
    const input = 'DIAGMARKER1234 said {"authorization":"Bearer opaque"}';
    const output = redactDiagnosticText(input);
    expect(output).toContain("DIAGMARKER1234");
    expect(output).not.toContain("opaque");
  });

  it("redacts a JSON secret value that contains an escaped quote", () => {
    // The value holds an escaped quote, so a naive matcher stops at the `\"` and
    // leaves the rest of the credential. The marker sits after the escaped quote.
    const input = '{"token":"pre\\"MARKERQUOTE_A"}';
    const output = redactDiagnosticText(input);
    expect(output).not.toContain("MARKERQUOTE_A");
    expect(output).toContain(`"token":"${REDACTED_COMMAND_TEXT_VALUE}"`);
  });

  it("redacts a JSON secret value that contains an escaped backslash", () => {
    const input = '{"secret":"pre\\\\MARKERBACKSLASH_A"}';
    const output = redactDiagnosticText(input);
    expect(output).not.toContain("MARKERBACKSLASH_A");
    expect(output).toContain(`"secret":"${REDACTED_COMMAND_TEXT_VALUE}"`);
  });

  it("redacts an escaped-JSON secret value that contains an escaped quote", () => {
    // A diagnostic can carry a serialized JSON string, so the whole JSON is
    // escaped a second time. The inner value still holds an escaped quote.
    const innerJson = '{"token":"pre\\"MARKERQUOTE_B"}';
    const input = JSON.stringify(innerJson);
    const output = redactDiagnosticText(input);
    expect(output).not.toContain("MARKERQUOTE_B");
    expect(output).toContain(REDACTED_COMMAND_TEXT_VALUE);
  });

  it("redacts an escaped-JSON secret value that contains an escaped backslash", () => {
    const innerJson = '{"password":"pre\\\\MARKERBACKSLASH_B"}';
    const input = JSON.stringify(innerJson);
    const output = redactDiagnosticText(input);
    expect(output).not.toContain("MARKERBACKSLASH_B");
    expect(output).toContain(REDACTED_COMMAND_TEXT_VALUE);
  });
});

describe("redactCommandText", () => {
  it("keeps a JSON-serialized command with an Authorization Bearer header parseable", () => {
    // A sandboxed tool call is often logged as JSON.stringify({command}). The
    // literal quotes around the header value are then escaped (`\"`), and the
    // old negated character class did not exclude the backslash, so it
    // consumed the escape and left the JSON truncated.
    const raw = 'curl -s -H "Authorization: Bearer opaque-value-123" "http://internal/health"';
    const input = JSON.stringify({ command: raw });
    const output = redactCommandText(input);
    expect(output).not.toContain("opaque-value-123");
    expect(() => JSON.parse(output)).not.toThrow();
    expect(JSON.parse(output).command).toContain(`Bearer ${REDACTED_COMMAND_TEXT_VALUE}`);
  });

  it("keeps the closing quote after redacting an unserialized Bearer header", () => {
    // The common, non-JSON shape: the value is followed by a real closing
    // quote. A fix that touches the string end would break this case.
    const input = 'curl -H "Authorization: Bearer opaque-value-123"';
    const output = redactCommandText(input);
    expect(output).not.toContain("opaque-value-123");
    expect(output).toBe(`curl -H "Authorization: Bearer ${REDACTED_COMMAND_TEXT_VALUE}"`);
  });

  it("keeps a JSON-serialized command with a shell-quoted CLI secret option value parseable", () => {
    // Known gap: the value stays visible (matches neither the quoted branch,
    // since its delimiter is now `\"` not `"`, nor is it redacted by the
    // unquoted branch's first character). JSON validity is what this fix
    // guarantees, not redaction of this specific shape.
    const raw = 'mycli --api-key="opaque-value-123" --verbose';
    const input = JSON.stringify({ command: raw });
    const output = redactCommandText(input);
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it("keeps a JSON-serialized command with a shell-quoted env assignment value parseable", () => {
    // Same known gap as above, for KEY=\"value\".
    const raw = 'ANTHROPIC_API_KEY="opaque-value-123" claude --print';
    const input = JSON.stringify({ command: raw });
    const output = redactCommandText(input);
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it("does not leave a credential suffix visible after a literal backslash (Bearer)", () => {
    // greptile-apps P1 on PR #12530: an earlier version of this fix excluded
    // every backslash from the value, which stops a JSON `\"` escape from
    // being consumed but also truncates a real secret that itself contains a
    // literal backslash (e.g. a Windows-style credential). The value class
    // now allows a backslash unless it is immediately followed by a quote
    // character (the lookahead `\\(?!["'])`), matching the same technique
    // used for the equivalent server-side fix in PR #9999.
    const input = String.raw`curl -H "Authorization: Bearer abc\def"`;
    const output = redactCommandText(input);
    expect(output).not.toContain("def");
    expect(output).toBe(`curl -H "Authorization: Bearer ${REDACTED_COMMAND_TEXT_VALUE}"`);
  });

  it("does not leave a credential suffix visible after a literal backslash (env assignment)", () => {
    // The realistic carrier for this shape is not a bearer token but a
    // Windows-style domain credential, e.g. PASSWORD=DOMAIN\user.
    const input = String.raw`PASSWORD=DOMAIN\admin next-cmd`;
    const output = redactCommandText(input);
    expect(output).not.toContain("admin");
    expect(output).toBe(`PASSWORD=${REDACTED_COMMAND_TEXT_VALUE} next-cmd`);
  });

  it("does not leave a credential suffix visible after a literal backslash (CLI option)", () => {
    const input = String.raw`mycli --api-key=abc\def --verbose`;
    const output = redactCommandText(input);
    expect(output).not.toContain("def");
    expect(output).toBe(`mycli --api-key=${REDACTED_COMMAND_TEXT_VALUE} --verbose`);
  });

  it("still keeps the JSON-serialized Bearer case parseable when the value also has a literal backslash before the closing escaped quote", () => {
    // Both failure modes at once: a value containing a literal backslash,
    // serialized so the backslash sits right before the JSON escape of the
    // closing quote. Must redact fully AND stay parseable.
    const raw = String.raw`curl -H "Authorization: Bearer abc\def"`;
    const input = JSON.stringify({ command: raw });
    const output = redactCommandText(input);
    expect(output).not.toContain("def");
    expect(() => JSON.parse(output)).not.toThrow();
    expect(JSON.parse(output).command).toBe(`curl -H "Authorization: Bearer ${REDACTED_COMMAND_TEXT_VALUE}"`);
  });

  it("redacts an unquoted env value containing a Windows-style path with literal backslashes", () => {
    const input = String.raw`env TOKEN=C:\private\credential next`;
    const output = redactCommandText(input);
    expect(output).not.toContain("private");
    expect(output).not.toContain("credential");
    expect(output).toBe(`env TOKEN=${REDACTED_COMMAND_TEXT_VALUE} next`);
  });

  it("redacts a quoted env value containing a Windows-style path with literal backslashes", () => {
    const input = String.raw`TOKEN="C:\private\credential" safe`;
    const output = redactCommandText(input);
    expect(output).not.toContain("private");
    expect(output).toBe(`TOKEN="${REDACTED_COMMAND_TEXT_VALUE}" safe`);
  });
});

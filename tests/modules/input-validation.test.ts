import { describe, expect, it } from "vitest";
import {
  formatToolInputValidationError,
  MAX_TOOL_INPUT_BYTES,
  normalizeToolInputKeys,
  validateToolInput,
} from "../../src/modules/input-validation.js";

const schema = {
  type: "object",
  properties: {
    target: { type: "string", minLength: 1 },
    verify: { type: "boolean" },
    severity: {
      type: "array",
      items: { type: "string", enum: ["critical", "high"] },
      minItems: 1,
    },
    limits: {
      type: "object",
      properties: { count: { type: "integer", minimum: 1, maximum: 100 } },
      required: ["count"],
    },
  },
  required: ["target"],
};

describe("validateToolInput", () => {
  it("accepts valid object payloads", () => {
    const result = validateToolInput(
      { target: "./repo", verify: true, severity: ["critical"], limits: { count: 3 } },
      schema,
    );

    expect(result.ok).toBe(true);
  });

  it("rejects missing required fields and wrong primitive types", () => {
    const result = validateToolInput({ target: 42, verify: "yes" }, schema);

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual(
      expect.arrayContaining([
        { path: "target", message: "expected string, got integer" },
        { path: "verify", message: "expected boolean, got string" },
      ]),
    );
  });

  it("rejects unexpected and reserved object keys by default", () => {
    const payload: Record<string, unknown> = { target: "./repo", extra: true };
    Object.defineProperty(payload, "__proto__", { value: { polluted: true }, enumerable: true });
    const result = validateToolInput(payload, schema);

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual(
      expect.arrayContaining([
        { path: "extra", message: "unknown property" },
        { path: "__proto__", message: "reserved object key is not allowed" },
      ]),
    );
  });

  it("validates nested arrays and objects", () => {
    const result = validateToolInput(
      { target: "./repo", severity: ["medium"], limits: { count: 0 } },
      schema,
    );

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual(
      expect.arrayContaining([
        { path: "severity[0]", message: "must be one of critical|high" },
        { path: "limits.count", message: "must be >= 1" },
      ]),
    );
  });

  it("allows unknown keys only when the schema explicitly opts in", () => {
    const result = validateToolInput(
      { known: "x", dynamic: 3 },
      {
        type: "object",
        properties: { known: { type: "string" } },
        additionalProperties: true,
      },
    );

    expect(result.ok).toBe(true);
  });

  it("rejects oversized payloads before schema walking", () => {
    const result = validateToolInput(
      { target: "x".repeat(MAX_TOOL_INPUT_BYTES + 1) },
      { type: "object", properties: { target: { type: "string" } } },
    );

    expect(result.ok).toBe(false);
    expect(result.issues[0]?.message).toContain("payload exceeds");
  });

  it("formats validation failures for tool responses", () => {
    expect(
      formatToolInputValidationError("demo:run", [{ path: "target", message: "is required" }]),
    ).toBe('Invalid input for tool "demo:run":\n  - target: is required');
  });
});

describe("normalizeToolInputKeys", () => {
  it("canonicalizes object keys case-insensitively against schema properties", () => {
    expect(normalizeToolInputKeys({ TARGET: "./repo", VERIFY: true }, schema)).toEqual({
      target: "./repo",
      verify: true,
    });
  });

  it("prefers exact schema keys when an alias duplicate is present", () => {
    expect(normalizeToolInputKeys({ target: "./repo", TARGET: "./other" }, schema)).toEqual({
      target: "./repo",
    });
  });

  it("canonicalizes nested object keys and leaves unknown keys for validation", () => {
    const normalized = normalizeToolInputKeys(
      { TARGET: "./repo", limits: { COUNT: 3 }, EXTRA: true },
      schema,
    );

    expect(normalized).toEqual({
      target: "./repo",
      limits: { count: 3 },
      EXTRA: true,
    });
    const result = validateToolInput(normalized, schema);
    expect(result.ok).toBe(false);
    expect(result.issues).toContainEqual({ path: "EXTRA", message: "unknown property" });
  });

  it("does not guess when schema property casing is ambiguous", () => {
    const ambiguousSchema = {
      type: "object",
      properties: {
        target: { type: "string" },
        TARGET: { type: "string" },
      },
    };

    expect(normalizeToolInputKeys({ Target: "./repo" }, ambiguousSchema)).toEqual({
      Target: "./repo",
    });
  });
});

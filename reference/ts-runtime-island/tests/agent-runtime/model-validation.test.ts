import { describe, expect, it } from "vitest";
import {
  assertRuntimeModelCompatible,
  assertRuntimeModelSelection,
  validateModelOverride,
} from "../../src/agent-runtime/model-validation.js";

describe("validateModelOverride", () => {
  it("requires provider:model and accepts unknown providers", () => {
    expect(validateModelOverride("anthropic:claude-opus-4-6")).toBeNull();
    expect(validateModelOverride("custom:local-model")).toBeNull();
  });

  it("rejects bare model ids without a provider prefix", () => {
    expect(validateModelOverride("claude-opus-4-6")).toContain("Expected format");
  });

  it("rejects an empty string", () => {
    expect(validateModelOverride("")).toContain("non-empty");
  });

  it("assertRuntimeModelCompatible throws on bare ids", () => {
    expect(() => assertRuntimeModelCompatible("claude-opus-4-6")).toThrow(
      /will not silently switch/u,
    );
  });

  it("rejects fallbackModel unless the operator explicitly chooses a primary model", () => {
    expect(() =>
      assertRuntimeModelSelection("anthropic:claude-sonnet-4-6", "anthropic:claude-haiku-4-5"),
    ).toThrow(/Automatic model fallback is disabled/u);
  });
});

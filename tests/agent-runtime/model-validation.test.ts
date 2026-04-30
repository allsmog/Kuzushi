import { describe, expect, it } from "vitest";
import {
  assertRuntimeModelCompatible,
  assertRuntimeModelSelection,
  validateModelOverride,
  validateRuntimeModel,
} from "../../src/agent-runtime/model-validation.js";

describe("validateModelOverride", () => {
  it("requires provider:model for pi-ai but allows unknown providers", () => {
    expect(validateModelOverride("pi-ai", "anthropic:claude-opus-4-6")).toBeNull();
    expect(validateModelOverride("pi-ai", "custom:local-model")).toBeNull();
    expect(validateModelOverride("pi-ai", "claude-opus-4-6")).toContain("Expected format");
  });

  it("accepts Claude bare and anthropic-prefixed models only", () => {
    expect(validateModelOverride("claude", "claude-opus-4-6")).toBeNull();
    expect(validateModelOverride("claude", "anthropic:claude-opus-4-6")).toBeNull();
    expect(validateModelOverride("claude", "openai:gpt-4o")).toContain(
      "only accepts bare Claude model ids",
    );
  });

  it("accepts Codex bare and OpenAI/Codex-prefixed models only", () => {
    expect(validateModelOverride("codex", "gpt-5.4-mini")).toBeNull();
    expect(validateModelOverride("codex", "openai:gpt-5.4-mini")).toBeNull();
    expect(validateModelOverride("codex", "codex:gpt-5.4-mini")).toBeNull();
    expect(validateModelOverride("codex", "anthropic:claude-opus-4-6")).toContain(
      "Codex runtime only accepts",
    );
  });

  it("validates concrete runtime ids and rejects incompatible runtime/model pairs", () => {
    expect(validateRuntimeModel("codex", "anthropic:claude-opus-4-6")).toContain(
      "Codex runtime only accepts",
    );
    expect(validateRuntimeModel("custom-runtime", "anything")).toBeNull();
    expect(() => assertRuntimeModelCompatible("codex", "anthropic:claude-opus-4-6")).toThrow(
      /will not silently switch models/u,
    );
  });

  it("rejects fallbackModel unless the operator explicitly chooses a primary model", () => {
    expect(() =>
      assertRuntimeModelSelection(
        "claude",
        "anthropic:claude-sonnet-4-6",
        "anthropic:claude-haiku-4-5",
      ),
    ).toThrow(/Automatic model fallback is disabled/u);
  });
});

import { describe, expect, it } from "vitest";
import { parsePiAiModelSpec } from "../../src/agent-runtime/model-spec.js";

describe("parsePiAiModelSpec", () => {
  it("parses provider:modelId values", () => {
    expect(parsePiAiModelSpec("openai:gpt-4o")).toEqual({
      provider: "openai",
      modelId: "gpt-4o",
    });
  });

  it("trims surrounding whitespace", () => {
    expect(parsePiAiModelSpec("  google:gemini-2.0-flash  ")).toEqual({
      provider: "google",
      modelId: "gemini-2.0-flash",
    });
  });

  it("throws when model delimiter is missing", () => {
    expect(() => parsePiAiModelSpec("gpt-4o")).toThrow(
      "Expected format: provider:modelId",
    );
  });

  it("throws when provider or model id is empty", () => {
    expect(() => parsePiAiModelSpec(":gpt-4o")).toThrow(
      "Expected format: provider:modelId",
    );
    expect(() => parsePiAiModelSpec("openai:")).toThrow(
      "Expected format: provider:modelId",
    );
  });
});

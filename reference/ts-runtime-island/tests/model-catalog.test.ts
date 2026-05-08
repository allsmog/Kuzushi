import { describe, expect, it } from "vitest";
import { modelOptionsForProvider, providerFromModelId } from "../src/model-catalog.js";

describe("model catalog", () => {
  it("parses providers from pi-ai model ids", () => {
    expect(providerFromModelId("openai-codex:gpt-5.4-mini")).toBe("openai-codex");
    expect(providerFromModelId("anthropic:claude-sonnet-4-6")).toBe("anthropic");
    expect(providerFromModelId("gpt-5.4-mini")).toBeUndefined();
  });

  it("filters selectable models by provider", () => {
    const ids = modelOptionsForProvider("openai-codex").map((entry) => entry.id);
    expect(ids).toContain("openai-codex:gpt-5.4-mini");
    expect(ids.every((id) => id.startsWith("openai-codex:"))).toBe(true);
  });

  it("includes active and saved custom models for that provider", () => {
    const ids = modelOptionsForProvider("anthropic", {
      activeModel: "anthropic:claude-haiku-4-5-20251001",
      availableModels: ["anthropic:custom-review-model", "openai:gpt-5"],
    }).map((entry) => entry.id);

    expect(ids[0]).toBe("anthropic:claude-haiku-4-5-20251001");
    expect(ids).toContain("anthropic:custom-review-model");
    expect(ids).not.toContain("openai:gpt-5");
  });
});

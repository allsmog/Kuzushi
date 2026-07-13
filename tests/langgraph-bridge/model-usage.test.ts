import { describe, expect, it } from "vitest";
// @ts-expect-error -- plain .mjs bridge module without type declarations
import { usageFromMessage } from "../../scripts/langgraph-bridge/model.mjs";

describe("LangGraph bridge usage cost", () => {
  it("keeps token-only usage cost unavailable", () => {
    const usage = usageFromMessage({
      usage_metadata: { input_tokens: 12, output_tokens: 3 },
    });

    expect(usage).toEqual({ inputTokens: 12, outputTokens: 3 });
    expect(Object.hasOwn(usage, "costUsd")).toBe(false);
  });

  it("distinguishes an explicitly reported zero from unavailable cost", () => {
    const usage = usageFromMessage({
      usage_metadata: { input_tokens: 1, output_tokens: 1, cost_usd: 0 },
    });

    expect(usage.costUsd).toBe(0);
    expect(Object.hasOwn(usage, "costUsd")).toBe(true);
  });

  it("rejects invalid reported cost", () => {
    expect(() => usageFromMessage({ usage_metadata: { cost_usd: -1 } })).toThrow(
      /finite non-negative/,
    );
    expect(() => usageFromMessage({ usage_metadata: { cost_usd: "Infinity" } })).toThrow(
      /finite non-negative/,
    );
  });
});

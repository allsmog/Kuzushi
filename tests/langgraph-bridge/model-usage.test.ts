import { describe, expect, it } from "vitest";
// @ts-expect-error -- plain .mjs bridge module without type declarations
import {
  interruptedQueryResult,
  modelContinuationDecision,
  usageFromMessage,
  usageFromMessages,
} from "../../scripts/langgraph-bridge/model.mjs";

function ai(usage_metadata: Record<string, unknown>) {
  return { _getType: () => "ai", usage_metadata };
}

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

  it("aggregates every model turn and retains per-field provenance", () => {
    const usage = usageFromMessages([
      ai({ input_tokens: 10, output_tokens: 2, cost_usd: 0.01 }),
      { _getType: () => "tool" },
      ai({ input_tokens: 20, output_tokens: 4 }),
      ai({ input_tokens: 30, output_tokens: 6, cost_usd: 0.03 }),
    ]);

    expect(usage).toEqual({
      inputTokens: 60,
      outputTokens: 12,
      inputReportedCalls: 3,
      outputReportedCalls: 3,
      costUsd: 0.04,
      costReportedCalls: 2,
      modelCalls: 3,
    });
  });

  it("returns an MCP-timeout receipt for completed model turns", () => {
    const result = interruptedQueryResult(
      [ai({ input_tokens: 10, output_tokens: 2, cost_usd: 0.01 }), ai({ input_tokens: 4 })],
      "mcp_tool_timeout",
    );

    expect(result).toEqual({
      ok: true,
      text: "",
      input_tokens: 14,
      output_tokens: 2,
      cost_usd: 0.01,
      input_reported_calls: 2,
      output_reported_calls: 1,
      cost_reported_calls: 1,
      model_calls: 2,
      cost_usd_exact: false,
      truncated: true,
      stopReason: "mcp_tool_timeout",
    });
  });

  it("stops follow-up turns when observed spend is incomplete or exhausted", () => {
    const incomplete = [ai({ cost_usd: 0.01 }), ai({})];
    const exhausted = [ai({ cost_usd: 0.02 }), ai({ cost_usd: 0.03 })];

    expect(modelContinuationDecision(incomplete, 1, 5)).toBe("observed_spend_incomplete");
    expect(modelContinuationDecision(exhausted, 0.05, 5)).toBe("observed_spend_exhausted");
    expect(modelContinuationDecision([ai({ cost_usd: 0 })], 1, 1)).toBe("model_turn_limit");
  });

  it("rejects aggregate token and cost overflow", () => {
    expect(() =>
      usageFromMessages([ai({ input_tokens: Number.MAX_SAFE_INTEGER }), ai({ input_tokens: 1 })]),
    ).toThrow(/aggregate overflowed/);
    expect(() =>
      usageFromMessages([ai({ cost_usd: Number.MAX_VALUE }), ai({ cost_usd: Number.MAX_VALUE })]),
    ).toThrow(/cost aggregate overflowed/);
  });
});

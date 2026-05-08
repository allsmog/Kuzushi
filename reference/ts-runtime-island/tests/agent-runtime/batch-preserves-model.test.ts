/**
 * Verifies that `runStructuredBatchQuery` preserves the operator-configured
 * model when it falls back from the Batch API to per-prompt sequential
 * queries. The fallback is policy-allowed only because it does not switch
 * models — this test pins the invariant so the door doesn't crack open
 * later.
 */
import { describe, expect, it, vi } from "vitest";
import { runStructuredBatchQuery } from "../../src/agent-runtime/execution.js";
import type {
  AgentMessage,
  AgentQueryRequest,
  AgentRuntime,
} from "../../src/agent-runtime/types.js";

class StubRuntime implements AgentRuntime {
  readonly id = "stub";
  /** Captured `model` strings from each query call. */
  readonly observedModels: string[] = [];
  /** Captured fallbackModel values (should remain undefined). */
  readonly observedFallbackModels: Array<string | undefined> = [];

  constructor(
    private readonly batchBehavior:
      | { kind: "available" }
      | { kind: "throws"; error: Error }
      | { kind: "missing" },
  ) {}

  async *query(request: AgentQueryRequest): AsyncIterable<AgentMessage> {
    this.observedModels.push(request.options.model);
    this.observedFallbackModels.push(request.options.fallbackModel);
    yield {
      type: "result",
      subtype: "success",
      result: JSON.stringify({ ok: true }),
      structuredOutput: { ok: true },
      durationMs: 1,
      numTurns: 1,
      totalCostUsd: 0.01,
    };
  }

  // queryBatch defined dynamically on instances that report "available"/"throws".
  queryBatch?: AgentRuntime["queryBatch"];
}

describe("runStructuredBatchQuery batch→sequential fallback", () => {
  it("uses the same model on every sequential call when batch throws", async () => {
    const runtime = new StubRuntime({ kind: "throws", error: new Error("batch endpoint 404") });
    runtime.queryBatch = vi.fn(async () => {
      throw new Error("batch endpoint 404");
    });

    const requests = [
      { id: "a", prompt: "alpha" },
      { id: "b", prompt: "beta" },
      { id: "c", prompt: "gamma" },
    ];

    const results = await runStructuredBatchQuery(requests, {
      cwd: "/tmp",
      model: "anthropic:claude-sonnet-4-6",
      schema: { type: "object", additionalProperties: true } as Record<string, unknown>,
      runtimeOptions: { runtime },
      fallbackConcurrency: 1,
    });

    expect(results.size).toBe(3);
    expect(runtime.observedModels.length).toBe(3);
    for (const observed of runtime.observedModels) {
      expect(observed).toBe("anthropic:claude-sonnet-4-6");
    }
    for (const fallback of runtime.observedFallbackModels) {
      expect(fallback).toBeUndefined();
    }
  });

  it("never injects a fallback model during sequential fallback", async () => {
    const runtime = new StubRuntime({ kind: "throws", error: new Error("oops") });
    runtime.queryBatch = vi.fn(async () => {
      throw new Error("oops");
    });

    await runStructuredBatchQuery([{ id: "x", prompt: "p" }], {
      cwd: "/tmp",
      model: "anthropic:claude-haiku-4-5",
      schema: { type: "object" } as Record<string, unknown>,
      runtimeOptions: { runtime },
    });

    expect(runtime.observedFallbackModels).toEqual([undefined]);
  });

  it("uses the operator's model when no batch endpoint is exposed at all", async () => {
    const runtime = new StubRuntime({ kind: "missing" });
    // queryBatch deliberately not assigned

    const requests = [{ id: "only", prompt: "hi" }];
    await runStructuredBatchQuery(requests, {
      cwd: "/tmp",
      model: "anthropic:claude-opus-4-7",
      schema: { type: "object" } as Record<string, unknown>,
      runtimeOptions: { runtime },
    });
    expect(runtime.observedModels).toEqual(["anthropic:claude-opus-4-7"]);
  });
});

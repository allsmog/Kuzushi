import { describe, expect, it } from "vitest";
import { LoggingAgentRuntime } from "../../src/agent-runtime/logging-runtime.js";
import type {
  AgentMessage,
  AgentQueryRequest,
  AgentRuntime,
} from "../../src/agent-runtime/types.js";

function makeInnerWithoutOptionals(): AgentRuntime {
  return {
    id: "inner-without-optionals",
    async *query(_request: AgentQueryRequest): AsyncIterable<AgentMessage> {
      // Never yields — caller shouldn't iterate in these tests.
    },
  };
}

describe("LoggingAgentRuntime decorator", () => {
  it("does not expose queryBatch when the inner runtime does not support batch mode", () => {
    const inner = makeInnerWithoutOptionals();
    const logged = new LoggingAgentRuntime(inner);

    // Regression: previously `queryBatch` was defined as a class method that
    // returned `undefined as never`, causing callers like `rescoreFindings`
    // to enter the batch code path and crash on `.get(...)` when the inner
    // runtime (e.g., pi-ai) has no batch API. The decorator must now mirror
    // the inner runtime's feature surface: if `inner.queryBatch` is absent,
    // `logged.queryBatch` must be absent too.
    expect(logged.queryBatch).toBeUndefined();
  });

  it("does not expose createSession when the inner runtime does not support sessions", () => {
    const inner = makeInnerWithoutOptionals();
    const logged = new LoggingAgentRuntime(inner);

    // Same pathology as queryBatch above — the decorator must honor the
    // inner runtime's optional-method surface so `runtime.createSession?.(...)`
    // actually skips when the backend has no session support.
    expect(logged.createSession).toBeUndefined();
  });

  it("exposes queryBatch when the inner runtime supports it", async () => {
    const expected = new Map<
      string,
      {
        resultText: string;
        structuredOutput: unknown;
        executionError: string | null;
        costUsd: number;
      }
    >([
      [
        "req-0",
        { resultText: "ok", structuredOutput: { ok: true }, executionError: null, costUsd: 0 },
      ],
    ]);

    const inner: AgentRuntime = {
      id: "inner-with-batch",
      async *query(_request: AgentQueryRequest): AsyncIterable<AgentMessage> {},
      async queryBatch() {
        return expected;
      },
    };
    const logged = new LoggingAgentRuntime(inner);

    expect(typeof logged.queryBatch).toBe("function");
    const result = await logged.queryBatch!([{ id: "req-0", prompt: "hello" }], {
      cwd: "/tmp",
      model: "anthropic:claude-haiku-4-5-20251001",
    });
    expect(result).toBe(expected);
  });
});

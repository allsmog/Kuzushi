/**
 * Coverage for `wrapRuntimeWithActivityForwarding` — the runtime-boundary
 * wrapper that tees every `query(...)` (and `createSession().query(...)`)
 * stream through the message bus as `task:activity` events.
 */
import { describe, expect, it, vi } from "vitest";
import type { AgentMessage, AgentRuntime, AgentSession } from "../../src/agent-runtime/types.js";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import { wrapRuntimeWithActivityForwarding } from "../../src/bus/runtime-forwarding.js";

type ActivityPayload = { taskId: string; description: string };

function collectActivityEvents(
  bus: InProcessBus,
): { payload: ActivityPayload; meta: Record<string, unknown> }[] {
  const received: { payload: ActivityPayload; meta: Record<string, unknown> }[] = [];
  bus.subscribe(
    "task:activity",
    (event: { payload: ActivityPayload; meta: Record<string, unknown> }) => {
      received.push({ payload: event.payload, meta: event.meta });
    },
  );
  return received;
}

function makeRuntime(messages: AgentMessage[]): AgentRuntime {
  return {
    id: "test-runtime",
    async *query() {
      for (const m of messages) yield m;
    },
  };
}

async function drain(iter: AsyncIterable<AgentMessage>): Promise<AgentMessage[]> {
  const out: AgentMessage[] = [];
  for await (const m of iter) out.push(m);
  return out;
}

describe("wrapRuntimeWithActivityForwarding", () => {
  it("tees each assistant tool_use / tool-summary message as task:activity", async () => {
    const bus = new InProcessBus();
    const received = collectActivityEvents(bus);

    const scripted: AgentMessage[] = [
      {
        type: "assistant",
        content: [
          { type: "text", text: "thinking" },
          { type: "tool_use", name: "Glob", input: { pattern: "src/**/*.ts" } },
          { type: "tool_use", name: "Read", input: { file_path: "/repo/a.ts" } },
        ],
      },
      {
        type: "tool-summary",
        summary: "Found 14 routes under src/routes\nline2\nline3",
        precedingToolUseIds: [],
      },
      { type: "result", subtype: "success", result: "ok", totalCostUsd: 0.02 },
    ];
    const wrapped = wrapRuntimeWithActivityForwarding(
      makeRuntime(scripted),
      bus,
      "carlini-threat-hunt",
      "run-1",
    );

    const yielded = await drain(wrapped.query({ prompt: "x", options: {} }));

    // Caller sees every message unchanged.
    expect(yielded.map((m) => m.type)).toEqual(["assistant", "tool-summary", "result"]);

    // One task:activity per describeRuntimeMessage line.
    await new Promise((r) => setTimeout(r, 0));
    const lines = received.map((r) => r.payload.description);
    expect(lines).toEqual([
      "Glob · src/**/*.ts",
      "Read · /repo/a.ts",
      "Found 14 routes under src/routes",
    ]);
    for (const r of received) {
      expect(r.payload.taskId).toBe("carlini-threat-hunt");
      expect(r.meta["runId"]).toBe("run-1");
    }
    await bus.close();
  });

  it("is idempotent for the same (taskId,runId)", () => {
    const bus = new InProcessBus();
    const inner = makeRuntime([]);
    const w1 = wrapRuntimeWithActivityForwarding(inner, bus, "t", "r");
    const w2 = wrapRuntimeWithActivityForwarding(w1, bus, "t", "r");
    expect(w2).toBe(w1);
    void bus.close();
  });

  it("stack-replaces when rewrapped with a different key (no double emit)", async () => {
    const bus = new InProcessBus();
    const received = collectActivityEvents(bus);

    const scripted: AgentMessage[] = [
      {
        type: "assistant",
        content: [{ type: "tool_use", name: "Grep", input: { pattern: "foo" } }],
      },
      { type: "result", subtype: "success", result: "ok", totalCostUsd: 0 },
    ];
    const inner = makeRuntime(scripted);
    const outer = wrapRuntimeWithActivityForwarding(inner, bus, "outer", "r");
    const replaced = wrapRuntimeWithActivityForwarding(outer, bus, "inner", "r");

    await drain(replaced.query({ prompt: "x", options: {} }));
    await new Promise((r) => setTimeout(r, 0));

    // Single emission under the innermost (most recent) key only.
    expect(received).toHaveLength(1);
    expect(received[0]?.payload).toEqual({
      taskId: "inner",
      description: "Grep · foo",
    });
    await bus.close();
  });

  it("delegates id through to the underlying runtime", () => {
    const bus = new InProcessBus();
    const inner = makeRuntime([]);
    const wrapped = wrapRuntimeWithActivityForwarding(inner, bus, "t", "r");
    expect(wrapped.id).toBe(inner.id);
    void bus.close();
  });

  it("tees createSession().query() and delegates close()", async () => {
    const bus = new InProcessBus();
    const received = collectActivityEvents(bus);
    const closeSpy = vi.fn().mockResolvedValue(undefined);

    const scripted: AgentMessage[] = [
      {
        type: "assistant",
        content: [{ type: "tool_use", name: "Bash", input: { command: "pnpm test" } }],
      },
      { type: "result", subtype: "success", result: "ok", totalCostUsd: 0 },
    ];

    const inner: AgentRuntime = {
      id: "session-runtime",
      query() {
        throw new Error("query should not be called for this test");
      },
      createSession(): AgentSession {
        return {
          async *query() {
            for (const m of scripted) yield m;
          },
          close: closeSpy,
        };
      },
    };
    const wrapped = wrapRuntimeWithActivityForwarding(inner, bus, "t", "r");
    const session = wrapped.createSession!({ cwd: "/tmp" });
    const yielded = await drain(session.query("hello"));
    await session.close();

    expect(yielded.map((m) => m.type)).toEqual(["assistant", "result"]);
    await new Promise((r) => setTimeout(r, 0));
    expect(received).toHaveLength(1);
    expect(received[0]?.payload).toEqual({
      taskId: "t",
      description: "Bash · pnpm test",
    });
    expect(closeSpy).toHaveBeenCalledTimes(1);
    await bus.close();
  });

  it("delegates queryBatch verbatim (no teeing)", async () => {
    const bus = new InProcessBus();
    const received = collectActivityEvents(bus);
    const batchSpy = vi.fn().mockResolvedValue(new Map());

    const inner = {
      id: "batch-runtime",
      query: async function* () {},
      queryBatch: batchSpy,
    } as unknown as AgentRuntime;
    const wrapped = wrapRuntimeWithActivityForwarding(inner, bus, "t", "r");

    await wrapped.queryBatch!([], { cwd: "/tmp" });
    expect(batchSpy).toHaveBeenCalledTimes(1);
    await new Promise((r) => setTimeout(r, 0));
    expect(received).toEqual([]);
    await bus.close();
  });

  it("drops createSession when the inner runtime lacks it", () => {
    const bus = new InProcessBus();
    const inner = makeRuntime([]);
    const wrapped = wrapRuntimeWithActivityForwarding(inner, bus, "t", "r");
    expect(wrapped.createSession).toBeUndefined();
    void bus.close();
  });

  it("publishes pi-ai tool-call-start events as task:activity for early visibility", async () => {
    // Regression: on the pi-ai path a deep-thinking Opus turn can spend
    // 5+ minutes streaming `thinking-delta` / `text-delta` events before
    // the first `assistant` yield — the activity rail was silent during
    // that window because describeRuntimeMessage only mapped
    // assistant/tool-summary. With tool-call-start handling, the rail
    // shows the tool name as soon as the model commits to it.
    const bus = new InProcessBus();
    const received = collectActivityEvents(bus);

    const scripted: AgentMessage[] = [
      { type: "thinking-delta", delta: "reasoning..." },
      { type: "tool-call-start", toolUseId: "tu-1", toolName: "Read" },
      { type: "tool-call-delta", toolUseId: "tu-1", delta: '{"file_path":' },
      {
        type: "assistant",
        content: [
          { type: "tool_use", id: "tu-1", name: "Read", input: { file_path: "/repo/a.ts" } },
        ],
      },
      { type: "result", subtype: "success", result: "ok", totalCostUsd: 0 },
    ];
    const wrapped = wrapRuntimeWithActivityForwarding(
      makeRuntime(scripted),
      bus,
      "carlini-threat-hunt",
      "run-1",
    );

    await drain(wrapped.query({ prompt: "x", options: {} }));
    await new Promise((r) => setTimeout(r, 0));

    const lines = received.map((r) => r.payload.description);
    // First entry comes from tool-call-start (just the name, no args yet).
    // Second entry comes from the assistant turn closing with full input.
    // thinking-delta and tool-call-delta are silent — intentionally.
    expect(lines).toEqual(["Read", "Read · /repo/a.ts"]);
    await bus.close();
  });

  it("never breaks the caller's stream on a failing publish", async () => {
    const brokenBus = {
      publish: vi.fn().mockRejectedValue(new Error("boom")),
      subscribe: vi.fn(),
      unsubscribe: vi.fn(),
      waitFor: vi.fn(),
      close: vi.fn().mockResolvedValue(undefined),
    } as unknown as InProcessBus;

    const scripted: AgentMessage[] = [
      {
        type: "assistant",
        content: [{ type: "tool_use", name: "Read", input: { path: "/x" } }],
      },
      { type: "result", subtype: "success", result: "ok", totalCostUsd: 0 },
    ];
    const wrapped = wrapRuntimeWithActivityForwarding(makeRuntime(scripted), brokenBus, "t", "r");
    const yielded = await drain(wrapped.query({ prompt: "x", options: {} }));
    expect(yielded.map((m) => m.type)).toEqual(["assistant", "result"]);
  });
});

import { describe, expect, it } from "vitest";
import type { AgentMessage } from "../../src/agent-runtime/types.js";
import { createFakeRuntime } from "../../src/testing/index.js";

async function collect(iter: AsyncIterable<AgentMessage>): Promise<AgentMessage[]> {
  const out: AgentMessage[] = [];
  for await (const msg of iter) out.push(msg);
  return out;
}

describe("createFakeRuntime", () => {
  it("records every query request on .calls", async () => {
    const rt = createFakeRuntime();
    await collect(rt.query({ prompt: "hello", options: { cwd: ".", model: "m" } }));
    expect(rt.calls).toHaveLength(1);
    expect(rt.calls[0]?.prompt).toBe("hello");
  });

  it("matches string.includes patterns and yields scripted text", async () => {
    const rt = createFakeRuntime([{ match: "triage", output: "verdict=TP" }]);
    const msgs = await collect(
      rt.query({ prompt: "please triage", options: { cwd: ".", model: "m" } }),
    );
    const assistant = msgs.find((m) => m.type === "assistant");
    expect(assistant).toBeTruthy();
    // @ts-expect-error — content is dynamic
    expect(assistant.content[0].text).toBe("verdict=TP");
    const result = msgs.find((m) => m.type === "result");
    // @ts-expect-error — dynamic message shape
    expect(result.result).toBe("verdict=TP");
  });

  it("supports RegExp match patterns", async () => {
    const rt = createFakeRuntime([{ match: /^SCAN\b/i, output: "ok" }]);
    const msgs = await collect(
      rt.query({ prompt: "scan the repo", options: { cwd: ".", model: "m" } }),
    );
    const result = msgs.find((m) => m.type === "result");
    // @ts-expect-error — dynamic
    expect(result.result).toBe("ok");
  });

  it("falls back to empty output + success result when no match", async () => {
    const rt = createFakeRuntime([{ match: "triage", output: "x" }]);
    const msgs = await collect(
      rt.query({ prompt: "unrelated prompt", options: { cwd: ".", model: "m" } }),
    );
    // Assistant message with no text blocks.
    const assistant = msgs.find((m) => m.type === "assistant");
    expect(assistant).toBeTruthy();
    // @ts-expect-error — content is always array
    expect(assistant.content).toEqual([]);
    const result = msgs.find((m) => m.type === "result");
    // @ts-expect-error — dynamic
    expect(result.subtype).toBe("success");
  });

  it("emits a tool_use content block + synthetic tool-result when toolUse is set", async () => {
    const rt = createFakeRuntime([
      {
        match: "use tool",
        output: "",
        toolUse: { name: "fs_read", input: { path: "a.txt" }, toolUseId: "tu1" },
      },
    ]);
    const msgs = await collect(
      rt.query({ prompt: "please use tool", options: { cwd: ".", model: "m" } }),
    );
    const assistant = msgs.find((m) => m.type === "assistant");
    // @ts-expect-error — dynamic
    expect(assistant.content[0].type).toBe("tool_use");
    const toolResult = msgs.find((m) => m.type === "tool-result");
    // @ts-expect-error — dynamic
    expect(toolResult.toolUseId).toBe("tu1");
  });

  it("reports costUsd + structuredOutput on the final result", async () => {
    const rt = createFakeRuntime([
      { match: "cost", output: "x", costUsd: 0.12, structuredOutput: { verdict: "TP" } },
    ]);
    const msgs = await collect(
      rt.query({ prompt: "cost test", options: { cwd: ".", model: "m" } }),
    );
    const result = msgs.find((m) => m.type === "result");
    // @ts-expect-error — dynamic
    expect(result.totalCostUsd).toBe(0.12);
    // @ts-expect-error — dynamic
    expect(result.structuredOutput).toEqual({ verdict: "TP" });
  });

  it("clear() drops recorded calls", async () => {
    const rt = createFakeRuntime();
    await collect(rt.query({ prompt: "p", options: { cwd: ".", model: "m" } }));
    rt.clear();
    expect(rt.calls).toEqual([]);
  });
});

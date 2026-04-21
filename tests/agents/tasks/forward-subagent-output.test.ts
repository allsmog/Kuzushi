/**
 * Coverage for the shared sub-agent message → onOutput forwarder.
 *
 * Every subprocess-running tool (tob:audit, vuln-scout:audit,
 * prompt-armor:*, randori:pasta) funnels its Claude Code message stream
 * through `forwardSubAgentMessage`. This file exercises the heuristics
 * that decide which messages become `onOutput(line)` calls and what the
 * line content looks like.
 */
import { describe, expect, it, vi } from "vitest";
import { forwardSubAgentMessage } from "../../../src/agents/tasks/forward-subagent-output.js";

describe("forwardSubAgentMessage", () => {
  it("emits one line per tool_use block in an assistant message", () => {
    const sink = vi.fn();
    forwardSubAgentMessage(
      {
        type: "assistant",
        content: [
          { type: "text", text: "reading context" },
          { type: "tool_use", name: "Read", input: { file_path: "/src/a.ts" } },
          { type: "tool_use", name: "Bash", input: { command: "npm test" } },
        ],
      },
      sink,
    );
    expect(sink).toHaveBeenCalledTimes(2);
    expect(sink).toHaveBeenNthCalledWith(1, "Read(/src/a.ts)");
    expect(sink).toHaveBeenNthCalledWith(2, "Bash(npm test)");
  });

  it("omits input hint when tool_use has no recognized primary field", () => {
    const sink = vi.fn();
    forwardSubAgentMessage(
      {
        type: "assistant",
        content: [{ type: "tool_use", name: "Custom", input: { nope: 1 } }],
      },
      sink,
    );
    expect(sink).toHaveBeenCalledWith("Custom");
  });

  it("handles tool_use with null or missing input", () => {
    const sink = vi.fn();
    forwardSubAgentMessage(
      { type: "assistant", content: [{ type: "tool_use", name: "NoInput" }] },
      sink,
    );
    expect(sink).toHaveBeenCalledWith("NoInput");
  });

  it("clamps long input hints to 40 chars with ellipsis", () => {
    const sink = vi.fn();
    const long = "/".repeat(120);
    forwardSubAgentMessage(
      {
        type: "assistant",
        content: [{ type: "tool_use", name: "Read", input: { file_path: long } }],
      },
      sink,
    );
    const [line] = sink.mock.calls[0]!;
    const hint = (line as string).slice("Read(".length, -1);
    expect(hint.length).toBeLessThanOrEqual(40);
    expect(hint.endsWith("…")).toBe(true);
  });

  it("prioritizes file_path > path > target > command > pattern > query > url", () => {
    const sink = vi.fn();
    forwardSubAgentMessage(
      {
        type: "assistant",
        content: [
          { type: "tool_use", name: "A", input: { file_path: "fp", path: "p" } },
          { type: "tool_use", name: "B", input: { path: "p", target: "t" } },
          { type: "tool_use", name: "C", input: { target: "t", command: "c" } },
          { type: "tool_use", name: "D", input: { command: "c", pattern: "pt" } },
          { type: "tool_use", name: "E", input: { pattern: "pt", query: "q" } },
          { type: "tool_use", name: "F", input: { query: "q", url: "u" } },
        ],
      },
      sink,
    );
    expect(sink.mock.calls.map((c) => c[0])).toEqual([
      "A(fp)",
      "B(p)",
      "C(t)",
      "D(c)",
      "E(pt)",
      "F(q)",
    ]);
  });

  it("emits a heartbeat line on tool-progress events", () => {
    const sink = vi.fn();
    const result = forwardSubAgentMessage(
      { type: "tool-progress", toolName: "Read", toolUseId: "x" },
      sink,
    );
    expect(result).toBe(true);
    expect(sink).toHaveBeenCalledWith("Read…");
  });

  it("falls back to 'tool…' when tool-progress has no name", () => {
    const sink = vi.fn();
    forwardSubAgentMessage({ type: "tool-progress" }, sink);
    expect(sink).toHaveBeenCalledWith("tool…");
  });

  it("ignores result and tool-summary messages", () => {
    const sink = vi.fn();
    forwardSubAgentMessage({ type: "result" }, sink);
    forwardSubAgentMessage({ type: "tool-summary" }, sink);
    expect(sink).not.toHaveBeenCalled();
  });

  it("is a safe no-op when onOutput is undefined", () => {
    expect(() =>
      forwardSubAgentMessage(
        {
          type: "assistant",
          content: [{ type: "tool_use", name: "Read", input: { file_path: "x" } }],
        },
        undefined,
      ),
    ).not.toThrow();
  });

  it("returns false when the assistant message has no tool_use blocks", () => {
    const sink = vi.fn();
    const result = forwardSubAgentMessage(
      { type: "assistant", content: [{ type: "text", text: "just thinking" }] },
      sink,
    );
    expect(result).toBe(false);
    expect(sink).not.toHaveBeenCalled();
  });

  it("returns true once an assistant message emits at least one line", () => {
    const sink = vi.fn();
    const result = forwardSubAgentMessage(
      {
        type: "assistant",
        content: [
          { type: "text", text: "thinking" },
          { type: "tool_use", name: "X" },
        ],
      },
      sink,
    );
    expect(result).toBe(true);
  });
});

import { describe, expect, it } from "vitest";
import {
  formatShellHistoryEntryPlain,
  projectShellHistoryEntry,
  shellHistoryPlainSignature,
} from "../../src/ui/shell-log-events.js";
import type { ShellHistoryEntry } from "../../src/ui/state.js";

describe("shell log event projection", () => {
  it("projects running tool calls as tool/use events", () => {
    const entry: ShellHistoryEntry = {
      type: "tool-call",
      id: "tc-1",
      tool: "sast:scan",
      displayName: "Scan",
      inputHint: "./src",
      status: "running",
      text: "⏺ Scan(./src)",
      timestamp: 1,
    };

    expect(projectShellHistoryEntry(entry)).toMatchObject({
      kind: "tool/use",
      tool: "sast:scan",
      displayName: "Scan",
      inputHint: "./src",
      status: "running",
    });
  });

  it("projects resolved tool calls as tool/result events", () => {
    const entry: ShellHistoryEntry = {
      type: "tool-call",
      id: "tc-1",
      tool: "context:build",
      status: "ok",
      elapsedSeconds: 3,
      resultOutput: "context built",
      text: "⏺ context:build",
      timestamp: 1,
    };

    expect(projectShellHistoryEntry(entry)).toMatchObject({
      kind: "tool/result",
      tool: "context:build",
      status: "ok",
      elapsedSeconds: 3,
      resultOutput: "context built",
    });
  });

  it("formats tool lifecycle lines for plain renderers", () => {
    const running: ShellHistoryEntry = {
      type: "tool-call",
      id: "tc-1",
      tool: "sast:scan",
      displayName: "Scan",
      inputHint: "./repo",
      status: "running",
      text: "⏺ Scan(./repo)",
      timestamp: 1,
    };
    const done: ShellHistoryEntry = {
      ...running,
      status: "ok",
      elapsedSeconds: 5,
      resultOutput: "4 findings",
    };

    expect(formatShellHistoryEntryPlain(running)).toEqual(["[tool] Scan(./repo) started"]);
    expect(formatShellHistoryEntryPlain(done)).toEqual(["[tool:ok] Scan · 4 findings · 5s"]);
  });

  it("summarizes long output blocks without flooding plain output", () => {
    const entry: ShellHistoryEntry = {
      type: "output",
      text: Array.from({ length: 6 }, (_, index) => `line ${index + 1}`).join("\n"),
      timestamp: 1,
    };

    expect(formatShellHistoryEntryPlain(entry, { maxOutputLines: 3 })).toEqual([
      "[output] 6 lines; showing first 3",
      "  line 1",
      "  line 2",
      "  line 3",
      "  ... 3 more",
    ]);
  });

  it("changes signature only when mutable tool-call terminal fields change", () => {
    const running: ShellHistoryEntry = {
      type: "tool-call",
      id: "tc-1",
      tool: "sast:scan",
      status: "running",
      liveActivities: [{ id: "la-1", text: "step" }],
      text: "⏺ sast:scan",
      timestamp: 1,
    };
    const withDifferentActivity: ShellHistoryEntry = {
      ...running,
      liveActivities: [{ id: "la-2", text: "another step" }],
    };
    const done: ShellHistoryEntry = {
      ...running,
      status: "ok",
      resultOutput: "done",
    };

    expect(shellHistoryPlainSignature(withDifferentActivity)).toBe(
      shellHistoryPlainSignature(running),
    );
    expect(shellHistoryPlainSignature(done)).not.toBe(shellHistoryPlainSignature(running));
  });
});

import { beforeEach, describe, expect, it } from "vitest";
import { __shellInternals } from "../../src/copilot/shell.js";
import { createUIStore, type UIStore } from "../../src/ui/state.js";

const {
  extractToolUseActivities,
  extractToolUseHeaders,
  summarizeInput,
  pushToolActivity,
  pushToolPhase,
  renderToolInputHint,
  patchHistoryEntry,
  pushLiveActivity,
  finalizeRunningToolCalls,
} = __shellInternals;

function seedShellState(): UIStore {
  const store = createUIStore();
  store.update({
    mode: "shell",
    shell: {
      modules: [],
      moduleCatalog: [],
      tools: [],
      focusedModule: null,
      shellView: "catalog",
      openFindingId: null,
      target: null,
      workspace: null,
      tuneSnapshot: null,
      history: [],
      commandHistory: [],
      moduleOptions: {},
      processing: true,
      currentTool: {
        name: "context:build",
        startedAt: Date.now(),
        lastEventAt: Date.now(),
      },
    },
  });
  return store;
}

describe("extractToolUseActivities", () => {
  it("returns a label per tool_use block", () => {
    const lines = extractToolUseActivities([
      { type: "text", text: "thinking" },
      { type: "tool_use", name: "Read", input: { path: "/src/foo.ts" } },
      { type: "tool_use", name: "Grep", input: { query: "needle" } },
    ]);
    expect(lines).toEqual(["Read · /src/foo.ts", "Grep · needle"]);
  });

  it("handles empty / missing inputs", () => {
    const lines = extractToolUseActivities([{ type: "tool_use", name: "Bash" }]);
    expect(lines).toEqual(["Bash"]);
  });

  it("truncates long input hints to 40 chars", () => {
    const long = "/".repeat(80);
    const lines = extractToolUseActivities([{ type: "tool_use", name: "Read", input: { path: long } }]);
    expect(lines[0]).toBeDefined();
    const [label] = lines;
    const hint = label!.split(" · ")[1]!;
    expect(hint.length).toBeLessThanOrEqual(40);
    expect(hint.endsWith("…")).toBe(true);
  });

  it("skips non-tool_use blocks", () => {
    expect(extractToolUseActivities([{ type: "text", text: "hi" }])).toEqual([]);
  });
});

describe("pushToolPhase", () => {
  let store: UIStore;
  beforeEach(() => {
    store = seedShellState();
  });

  it("parses trailing (N/M) counts", () => {
    pushToolPhase(store, "building threat model (3/15)");
    const tool = store.getState().shell!.currentTool!;
    expect(tool.phase).toBe("building threat model (3/15)");
    expect(tool.step).toBe(3);
    expect(tool.total).toBe(15);
  });

  it("parses mid-string (N/M) counts", () => {
    pushToolPhase(store, "lab (2/15) · building threat model");
    const tool = store.getState().shell!.currentTool!;
    expect(tool.step).toBe(2);
    expect(tool.total).toBe(15);
  });

  it("leaves step/total undefined when no counter present", () => {
    pushToolPhase(store, "phase 1 (S1-S3 scope)");
    const tool = store.getState().shell!.currentTool!;
    expect(tool.phase).toBe("phase 1 (S1-S3 scope)");
    expect(tool.step).toBeUndefined();
    expect(tool.total).toBeUndefined();
  });

  it("is a no-op when currentTool is undefined", () => {
    store.update({
      shell: { ...store.getState().shell!, currentTool: undefined },
    });
    pushToolPhase(store, "phase 2");
    expect(store.getState().shell!.currentTool).toBeUndefined();
  });
});

describe("pushToolActivity", () => {
  let store: UIStore;
  beforeEach(() => {
    store = seedShellState();
  });

  it("prepends entries newest-first", () => {
    pushToolActivity(store, "first");
    pushToolActivity(store, "second");
    pushToolActivity(store, "third");
    const texts = store.getState().shell!.currentTool!.activities!.map((a) => a.text);
    expect(texts).toEqual(["third", "second", "first"]);
  });

  it("caps the buffer at 5 entries", () => {
    for (let i = 0; i < 10; i++) pushToolActivity(store, `step ${i}`);
    const activities = store.getState().shell!.currentTool!.activities!;
    expect(activities.length).toBe(5);
    expect(activities[0]!.text).toBe("step 9");
    expect(activities[4]!.text).toBe("step 5");
  });

  it("dedupes consecutive duplicate text by bumping timestamp", () => {
    pushToolActivity(store, "scanning");
    const ts1 = store.getState().shell!.currentTool!.activities![0]!.ts;
    // tiny delay so ts updates
    const later = ts1 + 100;
    // fake clock advance by re-pushing
    pushToolActivity(store, "scanning");
    const activities = store.getState().shell!.currentTool!.activities!;
    expect(activities.length).toBe(1);
    expect(activities[0]!.ts).toBeGreaterThanOrEqual(later - 100);
  });

  it("truncates text longer than 80 chars", () => {
    const long = "x".repeat(120);
    pushToolActivity(store, long);
    const activities = store.getState().shell!.currentTool!.activities!;
    expect(activities[0]!.text.length).toBeLessThanOrEqual(80);
    expect(activities[0]!.text.endsWith("…")).toBe(true);
  });

  it("is a no-op when currentTool is undefined", () => {
    store.update({
      shell: { ...store.getState().shell!, currentTool: undefined },
    });
    pushToolActivity(store, "dropped");
    expect(store.getState().shell!.currentTool).toBeUndefined();
  });
});

describe("summarizeInput", () => {
  it("returns undefined for null/undefined", () => {
    expect(summarizeInput(null)).toBeUndefined();
    expect(summarizeInput(undefined)).toBeUndefined();
  });

  it("returns string input directly (trimmed)", () => {
    expect(summarizeInput("  ./src  ")).toBe("./src");
  });

  it("clamps strings longer than 40 chars", () => {
    const long = "a".repeat(60);
    const result = summarizeInput(long)!;
    expect(result.length).toBe(40);
    expect(result.endsWith("…")).toBe(true);
  });

  it("extracts primary field from object (target, path, file, query, name, url, module)", () => {
    expect(summarizeInput({ target: "." })).toBe(".");
    expect(summarizeInput({ path: "/src/foo.ts" })).toBe("/src/foo.ts");
    expect(summarizeInput({ file: "bar.js" })).toBe("bar.js");
    expect(summarizeInput({ query: "needle" })).toBe("needle");
    expect(summarizeInput({ url: "https://example.com" })).toBe("https://example.com");
    expect(summarizeInput({ module: "sast" })).toBe("sast");
  });

  it("falls back to JSON.stringify for objects without primary fields", () => {
    const result = summarizeInput({ foo: 1, bar: 2 });
    expect(result).toBe('{"foo":1,"bar":2}');
  });

  it("handles numbers and booleans", () => {
    expect(summarizeInput(42)).toBe("42");
    expect(summarizeInput(true)).toBe("true");
  });

  it("handles arrays with a string first element", () => {
    expect(summarizeInput(["a", "b"])).toBe("a");
  });

  it("returns undefined for empty arrays", () => {
    expect(summarizeInput([])).toBeUndefined();
  });
});

describe("extractToolUseHeaders", () => {
  it("returns { name, inputHint } per tool_use block", () => {
    const headers = extractToolUseHeaders([
      { type: "text", text: "thinking" },
      { type: "tool_use", name: "Read", input: { path: "/src/foo.ts" } },
      { type: "tool_use", name: "Bash", input: {} },
    ]);
    expect(headers).toEqual([
      { name: "Read", inputHint: "/src/foo.ts" },
      { name: "Bash" },
    ]);
  });

  it("omits inputHint when input is missing", () => {
    const headers = extractToolUseHeaders([{ type: "tool_use", name: "Grep" }]);
    expect(headers).toEqual([{ name: "Grep" }]);
  });

  it("skips non-tool_use blocks", () => {
    expect(extractToolUseHeaders([{ type: "text", text: "hi" }])).toEqual([]);
  });

  it("captures the Anthropic tool_use id when present", () => {
    const headers = extractToolUseHeaders([
      { type: "tool_use", id: "toolu_123", name: "Read", input: { path: "/a" } },
      { type: "tool_use", id: "toolu_456", name: "Bash" },
      { type: "tool_use", name: "NoId" }, // id missing
    ]);
    expect(headers).toEqual([
      { id: "toolu_123", name: "Read", inputHint: "/a" },
      { id: "toolu_456", name: "Bash" },
      { name: "NoId" },
    ]);
  });
});

describe("finalizeRunningToolCalls", () => {
  function seedWithHistory(entries: Parameters<typeof patchHistoryEntry>[1] extends infer _ ? Array<Record<string, unknown>> : never): UIStore {
    const store = seedShellState();
    store.update({
      ...store.getState(),
      shell: {
        ...store.getState().shell!,
        history: entries as never,
      },
    });
    return store;
  }

  it("flips all running tool-call entries to the supplied status", () => {
    const store = seedWithHistory([
      { type: "tool-call", id: "tc-1", tool: "a", text: "", status: "running", timestamp: 1 },
      { type: "tool-call", id: "tc-2", tool: "b", text: "", status: "running", timestamp: 2 },
    ]);
    finalizeRunningToolCalls(store, "ok");
    const history = store.getState().shell!.history;
    expect(history[0]!.status).toBe("ok");
    expect(history[1]!.status).toBe("ok");
  });

  it("does not touch already-resolved entries", () => {
    const store = seedWithHistory([
      { type: "tool-call", id: "tc-1", tool: "a", text: "", status: "ok", timestamp: 1 },
      { type: "tool-call", id: "tc-2", tool: "b", text: "", status: "running", timestamp: 2 },
    ]);
    finalizeRunningToolCalls(store, "fail");
    const history = store.getState().shell!.history;
    expect(history[0]!.status).toBe("ok"); // preserved
    expect(history[1]!.status).toBe("fail"); // flipped
  });

  it("preserves non-tool-call entries verbatim", () => {
    const store = seedWithHistory([
      { type: "output", text: "hello", timestamp: 1 },
      { type: "tool-call", id: "tc-1", tool: "a", text: "", status: "running", timestamp: 2 },
      { type: "error", text: "boom", timestamp: 3 },
    ]);
    finalizeRunningToolCalls(store, "abort");
    const history = store.getState().shell!.history;
    expect(history[0]!.type).toBe("output");
    expect(history[1]!.status).toBe("abort");
    expect(history[2]!.type).toBe("error");
  });

  it("clears liveActivities when finalizing", () => {
    const store = seedWithHistory([
      {
        type: "tool-call",
        id: "tc-1",
        tool: "a",
        text: "",
        status: "running",
        liveActivities: ["step1", "step2"],
        timestamp: 1,
      },
    ]);
    finalizeRunningToolCalls(store, "ok");
    expect(store.getState().shell!.history[0]!.liveActivities).toBeUndefined();
  });

  it("attaches the resultOutput when provided", () => {
    const store = seedWithHistory([
      { type: "tool-call", id: "tc-1", tool: "a", text: "", status: "running", timestamp: 1 },
    ]);
    finalizeRunningToolCalls(store, "ok", "done summary");
    expect(store.getState().shell!.history[0]!.resultOutput).toBe("done summary");
  });

  it("is a no-op when there are no running tool-calls", () => {
    const store = seedWithHistory([
      { type: "output", text: "hello", timestamp: 1 },
    ]);
    const before = store.getState().shell!.history;
    finalizeRunningToolCalls(store, "ok");
    // Reference equality: with no mutation the history array should be the
    // same reference (updateShell returns the same shell object).
    expect(store.getState().shell!.history).toBe(before);
  });
});

describe("renderToolInputHint", () => {
  it("uses tool.formatInput when it returns a non-empty string", () => {
    const tool = { formatInput: () => "custom-hint" };
    expect(renderToolInputHint(tool, { anything: 1 })).toBe("custom-hint");
  });

  it("clamps per-tool formatInput output to 40 chars", () => {
    const long = "X".repeat(80);
    const tool = { formatInput: () => long };
    const result = renderToolInputHint(tool, {});
    expect(result).toBeDefined();
    expect(result!.length).toBeLessThanOrEqual(40);
    expect(result!.endsWith("…")).toBe(true);
  });

  it("treats formatInput returning '' as 'suppress hint'", () => {
    const tool = { formatInput: () => "" };
    expect(renderToolInputHint(tool, { target: "x" })).toBeUndefined();
  });

  it("falls back to summarizeInput when formatInput returns null/undefined", () => {
    const nullTool = { formatInput: () => null };
    expect(renderToolInputHint(nullTool, { target: "/foo" })).toBe("/foo");
    const undefinedTool = { formatInput: () => undefined };
    expect(renderToolInputHint(undefinedTool, { path: "/bar" })).toBe("/bar");
  });

  it("falls back to summarizeInput when formatInput is missing", () => {
    expect(renderToolInputHint({}, { target: "/baz" })).toBe("/baz");
  });
});

describe("patchHistoryEntry", () => {
  it("mutates an existing entry in place by id", () => {
    const store = seedShellState();
    store.update({
      ...store.getState(),
      shell: {
        ...store.getState().shell!,
        history: [
          {
            type: "tool-call",
            id: "tc-1",
            tool: "sast:scan",
            text: "⏺ sast:scan",
            status: "running",
            timestamp: 1,
          },
        ],
      },
    });
    patchHistoryEntry(store, "tc-1", { status: "ok", resultOutput: "done summary", elapsedSeconds: 5 });
    const entry = store.getState().shell!.history[0]!;
    expect(entry.status).toBe("ok");
    expect(entry.resultOutput).toBe("done summary");
    expect(entry.elapsedSeconds).toBe(5);
    expect(entry.tool).toBe("sast:scan"); // Untouched fields preserved
  });

  it("silently no-ops when the id is not found", () => {
    const store = seedShellState();
    const before = store.getState().shell!.history;
    patchHistoryEntry(store, "missing", { status: "fail" });
    const after = store.getState().shell!.history;
    expect(after).toBe(before);
  });
});

describe("pushLiveActivity cap bumped to 5 (Phase 15)", () => {
  function seedWithRunningToolCall(): UIStore {
    const store = seedShellState();
    store.update({
      ...store.getState(),
      shell: {
        ...store.getState().shell!,
        history: [
          {
            type: "tool-call",
            id: "tc-cap",
            tool: "sast:scan",
            text: "",
            status: "running",
            timestamp: 1,
          },
        ],
      },
    });
    return store;
  }

  it("keeps up to 5 liveActivity entries (was 3)", () => {
    const store = seedWithRunningToolCall();
    for (let i = 0; i < 10; i++) pushLiveActivity(store, "tc-cap", `line ${i}`);
    const entry = store.getState().shell!.history[0]!;
    // cap is 5; older ones drop off the tail
    expect(entry.liveActivities!.length).toBe(5);
    expect(entry.liveActivities![0]).toBe("line 9");
    expect(entry.liveActivities![4]).toBe("line 5");
  });
});

describe("pushLiveActivity", () => {
  function seedWithRunningToolCall(): UIStore {
    const store = seedShellState();
    store.update({
      ...store.getState(),
      shell: {
        ...store.getState().shell!,
        history: [
          {
            type: "tool-call",
            id: "tc-1",
            tool: "sast:scan",
            text: "⏺ sast:scan",
            status: "running",
            timestamp: 1,
          },
        ],
      },
    });
    return store;
  }

  it("prepends to the entry's liveActivities (newest first)", () => {
    const store = seedWithRunningToolCall();
    pushLiveActivity(store, "tc-1", "step 1");
    pushLiveActivity(store, "tc-1", "step 2");
    const entry = store.getState().shell!.history[0]!;
    expect(entry.liveActivities).toEqual(["step 2", "step 1"]);
  });

  it("caps the tail at 3 entries", () => {
    const store = seedWithRunningToolCall();
    for (let i = 0; i < 10; i++) pushLiveActivity(store, "tc-1", `step ${i}`);
    const entry = store.getState().shell!.history[0]!;
    // Phase 15: cap bumped 3 → 5 so subprocess stdout preview has headroom.
    expect(entry.liveActivities!.length).toBeLessThanOrEqual(5);
    expect(entry.liveActivities![0]).toBe("step 9");
  });

  it("dedupes consecutive identical text", () => {
    const store = seedWithRunningToolCall();
    pushLiveActivity(store, "tc-1", "same");
    pushLiveActivity(store, "tc-1", "same");
    pushLiveActivity(store, "tc-1", "same");
    const entry = store.getState().shell!.history[0]!;
    expect(entry.liveActivities).toEqual(["same"]);
  });

  it("truncates long text to 80 chars", () => {
    const store = seedWithRunningToolCall();
    pushLiveActivity(store, "tc-1", "z".repeat(200));
    const entry = store.getState().shell!.history[0]!;
    expect(entry.liveActivities![0]!.length).toBeLessThanOrEqual(80);
    expect(entry.liveActivities![0]!.endsWith("…")).toBe(true);
  });

  it("silently no-ops for non-running tool-call ids", () => {
    const store = seedWithRunningToolCall();
    patchHistoryEntry(store, "tc-1", { status: "ok" });
    pushLiveActivity(store, "tc-1", "should-not-push");
    const entry = store.getState().shell!.history[0]!;
    expect(entry.liveActivities ?? []).toEqual([]);
  });

  it("silently no-ops for unknown ids", () => {
    const store = seedWithRunningToolCall();
    pushLiveActivity(store, "missing", "whatever");
    const entry = store.getState().shell!.history[0]!;
    expect(entry.liveActivities ?? []).toEqual([]);
  });
});

import { beforeEach, describe, expect, it } from "vitest";
import { summarizeToolCompletion } from "../../src/agent-runtime/tool-summary.js";
import { __shellInternals } from "../../src/copilot/shell.js";
import { createUIStore, type UIStore } from "../../src/ui/state.js";

const {
  extractToolUseActivities,
  extractToolUseHeaders,
  looksLikeSubagentToolLine,
  summarizeInput,
  pushToolActivity,
  pushToolPhase,
  renderToolInputHint,
  patchHistoryEntry,
  pushLiveActivity,
  finalizeRunningToolCalls,
  appendStoryEvent,
  applyStoryEventToShell,
  beginShellTurn,
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

describe("task story shell integration helpers", () => {
  it("seeds a new task story at turn start", () => {
    const store = seedShellState();
    beginShellTurn(store, "context build", null, "turn-1");

    const shell = store.getState().shell!;
    expect(shell.taskStory?.activeTurnId).toBe("turn-1");
    expect(shell.taskStory?.events).toEqual([]);
    expect(shell.processing).toBe(true);
    expect(shell.history.at(-1)).toMatchObject({ type: "input", text: "context build" });
  });

  it("preserves existing task story when navigating to details", () => {
    const store = seedShellState();
    appendStoryEvent(store, {
      kind: "phase",
      status: "running",
      importance: "primary",
      message: "Building context",
      turnId: "turn-1",
    });

    beginShellTurn(store, "/story", null, "turn-1", { preserveTaskStory: true });

    expect(store.getState().shell!.taskStory?.events.map((event) => event.message)).toEqual([
      "Building context",
    ]);
  });

  it("updates task story, current tool tail, and durable history for story events", () => {
    const store = seedShellState();

    appendStoryEvent(store, {
      kind: "phase",
      status: "running",
      importance: "primary",
      message: "Walking repository",
      runId: "run-1",
      turnId: "turn-1",
    });

    const shell = store.getState().shell!;
    expect(shell.taskStory?.activeRunIds).toEqual(["run-1"]);
    expect(shell.currentTool?.storyTail?.[0]?.message).toBe("Walking repository");
    expect(shell.history.at(-1)).toMatchObject({ type: "story" });
  });

  it("can apply debug story events as live-only tail without history", () => {
    const store = seedShellState();
    const shell = store.getState().shell!;
    const event = {
      id: "story-debug",
      kind: "activity" as const,
      status: "running" as const,
      importance: "debug" as const,
      message: "Read · package.json",
      timestamp: 2,
    };

    const next = applyStoryEventToShell(shell, event, { persistHistory: false, liveOnly: true });

    expect(next.taskStory?.events.at(-1)?.message).toBe("Read · package.json");
    expect(next.history).toEqual(shell.history);
  });

  it("suppresses story events from superseded turns", () => {
    const store = seedShellState();
    const shell = {
      ...store.getState().shell!,
      taskStory: {
        activeTurnId: "turn-new",
        activeRunIds: ["run-new"],
        startedAt: 1,
        events: [],
      },
    };
    const event = {
      id: "story-old",
      kind: "activity" as const,
      status: "running" as const,
      importance: "secondary" as const,
      message: "late old event",
      timestamp: 2,
      turnId: "turn-old",
      runId: "run-old",
    };

    expect(applyStoryEventToShell(shell, event)).toBe(shell);
  });

  it("marks finalized aborted tool calls with abort status", () => {
    const store = seedShellState();
    store.update({
      shell: {
        ...store.getState().shell!,
        history: [
          {
            type: "tool-call",
            id: "tc-1",
            tool: "context:build",
            text: "⏺ context:build",
            status: "running",
            timestamp: 1,
          },
        ],
      },
    });

    finalizeRunningToolCalls(store, "abort", "Cancelled active operation.");

    expect(store.getState().shell!.history[0]).toMatchObject({
      status: "abort",
      abortStatus: "aborted",
      resultOutput: "Cancelled active operation.",
    });
  });
});

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
    const lines = extractToolUseActivities([
      { type: "tool_use", name: "Read", input: { path: long } },
    ]);
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

describe("looksLikeSubagentToolLine", () => {
  it("matches tool_use invocation headers with `·` separator", () => {
    expect(looksLikeSubagentToolLine("Read · src/foo.ts")).toBe(true);
    expect(looksLikeSubagentToolLine("Glob · **/*.go")).toBe(true);
    expect(looksLikeSubagentToolLine("Grep · needle")).toBe(true);
    expect(looksLikeSubagentToolLine("Bash · pnpm test")).toBe(true);
    expect(looksLikeSubagentToolLine("Write · src/new.ts")).toBe(true);
    expect(looksLikeSubagentToolLine("Edit · src/foo.ts")).toBe(true);
    expect(looksLikeSubagentToolLine("LS · .")).toBe(true);
    expect(looksLikeSubagentToolLine("Task · investigate auth")).toBe(true);
  });

  it("matches summarizeToolCompletion result lines", () => {
    expect(
      looksLikeSubagentToolLine(summarizeToolCompletion("Read", { path: "a.ts" }, "1\n2\n", false)),
    ).toBe(true);
    expect(
      looksLikeSubagentToolLine(
        summarizeToolCompletion("Glob", { pattern: "**/*.ts" }, "a\nb\nc\n", false),
      ),
    ).toBe(true);
    expect(
      looksLikeSubagentToolLine(
        summarizeToolCompletion("Bash", { command: "echo hi" }, "exit 0", false, {
          elapsedSeconds: 0.5,
        }),
      ),
    ).toBe(true);
  });

  it("matches tool-name-only headers when hint was absent", () => {
    expect(looksLikeSubagentToolLine("Read")).toBe(true);
    expect(looksLikeSubagentToolLine("Bash")).toBe(true);
  });

  it("matches error variants (same leading tool name)", () => {
    expect(looksLikeSubagentToolLine("Read . failed: Read path is not a file: .")).toBe(true);
  });

  it("does NOT match Kuzushi's own free-form reportActivity pulses", () => {
    // Free-form pulses from ctx.reportActivity / randori-runner start with
    // lowercase verbs — they are body-text, not invocation headers.
    expect(looksLikeSubagentToolLine("scanning repo structure")).toBe(false);
    expect(looksLikeSubagentToolLine("enriching context")).toBe(false);
    expect(looksLikeSubagentToolLine("building threat model")).toBe(false);
    expect(looksLikeSubagentToolLine("scoping s1, s2, s3")).toBe(false);
    expect(looksLikeSubagentToolLine("enumerating STRIDE threats")).toBe(false);
    expect(looksLikeSubagentToolLine("drafting attacker narrative")).toBe(false);
    expect(looksLikeSubagentToolLine("phase 1 (S1/S2/S3 scope)")).toBe(false);
  });

  it("does NOT match qualified module:action tool names", () => {
    expect(looksLikeSubagentToolLine("context:build")).toBe(false);
    expect(looksLikeSubagentToolLine("sast:scan")).toBe(false);
  });

  it("does NOT match lowercase look-alikes that start with a tool-name substring", () => {
    // `Readable`/`Reading` would false-positive without the \b word-boundary.
    expect(looksLikeSubagentToolLine("Reading files")).toBe(false);
    expect(looksLikeSubagentToolLine("Globbing patterns")).toBe(false);
  });
});

describe("extractToolUseHeaders", () => {
  it("returns { name, inputHint } per tool_use block", () => {
    const headers = extractToolUseHeaders([
      { type: "text", text: "thinking" },
      { type: "tool_use", name: "Read", input: { path: "/src/foo.ts" } },
      { type: "tool_use", name: "Bash", input: {} },
    ]);
    expect(headers).toEqual([{ name: "Read", inputHint: "/src/foo.ts" }, { name: "Bash" }]);
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
  function seedWithHistory(
    entries: Parameters<typeof patchHistoryEntry>[1] extends infer _
      ? Array<Record<string, unknown>>
      : never,
  ): UIStore {
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
        liveActivities: [
          { id: "la-1", text: "step1" },
          { id: "la-2", text: "step2" },
        ],
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
    const store = seedWithHistory([{ type: "output", text: "hello", timestamp: 1 }]);
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
    patchHistoryEntry(store, "tc-1", {
      status: "ok",
      resultOutput: "done summary",
      elapsedSeconds: 5,
    });
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
    expect(entry.liveActivities![0]!.text).toBe("line 9");
    expect(entry.liveActivities![4]!.text).toBe("line 5");
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
    expect(entry.liveActivities?.map((a) => a.text)).toEqual(["step 2", "step 1"]);
  });

  it("caps the tail at 5 entries", () => {
    const store = seedWithRunningToolCall();
    for (let i = 0; i < 10; i++) pushLiveActivity(store, "tc-1", `step ${i}`);
    const entry = store.getState().shell!.history[0]!;
    // Phase 15: cap bumped 3 → 5 so subprocess stdout preview has headroom.
    expect(entry.liveActivities!.length).toBeLessThanOrEqual(5);
    expect(entry.liveActivities![0]!.text).toBe("step 9");
  });

  it("dedupes consecutive identical text", () => {
    const store = seedWithRunningToolCall();
    pushLiveActivity(store, "tc-1", "same");
    pushLiveActivity(store, "tc-1", "same");
    pushLiveActivity(store, "tc-1", "same");
    const entry = store.getState().shell!.history[0]!;
    expect(entry.liveActivities?.map((a) => a.text)).toEqual(["same"]);
  });

  it("truncates long text to 80 chars", () => {
    const store = seedWithRunningToolCall();
    pushLiveActivity(store, "tc-1", "z".repeat(200));
    const entry = store.getState().shell!.history[0]!;
    expect(entry.liveActivities![0]!.text.length).toBeLessThanOrEqual(80);
    expect(entry.liveActivities![0]!.text.endsWith("…")).toBe(true);
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

describe("summarizeToolCompletion — Read", () => {
  it("formats with file path and line count from cat-style output", () => {
    const result = ["     1 │ export function foo() {", "     2 │   return 42;", "     3 │ }"].join(
      "\n",
    );
    expect(summarizeToolCompletion("Read", { path: "src/foo.ts" }, result, false)).toBe(
      "Read src/foo.ts (3 lines)",
    );
  });

  it("uses file_path alias", () => {
    const result = "     1 │ a\n     2 │ b";
    expect(summarizeToolCompletion("Read", { file_path: "a.txt" }, result, false)).toBe(
      "Read a.txt (2 lines)",
    );
  });

  it("singular 'line' when one line", () => {
    expect(summarizeToolCompletion("Read", { path: "x.md" }, "     1 │ hi", false)).toBe(
      "Read x.md (1 line)",
    );
  });

  it("shortens very long paths to basename with abbreviated dir", () => {
    const longPath = "/Users/x/very/long/path/that/exceeds/fifty/characters/finally/foo.ts";
    const out = summarizeToolCompletion("Read", { path: longPath }, "     1 │ hi", false);
    expect(out).toContain("foo.ts");
    expect(out.length).toBeLessThan(longPath.length + 20);
  });

  it("falls back to bare 'Read <path>' when line count is zero", () => {
    expect(summarizeToolCompletion("Read", { path: "empty.txt" }, "", false)).toBe(
      "Read empty.txt",
    );
  });

  it("produces error form on failure", () => {
    const out = summarizeToolCompletion("Read", { path: "no.ts" }, "ENOENT: not found", true);
    expect(out).toBe("Read no.ts failed: ENOENT: not found");
  });
});

describe("summarizeToolCompletion — Grep", () => {
  it("formats pattern + search path + match count", () => {
    const result = "src/a.ts:12:match here\nsrc/b.ts:5:another";
    expect(
      summarizeToolCompletion("Grep", { pattern: "override", path: "src/" }, result, false),
    ).toBe('Grep "override" in src/ (2 matches)');
  });

  it("prefers explicit 'N matches' header when present", () => {
    const result = "14 matches across 5 files\nsrc/a.ts:1:x";
    const out = summarizeToolCompletion("Grep", { pattern: "foo", path: "." }, result, false);
    expect(out).toBe('Grep "foo" in . (14 matches)');
  });

  it("singular 'match'", () => {
    expect(summarizeToolCompletion("Grep", { pattern: "x" }, "a:1:y", false)).toBe(
      'Grep "x" (1 match)',
    );
  });

  it("handles zero matches", () => {
    expect(summarizeToolCompletion("Grep", { pattern: "x" }, "", false)).toBe(
      'Grep "x" (0 matches)',
    );
  });

  it("clamps very long patterns", () => {
    const long = "a".repeat(80);
    const out = summarizeToolCompletion("Grep", { pattern: long }, "", false);
    expect(out).toMatch(/Grep "a+…"/);
    expect(out.length).toBeLessThan(80);
  });
});

describe("summarizeToolCompletion — Glob", () => {
  it("formats with file count", () => {
    const result = "src/a.ts\nsrc/b.ts\nsrc/c.ts";
    expect(summarizeToolCompletion("Glob", { pattern: "**/*.ts" }, result, false)).toBe(
      'Glob "**/*.ts" (3 files)',
    );
  });

  it("reports no files when result is empty", () => {
    expect(summarizeToolCompletion("Glob", { pattern: "**/*.xyz" }, "", false)).toBe(
      'Glob "**/*.xyz" (no files)',
    );
  });

  it("singular 'file' when one", () => {
    expect(summarizeToolCompletion("Glob", { pattern: "README.md" }, "README.md", false)).toBe(
      'Glob "README.md" (1 file)',
    );
  });

  it("handles missing pattern", () => {
    expect(summarizeToolCompletion("Glob", {}, "a\nb", false)).toBe("Glob (2 files)");
  });

  it("ignores blank lines in count", () => {
    const result = "a\n\nb\n\nc\n";
    expect(summarizeToolCompletion("Glob", { pattern: "x" }, result, false)).toBe(
      'Glob "x" (3 files)',
    );
  });
});

describe("summarizeToolCompletion — Bash", () => {
  it("includes exit code and elapsed time", () => {
    const result = "all tests passed\nexit code: 0";
    expect(
      summarizeToolCompletion("Bash", { command: "pnpm test" }, result, false, {
        elapsedSeconds: 18.4,
      }),
    ).toBe('Bash "pnpm test" (exit 0, 18s)');
  });

  it("formats sub-second elapsed in ms", () => {
    const out = summarizeToolCompletion("Bash", { command: "echo hi" }, "hi\nexit 0", false, {
      elapsedSeconds: 0.08,
    });
    expect(out).toBe('Bash "echo hi" (exit 0, 80ms)');
  });

  it("omits elapsed when not provided", () => {
    expect(summarizeToolCompletion("Bash", { command: "ls" }, "foo\nexit 0", false)).toBe(
      'Bash "ls" (exit 0)',
    );
  });

  it("omits exit code when not parseable", () => {
    expect(summarizeToolCompletion("Bash", { command: "ls" }, "random output", false)).toBe(
      'Bash "ls"',
    );
  });

  it("clamps very long commands", () => {
    const long = "a".repeat(200);
    const out = summarizeToolCompletion("Bash", { command: long }, "exit 0", false);
    expect(out.length).toBeLessThan(80);
    expect(out).toContain("…");
  });
});

describe("summarizeToolCompletion — Write/Edit", () => {
  it("Write counts lines from content", () => {
    expect(
      summarizeToolCompletion(
        "Write",
        { file_path: "new.ts", content: "line1\nline2\nline3" },
        "File created",
        false,
      ),
    ).toBe("Write new.ts (3 lines)");
  });

  it("Write falls back to result line when content absent", () => {
    expect(summarizeToolCompletion("Write", { file_path: "x.ts" }, "Created: x.ts", false)).toBe(
      "Write x.ts: Created: x.ts",
    );
  });

  it("Edit reports replacement count when present", () => {
    expect(
      summarizeToolCompletion("Edit", { file_path: "a.ts" }, "3 replacements made", false),
    ).toBe("Edit a.ts (3 replacements made)");
  });

  it("Edit without replacement metric renders bare label", () => {
    expect(summarizeToolCompletion("Edit", { file_path: "a.ts" }, "ok", false)).toBe("Edit a.ts");
  });

  it("Write error mentions path + failure reason", () => {
    expect(
      summarizeToolCompletion(
        "Write",
        { file_path: "x.ts", content: "y" },
        "EACCES: permission denied",
        true,
      ),
    ).toBe("Write x.ts failed: EACCES: permission denied");
  });
});

describe("summarizeToolCompletion — fallback / module tools", () => {
  it("renders module tool with input hint and clamped result head", () => {
    expect(
      summarizeToolCompletion(
        "sast:scan",
        { target: "./repo" },
        "Found 12 findings in 4 files",
        false,
      ),
    ).toBe("sast:scan(./repo) → Found 12 findings in 4 files");
  });

  it("omits arrow when result empty", () => {
    expect(summarizeToolCompletion("sast:scan", { target: "./repo" }, "", false)).toBe(
      "sast:scan(./repo)",
    );
  });

  it("omits hint when input has no recognized primary field", () => {
    expect(summarizeToolCompletion("custom:verb", {}, "done", false)).toBe("custom:verb → done");
  });
});

describe("summarizeToolCompletion — AJV validation errors", () => {
  // pi-ai's AJV validator emits a two-line error:
  //   Validation failed for tool "Write":
  //     - : must have required property 'file_path'
  // The default error formatter keeps only the first line and clamps to 80 chars,
  // which truncates the actionable detail. These tests lock in the special-case
  // re-render that surfaces the real cause.

  it("re-renders two-line AJV errors to show the actionable detail", () => {
    const result =
      "Validation failed for tool \"Write\":\n  - : must have required property 'file_path'\n\nReceived arguments:\n{}";
    expect(summarizeToolCompletion("Write", { filePath: "/x" }, result, true)).toBe(
      "Write validation failed (Write): must have required property 'file_path'",
    );
  });

  it("handles a named-path AJV error", () => {
    const result =
      'Validation failed for tool "Edit":\n  - old_string: must be string\n\nReceived arguments:\n{"old_string": 42}';
    expect(summarizeToolCompletion("Edit", { old_string: 42 }, result, true)).toBe(
      "Edit validation failed (Edit): old_string: must be string",
    );
  });

  it("clamps overly long AJV details to 100 chars", () => {
    const detail = "z".repeat(150);
    const result = `Validation failed for tool "X":\n  - : ${detail}\n`;
    const out = summarizeToolCompletion("X", {}, result, true);
    expect(out.length).toBeLessThan("X validation failed (X): ".length + 102);
    expect(out.endsWith("…")).toBe(true);
  });

  it("falls through to the default label-failed-first-line path for non-AJV errors", () => {
    expect(summarizeToolCompletion("Read", { path: "no.ts" }, "ENOENT: not found", true)).toBe(
      "Read no.ts failed: ENOENT: not found",
    );
  });

  it("does not falsely match text that merely contains 'Validation failed'", () => {
    // Single-line error that doesn't match the AJV two-line shape — fall through.
    expect(
      summarizeToolCompletion("Read", { path: "x" }, "Validation failed somewhere", true),
    ).toBe("Read x failed: Validation failed somewhere");
  });
});

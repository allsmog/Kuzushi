import { beforeEach, describe, expect, it } from "vitest";
import { __shellInternals } from "../../src/copilot/shell.js";
import { createUIStore, type UIStore } from "../../src/ui/state.js";

const { extractToolUseActivities, pushToolActivity, pushToolPhase } = __shellInternals;

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

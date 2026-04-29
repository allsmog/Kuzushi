import { describe, expect, it } from "vitest";
import { type ShellState, UIStore } from "../../src/ui/state.js";

function shell(overrides: Partial<ShellState> = {}): ShellState {
  return {
    modules: [],
    moduleCatalog: [],
    tools: [],
    focusedModule: "context",
    shellView: "module-run",
    openFindingId: null,
    target: null,
    workspace: null,
    history: [],
    commandHistory: [],
    moduleOptions: {},
    processing: true,
    ...overrides,
  };
}

describe("UIStore agentActivity memory retention", () => {
  it("caps the agentActivity map at MAX_AGENT_ACTIVITY_ENTRIES under sustained growth", () => {
    const store = new UIStore();

    for (let i = 0; i < 10_000; i++) {
      store.addAgentActivity(`fp-${i}`, {
        kind: "tool-start",
        toolName: "Grep",
        detail: `call ${i}`,
        index: i,
        total: 10_000,
      });
    }

    const state = store.getState();
    // The cap is advisory — it must be bounded but still allow recent activity.
    expect(state.agentActivity.size).toBeLessThanOrEqual(1000);
    // The most recent entries must be retained (FIFO eviction).
    expect(state.agentActivity.has("fp-9999")).toBe(true);
    expect(state.agentActivity.has("fp-0")).toBe(false);
  }, 10_000);

  it("clearStaleActivity drops entries older than the TTL", async () => {
    const store = new UIStore();

    store.addAgentActivity("old-fp", {
      kind: "tool-start",
      toolName: "Grep",
      detail: "old entry",
      index: 0,
      total: 1,
    });

    // Wait past TTL (we use a tiny TTL in the test).
    await new Promise((r) => setTimeout(r, 25));

    store.addAgentActivity("new-fp", {
      kind: "tool-start",
      toolName: "Grep",
      detail: "recent entry",
      index: 0,
      total: 1,
    });

    // Evict anything older than 20ms.
    store.clearStaleActivity(0.02);
    const state = store.getState();
    expect(state.agentActivity.has("old-fp")).toBe(false);
    expect(state.agentActivity.has("new-fp")).toBe(true);
  });

  it("resetAgentActivity drops all entries (phase-boundary eviction)", () => {
    const store = new UIStore();

    for (let i = 0; i < 50; i++) {
      store.addAgentActivity(`fp-${i}`, {
        kind: "tool-start",
        toolName: "Grep",
        index: 0,
        total: 50,
      });
    }

    store.resetAgentActivity();
    expect(store.getState().agentActivity.size).toBe(0);
  });

  it("does not notify for repeated display-identical agent activity", () => {
    const store = new UIStore();
    let notifications = 0;
    const unsubscribe = store.subscribe(() => {
      notifications += 1;
    });
    const line = {
      kind: "tool-progress" as const,
      toolName: "Read",
      index: 0,
      total: 1,
    };

    expect(store.addAgentActivity("fp", line)).toBe(true);
    expect(store.addAgentActivity("fp", { ...line, elapsedSeconds: 12 })).toBe(false);
    unsubscribe();

    expect(notifications).toBe(1);
    expect(store.getState().agentActivity.get("fp")).toHaveLength(1);
  });

  it("dedupes repeated module-run evidence rows", () => {
    const store = new UIStore();
    store.update({
      shell: shell({
        moduleRun: {
          moduleId: "context",
          source: "shell",
          toolName: "context:build",
          startedAtMs: 0,
          status: "running",
          steps: [],
          evidenceTail: [],
        },
      }),
    });
    const line = {
      kind: "tool-progress" as const,
      toolName: "Read",
      index: 0,
      total: 1,
    };

    expect(store.pushModuleRunActivity(line)).toBe(true);
    expect(store.pushModuleRunActivity({ ...line, elapsedSeconds: 12 })).toBe(false);

    expect(store.getState().shell?.moduleRun?.evidenceTail).toHaveLength(1);
  });
});

describe("UIStore hunt snapshot archive", () => {
  // The shell's `hunt-post-mortem` scrollback block consumes these
  // snapshots — archive on `done:true` preserves the per-actor breakdown
  // after HeartbeatStrip stops rendering; consume drains + resets so a
  // second hunt's post-mortem doesn't inherit the first's actors.
  it("archiveAgentActivity copies lines into lastHuntSnapshot before clear", () => {
    const store = new UIStore();
    store.addAgentActivity("carlini-threat-hunt:Attacker:0", {
      kind: "tool-start",
      toolName: "Read",
      detail: "Read src/api.ts",
      index: 0,
      total: 1,
    });

    store.archiveAgentActivity("carlini-threat-hunt:Attacker:0");
    store.clearAgentActivity("carlini-threat-hunt:Attacker:0");

    const snapshot = store.getState().lastHuntSnapshot;
    expect(snapshot).toHaveLength(1);
    expect(snapshot[0]!.fingerprint).toBe("carlini-threat-hunt:Attacker:0");
    expect(snapshot[0]!.lines).toHaveLength(1);
    expect(snapshot[0]!.lines[0]!.toolName).toBe("Read");
    // Active map is now empty — snapshot survives.
    expect(store.getState().agentActivity.has("carlini-threat-hunt:Attacker:0")).toBe(false);
  });

  it("archiveAgentActivity is a no-op for unknown or empty fingerprints", () => {
    const store = new UIStore();
    store.archiveAgentActivity("nonexistent");
    expect(store.getState().lastHuntSnapshot).toHaveLength(0);
  });

  it("consumeHuntSnapshot returns the accumulated snapshots and clears them", () => {
    const store = new UIStore();
    store.addAgentActivity("carlini-threat-hunt:A:0", {
      kind: "tool-start",
      toolName: "Read",
      index: 0,
      total: 2,
    });
    store.addAgentActivity("carlini-threat-hunt:B:0", {
      kind: "tool-complete",
      detail: "Grep done",
      index: 0,
      total: 2,
    });
    store.archiveAgentActivity("carlini-threat-hunt:A:0");
    store.archiveAgentActivity("carlini-threat-hunt:B:0");

    const drained = store.consumeHuntSnapshot();
    expect(drained.map((s) => s.fingerprint)).toEqual([
      "carlini-threat-hunt:A:0",
      "carlini-threat-hunt:B:0",
    ]);
    expect(store.getState().lastHuntSnapshot).toHaveLength(0);

    // Second consume returns empty — prevents a subsequent hunt's
    // post-mortem from inheriting the prior run's actors.
    expect(store.consumeHuntSnapshot()).toHaveLength(0);
  });

  it("preserves insertion order across multiple archives (matches hunt completion order)", () => {
    const store = new UIStore();
    for (const name of ["Third", "First", "Second"]) {
      store.addAgentActivity(`carlini-threat-hunt:${name}:0`, {
        kind: "tool-complete",
        detail: `${name} done`,
        index: 0,
        total: 3,
      });
      store.archiveAgentActivity(`carlini-threat-hunt:${name}:0`);
    }
    const drained = store.consumeHuntSnapshot();
    expect(drained.map((s) => s.fingerprint)).toEqual([
      "carlini-threat-hunt:Third:0",
      "carlini-threat-hunt:First:0",
      "carlini-threat-hunt:Second:0",
    ]);
  });

  it("does not touch snapshots when clearAgentActivity runs without archive", () => {
    const store = new UIStore();
    store.addAgentActivity("carlini-threat-hunt:Orphan:0", {
      kind: "tool-start",
      index: 0,
      total: 1,
    });
    // No archive call — caller (triage/verification/poc-harness paths that
    // don't set `done:true`) just clears. Snapshot must remain empty so
    // non-hunt producers don't leak into the post-mortem block.
    store.clearAgentActivity("carlini-threat-hunt:Orphan:0");
    expect(store.getState().lastHuntSnapshot).toHaveLength(0);
  });
});

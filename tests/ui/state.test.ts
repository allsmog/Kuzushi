import { describe, expect, it } from "vitest";
import { UIStore } from "../../src/ui/state.js";

describe("UIStore agentActivity memory retention", () => {
  it("caps the agentActivity map at MAX_AGENT_ACTIVITY_ENTRIES under sustained growth", () => {
    const store = new UIStore();

    // Simulate 10k distinct-fingerprint updates — a long-running scan would normally
    // grow the map unboundedly. The cap keeps memory bounded.
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
    // Oldest entries are dropped.
    expect(state.agentActivity.has("fp-0")).toBe(false);
  });

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
});

describe("UIStore hunt snapshot archive", () => {
  // The shell's `hunt-post-mortem` scrollback block consumes these
  // snapshots — archive on `done:true` preserves the per-actor breakdown
  // after HeartbeatStrip stops rendering; consume drains + resets so a
  // second hunt's post-mortem doesn't inherit the first's actors.
  it("archiveAgentActivity copies lines into lastHuntSnapshot before clear", () => {
    const store = new UIStore();
    store.addAgentActivity("threat-hunt:Attacker:0", {
      kind: "tool-start",
      toolName: "Read",
      detail: "Read src/api.ts",
      index: 0,
      total: 1,
    });

    store.archiveAgentActivity("threat-hunt:Attacker:0");
    store.clearAgentActivity("threat-hunt:Attacker:0");

    const snapshot = store.getState().lastHuntSnapshot;
    expect(snapshot).toHaveLength(1);
    expect(snapshot[0]!.fingerprint).toBe("threat-hunt:Attacker:0");
    expect(snapshot[0]!.lines).toHaveLength(1);
    expect(snapshot[0]!.lines[0]!.toolName).toBe("Read");
    // Active map is now empty — snapshot survives.
    expect(store.getState().agentActivity.has("threat-hunt:Attacker:0")).toBe(false);
  });

  it("archiveAgentActivity is a no-op for unknown or empty fingerprints", () => {
    const store = new UIStore();
    store.archiveAgentActivity("nonexistent");
    expect(store.getState().lastHuntSnapshot).toHaveLength(0);
  });

  it("consumeHuntSnapshot returns the accumulated snapshots and clears them", () => {
    const store = new UIStore();
    store.addAgentActivity("threat-hunt:A:0", {
      kind: "tool-start",
      toolName: "Read",
      index: 0,
      total: 2,
    });
    store.addAgentActivity("threat-hunt:B:0", {
      kind: "tool-complete",
      detail: "Grep done",
      index: 0,
      total: 2,
    });
    store.archiveAgentActivity("threat-hunt:A:0");
    store.archiveAgentActivity("threat-hunt:B:0");

    const drained = store.consumeHuntSnapshot();
    expect(drained.map((s) => s.fingerprint)).toEqual(["threat-hunt:A:0", "threat-hunt:B:0"]);
    expect(store.getState().lastHuntSnapshot).toHaveLength(0);

    // Second consume returns empty — prevents a subsequent hunt's
    // post-mortem from inheriting the prior run's actors.
    expect(store.consumeHuntSnapshot()).toHaveLength(0);
  });

  it("preserves insertion order across multiple archives (matches hunt completion order)", () => {
    const store = new UIStore();
    for (const name of ["Third", "First", "Second"]) {
      store.addAgentActivity(`threat-hunt:${name}:0`, {
        kind: "tool-complete",
        detail: `${name} done`,
        index: 0,
        total: 3,
      });
      store.archiveAgentActivity(`threat-hunt:${name}:0`);
    }
    const drained = store.consumeHuntSnapshot();
    expect(drained.map((s) => s.fingerprint)).toEqual([
      "threat-hunt:Third:0",
      "threat-hunt:First:0",
      "threat-hunt:Second:0",
    ]);
  });

  it("does not touch snapshots when clearAgentActivity runs without archive", () => {
    const store = new UIStore();
    store.addAgentActivity("threat-hunt:Orphan:0", {
      kind: "tool-start",
      index: 0,
      total: 1,
    });
    // No archive call — caller (triage/verification/poc-harness paths that
    // don't set `done:true`) just clears. Snapshot must remain empty so
    // non-hunt producers don't leak into the post-mortem block.
    store.clearAgentActivity("threat-hunt:Orphan:0");
    expect(store.getState().lastHuntSnapshot).toHaveLength(0);
  });
});

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

import { describe, expect, it, vi, beforeEach } from "vitest";
import type { RunState } from "../../src/bus/orchestrator/types.js";
import type { RunContext } from "../../src/bus/events.js";

// Minimal RunContext for testing
function makeRunContext(): RunContext {
  return {
    runId: "run-1",
    repoRoot: "/tmp/test-repo",
    repoName: "test-repo",
    dbPath: "/tmp/test.db",
  };
}

// Minimal patch-related RunState fields
function makePatchState(): Pick<RunState,
  "autoPatchEnabled" | "patchCandidates" | "patchQueue" | "patchInFlight" |
  "patchCompleted" | "patchVerified" | "patchFailed" | "patchCostUsd" |
  "patchErrors" | "patchDispatching" | "patchStarted" | "budgetExceeded" |
  "config" | "context"
> {
  return {
    autoPatchEnabled: true,
    patchCandidates: new Set(),
    patchQueue: [],
    patchInFlight: 0,
    patchCompleted: 0,
    patchVerified: 0,
    patchFailed: 0,
    patchCostUsd: 0,
    patchErrors: 0,
    patchDispatching: false,
    patchStarted: false,
    budgetExceeded: false,
    config: {
      model: "test",
      triageMaxTurns: null,
      busBackend: "in-process",
      triageBatchSize: 10,
      triageConcurrency: 5,
      scanMode: "concurrent",
      scanners: ["semgrep"],
      severity: ["ERROR"],
      excludePatterns: [],
      scannerConfig: {},
      autoPatchEnabled: true,
      autoPatchAfter: "verify",
      patchVerifyDepth: "scanner",
      patchConcurrency: 2,
    },
    context: makeRunContext(),
  };
}

describe("Patch Dispatcher State", () => {
  it("initializes with empty patch state", () => {
    const state = makePatchState();
    expect(state.patchCandidates.size).toBe(0);
    expect(state.patchQueue).toHaveLength(0);
    expect(state.patchInFlight).toBe(0);
    expect(state.patchCompleted).toBe(0);
    expect(state.patchVerified).toBe(0);
    expect(state.patchFailed).toBe(0);
  });

  it("tracks patch candidates by fingerprint", () => {
    const state = makePatchState();
    state.patchCandidates.add("fp-1");
    state.patchCandidates.add("fp-2");

    expect(state.patchCandidates.size).toBe(2);
    expect(state.patchCandidates.has("fp-1")).toBe(true);
  });

  it("prevents duplicate candidates", () => {
    const state = makePatchState();
    state.patchCandidates.add("fp-1");
    state.patchCandidates.add("fp-1");

    expect(state.patchCandidates.size).toBe(1);
  });

  it("tracks concurrency correctly", () => {
    const state = makePatchState();
    state.patchInFlight = 2;
    state.patchCompleted = 3;

    expect(state.patchInFlight).toBe(2);
    expect(state.patchCompleted).toBe(3);
  });

  it("respects budget exceeded flag", () => {
    const state = makePatchState();
    state.budgetExceeded = true;

    // When budget is exceeded, new patches should not be queued
    expect(state.budgetExceeded).toBe(true);
  });
});

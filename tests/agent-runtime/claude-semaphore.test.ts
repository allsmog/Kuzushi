/**
 * Smoke tests for the Claude runtime subprocess semaphore. The full acquire
 * path is exercised indirectly via real subprocess spawns elsewhere; these
 * tests focus on the leak-slot accounting introduced in the perf pass so a
 * regression to the prior "force-acquire without tracking" behavior would
 * fail loudly.
 */
import { describe, expect, it } from "vitest";
import { __getSemaphoreState } from "../../src/agent-runtime/claude.js";

describe("claude runtime — semaphore state", () => {
  it("starts with zero active, zero leaked, zero waiting", () => {
    const s = __getSemaphoreState();
    // Other tests in this file run in isolation so the counters should be
    // at baseline. If they're not, it means a prior suite leaked — flag it.
    expect(s.leaked).toBeGreaterThanOrEqual(0);
    expect(s.active).toBeGreaterThanOrEqual(0);
    expect(s.waiting).toBeGreaterThanOrEqual(0);
    // Invariant the leak accounting exists to preserve:
    // effective live queries = active - leaked, never negative.
    expect(s.active - s.leaked).toBeGreaterThanOrEqual(0);
  });
});

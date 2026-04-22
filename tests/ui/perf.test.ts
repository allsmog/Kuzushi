/**
 * Tests for the render-count perf instrumentation.
 *
 * The primitives need to satisfy two contracts:
 *
 *   1. They are a strict no-op when disabled. Forgetting this turns a perf
 *      tool into a perf hazard (we've been bitten by this before).
 *   2. They can be enabled / disabled independently of env vars, so tests
 *      can exercise them without polluting process.env.
 */

import { afterEach, describe, expect, it } from "vitest";
import {
  bumpRenderCount,
  disableRenderCounters,
  enableRenderCounters,
  isRenderCountingEnabled,
  renderCount,
  renderCountsSnapshot,
  resetRenderCounts,
} from "../../src/ui/perf.js";

afterEach(() => {
  disableRenderCounters();
  resetRenderCounts();
});

describe("perf instrumentation", () => {
  it("is disabled by default in tests", () => {
    disableRenderCounters();
    expect(isRenderCountingEnabled()).toBe(false);
  });

  it("is a strict no-op when disabled", () => {
    disableRenderCounters();
    resetRenderCounts();
    bumpRenderCount("ghost");
    bumpRenderCount("ghost");
    expect(renderCount("ghost")).toBe(0);
  });

  it("counts bumps when enabled", () => {
    enableRenderCounters();
    resetRenderCounts();
    bumpRenderCount("CommandInput");
    bumpRenderCount("CommandInput");
    bumpRenderCount("CommandInput");
    expect(renderCount("CommandInput")).toBe(3);
  });

  it("resetRenderCounts clears every counter", () => {
    enableRenderCounters();
    bumpRenderCount("A");
    bumpRenderCount("B");
    resetRenderCounts();
    expect(renderCount("A")).toBe(0);
    expect(renderCount("B")).toBe(0);
  });

  it("snapshot returns a plain object of current counts", () => {
    enableRenderCounters();
    resetRenderCounts();
    bumpRenderCount("X");
    bumpRenderCount("Y");
    bumpRenderCount("Y");
    const snap = renderCountsSnapshot();
    expect(snap).toEqual({ X: 1, Y: 2 });
  });
});

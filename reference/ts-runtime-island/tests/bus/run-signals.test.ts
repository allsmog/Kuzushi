/**
 * Coverage for the per-runId abort-signal registry that bridges
 * `runPipeline` to bus workers so `DagRunContext.signal` can be populated.
 */
import { afterEach, describe, expect, it } from "vitest";
import {
  __clearRunSignalsForTest,
  getRunSignal,
  registerRunSignal,
  unregisterRunSignal,
} from "../../src/bus/run-signals.js";

afterEach(() => {
  __clearRunSignalsForTest();
});

describe("run-signals registry", () => {
  it("returns undefined for unknown runIds", () => {
    expect(getRunSignal("does-not-exist")).toBeUndefined();
  });

  it("round-trips a registered signal", () => {
    const controller = new AbortController();
    registerRunSignal("run-1", controller.signal);
    expect(getRunSignal("run-1")).toBe(controller.signal);
  });

  it("scopes signals per runId — different runs don't collide", () => {
    const c1 = new AbortController();
    const c2 = new AbortController();
    registerRunSignal("run-1", c1.signal);
    registerRunSignal("run-2", c2.signal);
    expect(getRunSignal("run-1")).toBe(c1.signal);
    expect(getRunSignal("run-2")).toBe(c2.signal);
    expect(c1.signal).not.toBe(c2.signal);
  });

  it("forgets the signal on unregister", () => {
    const controller = new AbortController();
    registerRunSignal("run-1", controller.signal);
    expect(getRunSignal("run-1")).toBeDefined();
    unregisterRunSignal("run-1");
    expect(getRunSignal("run-1")).toBeUndefined();
  });

  it("unregister is idempotent", () => {
    unregisterRunSignal("never-registered");
    unregisterRunSignal("never-registered");
    // No throw, no state.
    expect(getRunSignal("never-registered")).toBeUndefined();
  });

  it("preserves abort state — reading after signal.abort() still sees aborted=true", () => {
    // The registry stores the signal by reference, so consumers see the
    // aborted-ness through the same AbortSignal instance runPipeline owns.
    const controller = new AbortController();
    registerRunSignal("run-abort", controller.signal);
    controller.abort();
    const retrieved = getRunSignal("run-abort");
    expect(retrieved?.aborted).toBe(true);
  });

  it("re-registering overwrites the prior signal", () => {
    const c1 = new AbortController();
    const c2 = new AbortController();
    registerRunSignal("run-same", c1.signal);
    registerRunSignal("run-same", c2.signal);
    expect(getRunSignal("run-same")).toBe(c2.signal);
  });
});

/**
 * Coverage for `wireRunAbort` — the per-run AbortController that bridges
 * operator Ctrl+C and fatal `pipeline:error` events into the run-signals
 * registry that downstream dispatchers consult.
 */
import { afterEach, describe, expect, it } from "vitest";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import { createEvent } from "../../src/bus/helpers.js";
import { wireRunAbort } from "../../src/bus/run-abort.js";
import { __clearRunSignalsForTest, getRunSignal } from "../../src/bus/run-signals.js";

afterEach(() => {
  __clearRunSignalsForTest();
});

function makeRunContext(runId: string) {
  return {
    runId,
    repoRoot: "/tmp/repo",
    repoName: "repo",
    dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
  };
}

describe("wireRunAbort", () => {
  it("registers the run's signal so dispatchers can find it", () => {
    const bus = new InProcessBus();
    const runId = "run-register";
    const handle = wireRunAbort(bus, runId, undefined);
    expect(getRunSignal(runId)).toBe(handle.signal);
    expect(handle.signal.aborted).toBe(false);
  });

  it("aborts when the parent signal aborts (operator Ctrl+C path)", () => {
    const bus = new InProcessBus();
    const parent = new AbortController();
    const handle = wireRunAbort(bus, "run-parent", parent.signal);
    expect(handle.signal.aborted).toBe(false);
    parent.abort();
    expect(handle.signal.aborted).toBe(true);
  });

  it("starts already-aborted when the parent signal was aborted before wiring", () => {
    const bus = new InProcessBus();
    const parent = new AbortController();
    parent.abort();
    const handle = wireRunAbort(bus, "run-pre-abort", parent.signal);
    expect(handle.signal.aborted).toBe(true);
  });

  it("aborts when a fatal pipeline:error fires for this runId", async () => {
    const bus = new InProcessBus();
    const runId = "run-fatal";
    const handle = wireRunAbort(bus, runId, undefined);

    await bus.publish(
      createEvent("pipeline:error", runId, {
        context: makeRunContext(runId),
        error: "boom",
        fatal: true,
      }),
    );

    expect(handle.signal.aborted).toBe(true);
  });

  it("ignores non-fatal pipeline:error events", async () => {
    const bus = new InProcessBus();
    const runId = "run-nonfatal";
    const handle = wireRunAbort(bus, runId, undefined);

    await bus.publish(
      createEvent("pipeline:error", runId, {
        context: makeRunContext(runId),
        error: "warning",
        fatal: false,
      }),
    );

    expect(handle.signal.aborted).toBe(false);
  });

  it("ignores fatal pipeline:error from a different runId", async () => {
    const bus = new InProcessBus();
    const runId = "run-mine";
    const handle = wireRunAbort(bus, runId, undefined);

    await bus.publish(
      createEvent("pipeline:error", "some-other-run", {
        context: makeRunContext("some-other-run"),
        error: "not mine",
        fatal: true,
      }),
    );

    expect(handle.signal.aborted).toBe(false);
  });

  it("manual abort() short-circuits without throwing", () => {
    const bus = new InProcessBus();
    const handle = wireRunAbort(bus, "run-manual", undefined);
    handle.abort();
    expect(handle.signal.aborted).toBe(true);
    handle.abort(); // idempotent
    expect(handle.signal.aborted).toBe(true);
  });
});

/**
 * Regression test for v0.21 followup O3 — `Currently waiting on actor N of M
 * — last activity Ys ago`. Verifies the pause hint:
 *   - returns null when activity is fresh,
 *   - returns null when no `tsMs` was stamped (older callers),
 *   - flags the most-stalled actor when several are stalled,
 *   - reports the position 1-indexed and the seconds-since metric.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type ActorRow, computePauseHint } from "../../src/ui/components/ModuleRunView.js";
import type { AgentActivityLine } from "../../src/ui/state.js";

function row(
  fingerprint: string,
  latestKind: "running" | "lastCompleted",
  latest: Partial<AgentActivityLine>,
  status: ActorRow["status"] = "active",
): ActorRow {
  const line: AgentActivityLine = {
    kind: latest.kind ?? "tool-progress",
    index: 0,
    total: 0,
    ...latest,
  };
  return {
    fingerprint,
    shortId: fingerprint.slice(0, 6),
    label: fingerprint,
    status,
    ...(latestKind === "running" ? { running: line } : { lastCompleted: line }),
  };
}

describe("computePauseHint (O3)", () => {
  const NOW = 1_000_000_000_000;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns null when no rows are present", () => {
    expect(computePauseHint([])).toBeNull();
  });

  it("returns null when every actor's latest line lacks tsMs (older callers)", () => {
    expect(
      computePauseHint([row("fp:1", "running", {}), row("fp:2", "lastCompleted", {})]),
    ).toBeNull();
  });

  it("returns null when the latest activity is fresh (under 30s)", () => {
    expect(computePauseHint([row("fp:1", "running", { tsMs: NOW - 10_000 })])).toBeNull();
  });

  it("flags a stalled actor with the seconds-since-last-activity", () => {
    const hint = computePauseHint([
      row("fp:1", "running", { tsMs: NOW - 47_000 }),
      row("fp:2", "running", { tsMs: NOW - 5_000 }),
    ]);
    expect(hint).toBe("Currently waiting on actor 1 of 2 — last activity 47s ago");
  });

  it("picks the MOST stalled when several actors are stalled", () => {
    const hint = computePauseHint([
      row("fp:1", "running", { tsMs: NOW - 35_000 }),
      row("fp:2", "running", { tsMs: NOW - 90_000 }),
      row("fp:3", "running", { tsMs: NOW - 60_000 }),
    ]);
    expect(hint).toBe("Currently waiting on actor 2 of 3 — last activity 90s ago");
  });

  it("uses lastCompleted when no `running` line is present", () => {
    const hint = computePauseHint([
      row("fp:1", "lastCompleted", { kind: "tool-complete", tsMs: NOW - 60_000 }),
    ]);
    expect(hint).toBe("Currently waiting on actor 1 of 1 — last activity 60s ago");
  });
});

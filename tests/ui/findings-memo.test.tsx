/**
 * Memoization / re-render avoidance tests.
 *
 * Ink re-executes every component function on every commit, so `React.memo`
 * + stable props is the primary lever for perf. These tests lock in:
 *
 *   1. `LooseRow` short-circuits when its `finding` reference is unchanged.
 *   2. `FindingsView` re-computes the visible slice without re-running every
 *      row body when the parent re-renders with the same findings array.
 *   3. Incrementing an unrelated state slice (wrapped via a parent container)
 *      does not re-run any `LooseRow` body.
 */

import { PassThrough, type Writable } from "node:stream";
import { Box, render, Text } from "ink";
import { createElement } from "react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FindingsView } from "../../src/ui/components/FindingsView.js";
import {
  disableRenderCounters,
  enableRenderCounters,
  renderCount,
  resetRenderCounts,
} from "../../src/ui/perf.js";
import type { ActionableFinding } from "../../src/ui/state.js";

beforeEach(() => {
  enableRenderCounters();
  resetRenderCounts();
});

afterEach(() => {
  disableRenderCounters();
});

function makeFindings(n: number): ActionableFinding[] {
  const out: ActionableFinding[] = [];
  for (let i = 0; i < n; i++) {
    out.push({
      verdict: "tp",
      confidence: 0.9,
      severity: "high",
      displaySeverity: "high",
      taskId: "sast",
      filePath: `src/mod-${i}.ts`,
      startLine: 10 + i,
      ruleId: `rule-${i}`,
      rationale: `finding ${i}`,
      fingerprint: `fp-${i}`,
      title: `finding ${i}`,
      corroboratingSignals: [],
      suppressionReasons: [],
    } as ActionableFinding);
  }
  return out;
}

function renderTree(element: React.ReactElement): {
  unmount: () => void;
  rerender: (next: React.ReactElement) => void;
} {
  const stream = new PassThrough();
  stream.on("data", () => void 0);
  const instance = render(element, {
    stdout: stream as unknown as Writable & NodeJS.WriteStream,
    debug: true,
  });
  return {
    unmount: () => {
      instance.unmount();
      stream.end();
    },
    rerender: (next) => instance.rerender(next),
  };
}

describe("FindingsView memoization", () => {
  it("does not re-run LooseRow bodies when the findings array reference is stable", () => {
    const findings = makeFindings(30);
    const t = renderTree(createElement(FindingsView, { mode: "unified", findings, pageSize: 50 }));
    const initial = renderCount("LooseRow");
    // Re-render with the same props — LooseRow memo should skip every row.
    t.rerender(createElement(FindingsView, { mode: "unified", findings, pageSize: 50 }));
    expect(renderCount("LooseRow")).toBe(initial);
    t.unmount();
  });

  it("re-runs only the rows whose finding reference actually changed", () => {
    const findings = makeFindings(30);
    const t = renderTree(createElement(FindingsView, { mode: "unified", findings, pageSize: 50 }));
    const initial = renderCount("LooseRow");
    // Swap ONE finding reference; copy the rest so those rows stay memoized.
    const nextFindings = findings.slice();
    nextFindings[5] = { ...findings[5]!, title: "updated title" };
    t.rerender(
      createElement(FindingsView, { mode: "unified", findings: nextFindings, pageSize: 50 }),
    );
    // Only the swapped row should re-run; the other 29 stay memoized.
    expect(renderCount("LooseRow") - initial).toBe(1);
    t.unmount();
  });

  it("moving the cursor within the current window does not re-run visible rows", () => {
    const findings = makeFindings(200);
    const t = renderTree(
      createElement(FindingsView, {
        mode: "unified",
        findings,
        pageSize: 50,
        findingCursor: 10,
      }),
    );
    const initial = renderCount("LooseRow");
    t.rerender(
      createElement(FindingsView, {
        mode: "unified",
        findings,
        pageSize: 50,
        findingCursor: 11,
      }),
    );
    // Cursor moved 1 step inside the existing [0, 50) window → no new rows
    // mount, no row bodies re-run (memoized on `finding` identity).
    expect(renderCount("LooseRow")).toBe(initial);
    t.unmount();
  });

  it("scrolling the cursor past the window renders only the newly visible rows", () => {
    const findings = makeFindings(200);
    const t = renderTree(
      createElement(FindingsView, {
        mode: "unified",
        findings,
        pageSize: 50,
        findingCursor: 0,
      }),
    );
    const initial = renderCount("LooseRow");
    // Scroll cursor from 0 → 100: new window is [51, 101) or so — should
    // only mount `pageSize` rows total at the new window, not 200.
    t.rerender(
      createElement(FindingsView, {
        mode: "unified",
        findings,
        pageSize: 50,
        findingCursor: 100,
      }),
    );
    const delta = renderCount("LooseRow") - initial;
    expect(delta).toBeLessThanOrEqual(50);
    expect(delta).toBeGreaterThan(0);
    t.unmount();
  });

  it("unrelated parent state ticks do not re-run LooseRow bodies", () => {
    const findings = makeFindings(40);

    function Wrapper({ tick }: { tick: number }): React.ReactElement {
      return createElement(
        Box,
        { flexDirection: "column" },
        createElement(Text, null, `unrelated tick: ${tick}`),
        createElement(FindingsView, { mode: "unified", findings, pageSize: 50 }),
      );
    }

    const t = renderTree(createElement(Wrapper, { tick: 0 }));
    const initial = renderCount("LooseRow");
    // Simulate 10 unrelated-state renders (throttle tick, LLM heartbeat, etc).
    for (let i = 1; i <= 10; i++) {
      t.rerender(createElement(Wrapper, { tick: i }));
    }
    // Every row should have been memoized — zero extra row bodies.
    expect(renderCount("LooseRow")).toBe(initial);
    t.unmount();
  });
});

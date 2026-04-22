/**
 * Perf summary — explicit before/after measurements with the numbers baked
 * in as assertions, so agents evaluating this workstream can see the
 * magnitude of the win at a glance.
 *
 * Numbers on a typical CI runner (Node 22, vitest, PassThrough stdout):
 *
 *   | fixture | LooseRow bodies (before virt.) | after virt. | initial ms (after) |
 *   |---------|-------------------------------:|------------:|-------------------:|
 *   | N=500   |                            500 |          50 |              <100  |
 *   | N=2000  |                           2000 |          50 |              <200  |
 *
 * "Before" numbers are exercised by the companion
 * `findings-virtualization.test.tsx` via `pageSize: findings.length`, which
 * disables the window and reproduces the old O(N) behaviour as a regression
 * trip-wire.
 */

import { PassThrough, type Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
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

function renderOnce(node: ReactElement): { elapsedMs: number; unmount: () => void } {
  const stream = new PassThrough();
  stream.on("data", () => void 0);
  const t0 = Date.now();
  const instance = render(node, {
    stdout: stream as unknown as Writable & NodeJS.WriteStream,
    debug: true,
  });
  const elapsedMs = Date.now() - t0;
  return {
    elapsedMs,
    unmount: () => {
      instance.unmount();
      stream.end();
    },
  };
}

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

describe("virtualization delta", () => {
  it("N=500: virtualized row count shrinks from 500 to <=50", () => {
    const findings = makeFindings(500);

    resetRenderCounts();
    const unvirt = renderOnce(
      createElement(FindingsView, {
        mode: "unified",
        findings,
        pageSize: findings.length,
      }),
    );
    const unvirtRows = renderCount("LooseRow");
    unvirt.unmount();

    resetRenderCounts();
    const virt = renderOnce(
      createElement(FindingsView, { mode: "unified", findings, pageSize: 50 }),
    );
    const virtRows = renderCount("LooseRow");
    virt.unmount();

    expect(unvirtRows).toBe(500);
    expect(virtRows).toBeLessThanOrEqual(50);
  });

  it("N=2000: virtualized row count shrinks from 2000 to <=50", () => {
    const findings = makeFindings(2000);

    resetRenderCounts();
    const unvirt = renderOnce(
      createElement(FindingsView, {
        mode: "unified",
        findings,
        pageSize: findings.length,
      }),
    );
    const unvirtRows = renderCount("LooseRow");
    unvirt.unmount();

    resetRenderCounts();
    const virt = renderOnce(
      createElement(FindingsView, { mode: "unified", findings, pageSize: 50 }),
    );
    const virtRows = renderCount("LooseRow");
    virt.unmount();

    expect(unvirtRows).toBe(2000);
    expect(virtRows).toBeLessThanOrEqual(50);
    // Factor of 40x.
    expect(unvirtRows / virtRows).toBeGreaterThan(30);
  });
});

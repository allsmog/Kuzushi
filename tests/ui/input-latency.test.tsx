/**
 * Input-latency lock-ins.
 *
 * Before virtualization + memoization, typing a single character into the
 * shell's command input re-rendered every finding row in the findings
 * view. On a 500-finding list that was ~1000 row updates per keystroke.
 *
 * These tests simulate a typical "findings list is mounted, user is
 * typing" scenario and assert that character-level parent re-renders do
 * NOT fan out into the findings subtree.
 */

import { PassThrough, type Writable } from "node:stream";
import { Box, render, Text } from "ink";
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
      rationale: `synthetic ${i}`,
      fingerprint: `fp-${i}`,
      title: `finding ${i}`,
      corroboratingSignals: [],
      suppressionReasons: [],
    } as ActionableFinding);
  }
  return out;
}

function renderTree(node: ReactElement): {
  unmount: () => void;
  rerender: (next: ReactElement) => void;
} {
  const stream = new PassThrough();
  stream.on("data", () => void 0);
  const instance = render(node, {
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

describe("typing doesn't re-render findings rows", () => {
  it("10 keystrokes with a 500-finding list mounted: zero extra LooseRow bodies", () => {
    const findings = makeFindings(500);

    function Shell({ input }: { input: string }): ReactElement {
      return createElement(
        Box,
        { flexDirection: "column" },
        // Stand-in for the command input prompt line — re-renders on every
        // keystroke, like the real `CommandInput`/shell prompt.
        createElement(Text, null, `> ${input}`),
        // The heavy subtree. Props are stable across keystrokes, so memoed
        // rows should not re-run.
        createElement(FindingsView, { mode: "unified", findings, pageSize: 50 }),
      );
    }

    const t = renderTree(createElement(Shell, { input: "" }));
    const baseline = renderCount("LooseRow");

    // Type 10 characters, one re-render each.
    const chars = "hello world".split("");
    let buf = "";
    for (const ch of chars) {
      buf += ch;
      t.rerender(createElement(Shell, { input: buf }));
    }

    // Every row in the window memoized, so no additional body runs.
    expect(renderCount("LooseRow")).toBe(baseline);
    t.unmount();
  });

  it("rapid keystrokes keep FindingsView body re-runs independent of findings.length", () => {
    const small = makeFindings(20);
    const large = makeFindings(2000);

    function Shell({
      findings,
      input,
    }: {
      findings: ActionableFinding[];
      input: string;
    }): ReactElement {
      return createElement(
        Box,
        { flexDirection: "column" },
        createElement(Text, null, `> ${input}`),
        createElement(FindingsView, { mode: "unified", findings, pageSize: 50 }),
      );
    }

    // Warm-up: baseline for small list
    resetRenderCounts();
    const smallTree = renderTree(createElement(Shell, { findings: small, input: "" }));
    const smallInitial = renderCount("FindingsView");
    for (let i = 0; i < 20; i++) {
      smallTree.rerender(createElement(Shell, { findings: small, input: "x".repeat(i) }));
    }
    const smallDelta = renderCount("FindingsView") - smallInitial;
    smallTree.unmount();

    // Same scenario, bigger findings list.
    resetRenderCounts();
    const largeTree = renderTree(createElement(Shell, { findings: large, input: "" }));
    const largeInitial = renderCount("FindingsView");
    for (let i = 0; i < 20; i++) {
      largeTree.rerender(createElement(Shell, { findings: large, input: "x".repeat(i) }));
    }
    const largeDelta = renderCount("FindingsView") - largeInitial;
    largeTree.unmount();

    // Per-keystroke FindingsView body runs should not scale with list size.
    // (Allow a small slop in either direction for React/Ink overhead.)
    expect(Math.abs(largeDelta - smallDelta)).toBeLessThanOrEqual(2);
  });

  it("20 keystrokes with 2000-finding list: total LooseRow body executions bounded", () => {
    const findings = makeFindings(2000);

    function Shell({ input }: { input: string }): ReactElement {
      return createElement(
        Box,
        { flexDirection: "column" },
        createElement(Text, null, `> ${input}`),
        createElement(FindingsView, { mode: "unified", findings, pageSize: 50 }),
      );
    }

    const t = renderTree(createElement(Shell, { input: "" }));
    const initial = renderCount("LooseRow");

    for (let i = 0; i < 20; i++) {
      t.rerender(createElement(Shell, { input: "x".repeat(i + 1) }));
    }

    const total = renderCount("LooseRow");
    // Without memo this would be initial + 20 * 50 = 1050+.
    // With memo + stable props the rows should all short-circuit.
    expect(total - initial).toBeLessThanOrEqual(5);
    t.unmount();
  });
});

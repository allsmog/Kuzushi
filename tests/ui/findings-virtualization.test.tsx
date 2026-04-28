/**
 * Virtualization perf tests for the unified `FindingsView`.
 *
 * The unified findings screen used to render every loose finding on every
 * parent re-render. For a 2000-finding fixture that meant 2000 `LooseRow`
 * function bodies every time the shell store pushed an update (throttle
 * tick, LLM heartbeat, keystroke). These tests lock in the windowed
 * slice so regressions are caught immediately.
 *
 * Render-count measurement uses the `perf.ts` gate — enabled per-test so
 * production builds stay zero-cost.
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

function renderHeadless(node: ReactElement): { unmount: () => void; output: string } {
  const stream = new PassThrough();
  const chunks: Buffer[] = [];
  stream.on("data", (chunk: Buffer) => chunks.push(chunk));
  const instance = render(node, {
    stdout: stream as unknown as Writable & NodeJS.WriteStream,
    debug: true,
  });
  return {
    unmount: () => {
      instance.unmount();
      stream.end();
    },
    get output() {
      return Buffer.concat(chunks).toString("utf-8");
    },
  };
}

function makeFindings(n: number): ActionableFinding[] {
  const out: ActionableFinding[] = [];
  const severities: Array<"critical" | "high" | "medium" | "low"> = [
    "critical",
    "high",
    "medium",
    "low",
  ];
  for (let i = 0; i < n; i++) {
    out.push({
      verdict: "tp",
      confidence: 0.9,
      severity: severities[i % severities.length]!,
      displaySeverity: severities[i % severities.length]!,
      taskId: "sast",
      filePath: `src/mod-${i}.ts`,
      startLine: 10 + i,
      ruleId: `rule-${i}`,
      rationale: `synthetic finding ${i}`,
      fingerprint: `fp-${i.toString().padStart(6, "0")}`,
      title: `finding ${i}`,
      corroboratingSignals: [],
      suppressionReasons: [],
    } as ActionableFinding);
  }
  return out;
}

describe("FindingsView virtualization", () => {
  it("renders only a windowed slice of LooseRow for a 2000-finding list", () => {
    const findings = makeFindings(2000);
    const instance = renderHeadless(
      createElement(FindingsView, { mode: "unified", findings, pageSize: 50 }),
    );
    // One ∘ initial commit: LooseRow body should fire ~pageSize times, not 2000.
    expect(renderCount("LooseRow")).toBeLessThanOrEqual(50);
    expect(renderCount("LooseRow")).toBeGreaterThan(0);
    instance.unmount();
  });

  it("finishes a 2000-finding initial render well under the un-virtualized baseline", () => {
    const findings = makeFindings(2000);
    const t0 = Date.now();
    const instance = renderHeadless(
      createElement(FindingsView, { mode: "unified", findings, pageSize: 50 }),
    );
    const elapsed = Date.now() - t0;
    // Regression sentinel rather than a tight perf assertion: without
    // virtualization this fixture was 600ms+, so anything below 500ms
    // proves the windowing path is engaged. The render-count test above
    // already pins the intent (≤ pageSize LooseRow bodies); this one just
    // catches a structural regression that defeats virtualization without
    // flaking when the wider test suite runs in parallel and steals CPU.
    expect(elapsed).toBeLessThan(500);
    instance.unmount();
  });

  it("renders the cursor neighborhood when cursor points deep into the list", () => {
    // Use uniform severity so the displayed order matches the input order
    // and the cursor index points at a predictable `finding N`.
    const findings: ActionableFinding[] = [];
    for (let i = 0; i < 500; i++) {
      findings.push({
        verdict: "tp",
        confidence: 0.9,
        severity: "high",
        displaySeverity: "high",
        taskId: "sast",
        filePath: `src/mod-${i}.ts`,
        startLine: 10 + i,
        ruleId: `rule-${i}`,
        rationale: `synthetic finding ${i}`,
        fingerprint: `fp-${i.toString().padStart(6, "0")}`,
        title: `finding ${i}`,
        corroboratingSignals: [],
        suppressionReasons: [],
      } as ActionableFinding);
    }
    const instance = renderHeadless(
      createElement(FindingsView, {
        mode: "unified",
        findings,
        pageSize: 20,
        findingCursor: 250,
      }),
    );
    const text = instance.output;
    // Window should contain rows near index 250, not rows near index 0.
    expect(text).toContain("finding 250");
    expect(text).not.toContain("finding 10 ");
    // Hidden-above hint is rendered.
    expect(text).toMatch(/more above/);
    instance.unmount();
  });

  it("does not render hint rows when findings fit in one page", () => {
    const findings = makeFindings(10);
    const instance = renderHeadless(
      createElement(FindingsView, { mode: "unified", findings, pageSize: 50 }),
    );
    // Every finding body should render since the window covers the whole list.
    expect(renderCount("LooseRow")).toBe(10);
    const text = instance.output;
    expect(text).not.toMatch(/more above/);
    expect(text).not.toMatch(/more below/);
    instance.unmount();
  });

  it("500-finding initial render stays in the windowed regime", () => {
    const findings = makeFindings(500);
    const t0 = Date.now();
    const instance = renderHeadless(
      createElement(FindingsView, { mode: "unified", findings, pageSize: 50 }),
    );
    const elapsed = Date.now() - t0;
    expect(renderCount("LooseRow")).toBeLessThanOrEqual(50);
    // Same rationale as the 2000-row test: hold the budget loose enough
    // that we don't flake under parallel load while still catching a
    // structural regression that drops virtualization.
    expect(elapsed).toBeLessThan(400);
    instance.unmount();
  });
});

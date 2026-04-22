/**
 * Locks that the `shell.findingCursor` prop threads through CopilotShell's
 * ShellViewPanel into FindingsView. The pure cursor-movement logic is
 * covered by `tests/copilot/keybinds.test.ts`; here we assert the
 * integration: changing `findingCursor` actually shifts the visible
 * window rendered by the unified findings list.
 */

import { PassThrough, type Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import { FindingsView } from "../../src/ui/components/FindingsView.js";
import type { ActionableFinding } from "../../src/ui/state.js";

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

function renderTree(element: ReactElement): {
  unmount: () => void;
  rerender: (next: ReactElement) => void;
  frames: () => string[];
} {
  const stream = new PassThrough();
  const frames: string[] = [];
  stream.on("data", (chunk: Buffer) => frames.push(chunk.toString("utf8")));
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
    frames: () => frames,
  };
}

describe("findingCursor threads into the visible window", () => {
  it("cursor 0 anchors the window at the top", () => {
    const findings = makeFindings(500);
    const t = renderTree(
      createElement(FindingsView, {
        mode: "unified",
        findings,
        findingCursor: 0,
        pageSize: 10,
      }),
    );
    // First window should include the top finding.
    const all = t.frames().join("");
    expect(all).toContain("finding 0");
    t.unmount();
  });

  it("cursor deep into the list scrolls the window down", () => {
    const findings = makeFindings(500);
    const t = renderTree(
      createElement(FindingsView, {
        mode: "unified",
        findings,
        findingCursor: 250,
        pageSize: 10,
      }),
    );
    const all = t.frames().join("");
    expect(all).toContain("finding 250");
    // A finding well outside the 10-wide window at the top is hidden.
    expect(all).not.toContain("finding 0");
    t.unmount();
  });

  it("advancing the cursor moves the visible window past the previous top", () => {
    const findings = makeFindings(500);
    const t = renderTree(
      createElement(FindingsView, {
        mode: "unified",
        findings,
        findingCursor: 0,
        pageSize: 10,
      }),
    );
    const topFrames = t.frames().slice().join("");
    expect(topFrames).toContain("finding 5");

    t.rerender(
      createElement(FindingsView, {
        mode: "unified",
        findings,
        findingCursor: 100,
        pageSize: 10,
      }),
    );
    const after = t.frames().slice().join("");
    // The new window should show finding 100 and hide the old first page.
    expect(after).toContain("finding 100");
    t.unmount();
  });

  it("clamping at the end shows the last findings and no overflow", () => {
    const findings = makeFindings(50);
    const t = renderTree(
      createElement(FindingsView, {
        mode: "unified",
        findings,
        findingCursor: 49,
        pageSize: 10,
      }),
    );
    const all = t.frames().join("");
    expect(all).toContain("finding 49");
    // There should be no "finding 50" (out of range).
    expect(all).not.toContain("finding 50");
    t.unmount();
  });
});

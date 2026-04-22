/**
 * ShellFooterHints tests — greedy-fit at narrow widths, dot-separator
 * collapse, and the pure `fitHints` helper.
 */

import { PassThrough, type Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import {
  fitHints,
  ShellFooterHints,
  type ShellHint,
} from "../../src/ui/components/ShellFooterHints.js";

// biome-ignore lint/suspicious/noControlCharactersInRegex: strip ANSI for assertions
const ANSI_RE = /\[[0-9;]*[a-zA-Z]/g;

function stripAnsi(s: string): string {
  return s.replace(ANSI_RE, "");
}

function renderToText(node: ReactElement, columns = 120): string {
  const stream = new PassThrough() as unknown as Writable & NodeJS.WriteStream;
  (stream as unknown as { columns: number }).columns = columns;
  (stream as unknown as { rows: number }).rows = 24;
  const chunks: Buffer[] = [];
  (stream as unknown as PassThrough).on("data", (chunk: Buffer) => chunks.push(chunk));
  const instance = render(node, { stdout: stream, debug: true });
  instance.unmount();
  (stream as unknown as PassThrough).end();
  return stripAnsi(Buffer.concat(chunks).toString("utf-8")).trimEnd();
}

const CANONICAL_HINTS: ShellHint[] = [
  { key: "j/k", label: "scroll" },
  { key: "enter", label: "open" },
  { key: "/back", label: "" },
  { key: "/help", label: "more" },
];

describe("fitHints", () => {
  it("fits everything when budget is generous", () => {
    const { rendered, overflowed } = fitHints(CANONICAL_HINTS, 200, false);
    expect(rendered.length).toBe(4);
    expect(overflowed).toBe(false);
  });

  it("drops trailing hints when budget overflows", () => {
    const { rendered, overflowed } = fitHints(CANONICAL_HINTS, 20, false);
    expect(rendered.length).toBeLessThan(CANONICAL_HINTS.length);
    expect(overflowed).toBe(true);
  });

  it("drops labels under tiny terminals (dropLabels=true)", () => {
    const { rendered } = fitHints(CANONICAL_HINTS, 200, true);
    for (const r of rendered) {
      expect(r.label).toBe("");
    }
  });

  it("first hint always renders even with tight budget", () => {
    const { rendered, overflowed } = fitHints(CANONICAL_HINTS, 12, false);
    expect(rendered.length).toBeGreaterThanOrEqual(1);
    expect(rendered[0]?.key).toBe("j/k");
    expect(overflowed).toBe(true);
  });

  it("returns zero hints but no overflow when input is empty", () => {
    const { rendered, overflowed } = fitHints([], 80, false);
    expect(rendered.length).toBe(0);
    expect(overflowed).toBe(false);
  });
});

describe("ShellFooterHints rendering", () => {
  it("renders all hints at a wide terminal", () => {
    const out = renderToText(
      createElement(ShellFooterHints, { hints: CANONICAL_HINTS }),
      120,
    );
    expect(out).toContain("j/k");
    expect(out).toContain("scroll");
    expect(out).toContain("enter");
    expect(out).toContain("/back");
    expect(out).toContain("/help");
  });

  it("uses · as the separator between hints", () => {
    const out = renderToText(
      createElement(ShellFooterHints, { hints: CANONICAL_HINTS, divider: false }),
      120,
    );
    // At least one · between hint pieces
    expect(out).toContain("·");
  });

  it("collapses to … on tight widths rather than wrapping", () => {
    // Use longer key names so that even with labels dropped, the bar still
    // overflows the tiny terminal's budget and must ellipsis-truncate.
    const many: ShellHint[] = [
      { key: "alpha-key", label: "a" },
      { key: "beta-key", label: "b" },
      { key: "gamma-key", label: "c" },
      { key: "delta-key", label: "d" },
      { key: "epsilon-key", label: "e" },
      { key: "zeta-key", label: "f" },
      { key: "eta-key", label: "g" },
    ];
    const out = renderToText(
      createElement(ShellFooterHints, { hints: many, divider: false }),
      40,
    );
    expect(out).toContain("…");
  });

  it("renders empty when given no hints", () => {
    const out = renderToText(
      createElement(ShellFooterHints, { hints: [] }),
      80,
    );
    // Empty hints shouldn't produce meaningful content (no · separator).
    expect(out.trim()).toBe("");
  });

  it("omits divider when divider=false", () => {
    const withDiv = renderToText(
      createElement(ShellFooterHints, { hints: CANONICAL_HINTS, divider: true }),
      120,
    );
    const withoutDiv = renderToText(
      createElement(ShellFooterHints, { hints: CANONICAL_HINTS, divider: false }),
      120,
    );
    expect(withDiv).toContain("─");
    expect(withoutDiv.includes("─")).toBe(false);
  });
});

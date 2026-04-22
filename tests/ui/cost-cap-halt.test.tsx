/**
 * CostCapHalt tests — verify the tightened copy: spent-of-cap math,
 * over-budget delta, both keybinds with their semantics.
 */

import { PassThrough, type Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import { CostCapHalt } from "../../src/ui/components/CostCapHalt.js";

// biome-ignore lint/suspicious/noControlCharactersInRegex: strip ANSI for assertions
const ANSI_RE = /\[[0-9;]*[a-zA-Z]/g;

function renderToText(node: ReactElement, columns = 120): string {
  const stream = new PassThrough() as unknown as Writable & NodeJS.WriteStream;
  (stream as unknown as { columns: number }).columns = columns;
  (stream as unknown as { rows: number }).rows = 24;
  const chunks: Buffer[] = [];
  (stream as unknown as PassThrough).on("data", (chunk: Buffer) => chunks.push(chunk));
  const instance = render(node, { stdout: stream, debug: true });
  instance.unmount();
  (stream as unknown as PassThrough).end();
  return Buffer.concat(chunks).toString("utf-8").replace(ANSI_RE, "").trimEnd();
}

describe("CostCapHalt", () => {
  it("renders the BUDGET EXCEEDED header", () => {
    const out = renderToText(
      createElement(CostCapHalt, { runningCostUsd: 5.5, budgetUsd: 5.0 }),
    );
    expect(out).toContain("BUDGET EXCEEDED");
  });

  it("shows spent vs cap and the over-budget delta", () => {
    const out = renderToText(
      createElement(CostCapHalt, { runningCostUsd: 7.5, budgetUsd: 5.0 }),
    );
    expect(out).toContain("$7.50");
    expect(out).toContain("$5.00");
    expect(out).toContain("+$2.50");
  });

  it("renders a percent-of-cap hint when budget is set", () => {
    const out = renderToText(
      createElement(CostCapHalt, { runningCostUsd: 6.0, budgetUsd: 5.0 }),
    );
    // 6 / 5 = 120%
    expect(out).toContain("120%");
  });

  it("handles missing budget without crashing", () => {
    const out = renderToText(createElement(CostCapHalt, { runningCostUsd: 9.99 }));
    expect(out).toContain("$9.99");
    expect(out).toContain("no cap set");
  });

  it("renders both the c and a keybinds with their semantics", () => {
    const out = renderToText(
      createElement(CostCapHalt, { runningCostUsd: 5.5, budgetUsd: 5.0 }),
    );
    expect(out).toMatch(/press\s+c/);
    expect(out).toContain("continue");
    expect(out).toContain("bypass cap");
    expect(out).toContain("a");
    expect(out).toContain("abort");
  });

  it("hints that the cap resets next run", () => {
    const out = renderToText(
      createElement(CostCapHalt, { runningCostUsd: 5.5, budgetUsd: 5.0 }),
    );
    expect(out).toMatch(/next run|--budget/);
  });

  it("clamps negative over-delta to zero (runningCost < cap somehow)", () => {
    const out = renderToText(
      createElement(CostCapHalt, { runningCostUsd: 3.0, budgetUsd: 5.0 }),
    );
    expect(out).toContain("+$0.00");
  });
});

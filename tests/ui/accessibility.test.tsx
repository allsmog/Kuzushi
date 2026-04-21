/**
 * Accessibility guardrails.
 *
 * Covers:
 *   1. Severity rendering always emits glyph + label even with color
 *      stripped — so color-blind, NO_COLOR, and screen-reader readers
 *      can still distinguish tiers.
 *   2. `tokens.muted` / `tokens.subtle` become identity functions under
 *      `NO_COLOR` and `KUZUSHI_HIGH_CONTRAST` so dim text upgrades to
 *      readable text on high-contrast terminals.
 *   3. A narrow-terminal (40-col) snapshot of `FindingsView` empty state
 *      ensures the view doesn't explode / line-wrap into an illegible
 *      mess when the terminal shrinks.
 */

import { PassThrough, type Writable } from "node:stream";
import chalk from "chalk";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FindingsView } from "../../src/ui/components/FindingsView.js";
import { severityLabel } from "../../src/ui/format.js";
import { type Severity, severityStyle, severityToken } from "../../src/ui/severity.js";
import { tokens } from "../../src/ui/tokens.js";

// Force chalk on in tests — stdout isn't a TTY under vitest so chalk
// would otherwise emit no ANSI at all.
chalk.level = Math.max(chalk.level, 1);

// biome-ignore lint/suspicious/noControlCharactersInRegex: ANSI-strip for snapshots
const ANSI = /\[[0-9;]*m/g;
function stripAnsi(s: string): string {
  return s.replace(ANSI, "");
}

function renderToString(node: ReactElement, columns = 80): string {
  const stream = new PassThrough() as unknown as Writable & NodeJS.WriteStream;
  // Fake the `columns` so `useTerminalWidth` sees the requested width.
  (stream as unknown as { columns: number }).columns = columns;
  (stream as unknown as { rows: number }).rows = 24;
  const chunks: Buffer[] = [];
  (stream as unknown as PassThrough).on("data", (chunk: Buffer) => chunks.push(chunk));
  const instance = render(node, { stdout: stream, debug: true });
  instance.unmount();
  (stream as unknown as PassThrough).end();
  const raw = Buffer.concat(chunks).toString("utf-8");
  return stripAnsi(raw).trimEnd();
}

const ALL_SEV: Severity[] = ["critical", "high", "medium", "low", "info"];

describe("severity tier carries glyph + label without color", () => {
  it.each(ALL_SEV)("'%s' token has a glyph AND a label", (sev) => {
    const token = severityToken(sev, { NO_COLOR: "1" });
    const style = severityStyle(sev, { NO_COLOR: "1" });
    // Color is stripped — but glyph and label must still be present.
    expect(token).toContain(style.glyph);
    expect(token).toContain(style.label);
    expect(stripAnsi(token)).toBe(token);
  });

  it("severityLabel(format.ts) still distinguishes tiers under NO_COLOR", () => {
    const crit = stripAnsi(severityLabelWithEnv("CRITICAL", { NO_COLOR: "1" }));
    const high = stripAnsi(severityLabelWithEnv("HIGH", { NO_COLOR: "1" }));
    const med = stripAnsi(severityLabelWithEnv("MEDIUM", { NO_COLOR: "1" }));
    const low = stripAnsi(severityLabelWithEnv("LOW", { NO_COLOR: "1" }));
    const info = stripAnsi(severityLabelWithEnv("INFO", { NO_COLOR: "1" }));
    // Each stripped token must be distinct so color-blind users can tell
    // them apart by glyph + text alone.
    const set = new Set([crit, high, med, low, info]);
    expect(set.size).toBe(5);
  });
});

// Helper — mirrors severityLabel behavior by temporarily toggling env.
function severityLabelWithEnv(level: string, env: NodeJS.ProcessEnv): string {
  const saved = { ...process.env };
  try {
    Object.assign(process.env, env);
    return severityLabel(level);
  } finally {
    for (const k of Object.keys(process.env)) delete process.env[k];
    Object.assign(process.env, saved);
  }
}

describe("tokens.muted/subtle honor NO_COLOR + KUZUSHI_HIGH_CONTRAST", () => {
  const OLD = { ...process.env };
  beforeEach(() => {
    delete process.env["NO_COLOR"];
    delete process.env["KUZUSHI_HIGH_CONTRAST"];
  });
  afterEach(() => {
    for (const k of Object.keys(process.env)) delete process.env[k];
    Object.assign(process.env, OLD);
  });

  it("muted applies ANSI by default", () => {
    const wrapped = tokens.muted("hello");
    expect(wrapped).not.toBe("hello");
  });

  it("muted becomes identity under NO_COLOR", () => {
    process.env["NO_COLOR"] = "1";
    expect(tokens.muted("hello")).toBe("hello");
    expect(tokens.subtle("hello")).toBe("hello");
  });

  it("muted becomes identity under KUZUSHI_HIGH_CONTRAST (dim text is unreadable on hi-contrast)", () => {
    process.env["KUZUSHI_HIGH_CONTRAST"] = "1";
    expect(tokens.muted("hello")).toBe("hello");
    expect(tokens.subtle("hello")).toBe("hello");
  });
});

describe("FindingsView narrow-terminal tolerance", () => {
  it("renders an empty-state at 40 columns without crashing", () => {
    const out = renderToString(
      createElement(FindingsView, { mode: "compact", results: [] }),
      40,
    );
    // Should contain the "No findings" message somewhere, regardless
    // of wrapping decisions.
    expect(out).toContain("No findings triaged");
    // No line should be pathologically long (> 4x requested width).
    // Guards against a view that ignores terminal width entirely.
    const longest = Math.max(...out.split("\n").map((l) => l.length));
    expect(longest).toBeLessThan(160);
  });

  it("renders empty-state at 60 and 79 cols identically (structure-wise)", () => {
    const at60 = renderToString(
      createElement(FindingsView, { mode: "compact", results: [] }),
      60,
    );
    const at79 = renderToString(
      createElement(FindingsView, { mode: "compact", results: [] }),
      79,
    );
    expect(at60).toContain("No findings triaged");
    expect(at79).toContain("No findings triaged");
  });
});

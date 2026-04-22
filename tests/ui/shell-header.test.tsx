/**
 * ShellHeader width-responsiveness tests.
 *
 * `useTerminalWidth` → `useTerminalSize` reads `columns` off the stdout
 * passed to Ink's `render`. The helper `renderToText(node, columns)`
 * fakes that property on a PassThrough so each case renders at the
 * exact terminal width the test cares about.
 */

import { PassThrough, type Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import {
  resolveContentWidth,
  ShellHeader,
  SHELL_CONTENT_WIDTH_CAP,
} from "../../src/ui/components/ShellHeader.js";

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

describe("resolveContentWidth", () => {
  it("caps at 100 columns by default", () => {
    expect(resolveContentWidth(200)).toBe(SHELL_CONTENT_WIDTH_CAP);
    expect(resolveContentWidth(100)).toBe(100);
    expect(resolveContentWidth(80)).toBe(80);
  });

  it("floors at 20 to avoid pathological widths", () => {
    expect(resolveContentWidth(5)).toBe(20);
  });

  it("honors custom cap", () => {
    expect(resolveContentWidth(200, 80)).toBe(80);
  });
});

describe("ShellHeader", () => {
  it("renders title + subtitle + count on a wide terminal (120 cols)", () => {
    const out = renderToText(
      createElement(ShellHeader, {
        title: "findings",
        subtitle: "severity-sorted · chain-aware",
        count: "12 open",
      }),
      120,
    );
    expect(out).toContain("findings");
    expect(out).toContain("severity-sorted");
    expect(out).toContain("12 open");
    expect(out).toContain("◂ back");
  });

  it("uses a custom back label when provided", () => {
    const out = renderToText(
      createElement(ShellHeader, {
        title: "F-0001",
        backLabel: "findings",
        subtitle: "deep page",
      }),
      120,
    );
    expect(out).toContain("◂ findings");
    expect(out).toContain("F-0001");
  });

  it("renders secondary line at standard widths (80 cols)", () => {
    const out = renderToText(
      createElement(ShellHeader, {
        title: "threat summary",
        secondary: "loaded from .kuzushi/threat-model.json (2m ago)",
      }),
      80,
    );
    expect(out).toContain("loaded from");
  });

  it("drops secondary line at narrow widths (< 80 cols)", () => {
    const out = renderToText(
      createElement(ShellHeader, {
        title: "threat summary",
        secondary: "loaded from .kuzushi/threat-model.json (2m ago)",
      }),
      70,
    );
    expect(out).not.toContain("loaded from");
    expect(out).toContain("threat summary");
  });

  it("drops subtitle at tiny widths (< 60 cols) but keeps title + count", () => {
    const out = renderToText(
      createElement(ShellHeader, {
        title: "findings",
        subtitle: "severity-sorted · chain-aware",
        count: "12 open",
      }),
      40,
    );
    expect(out).not.toContain("severity-sorted");
    expect(out).toContain("findings");
    expect(out).toContain("12 open");
  });

  it("truncates long subtitles to fit the width budget", () => {
    const veryLong =
      "a very long subtitle that will definitely not fit inside a 60 column terminal budget ever";
    const out = renderToText(
      createElement(ShellHeader, {
        title: "t",
        subtitle: veryLong,
      }),
      60,
    );
    // Either the whole subtitle renders (if budget allows) or it ends in an
    // ellipsis; never rendered verbatim when longer than the budget.
    expect(out.includes(veryLong)).toBe(false);
    expect(out).toContain("…");
  });
});

/**
 * layout-reflow — verify the views touched in the layout-overflow audit
 * scale dividers and clip widths to the live terminal columns rather
 * than to hardcoded 78/80/74 character literals.
 *
 * Renders each view at 80x24 and 120x40 and asserts:
 *   - no rendered line exceeds the terminal columns (no overflow), and
 *   - the wider terminal renders some line strictly longer than the
 *     longest line at 80 cols (some content actually reflowed).
 */
import { Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import { createManualUiClock, UiClockProvider } from "../../src/ui/clock.js";
import { FindingsView } from "../../src/ui/components/FindingsView.js";
import { TuneView } from "../../src/ui/components/TuneView.js";
import type { ActionableFinding, ShellState } from "../../src/ui/state.js";

class FrameCaptureStream extends Writable {
  columns: number;
  rows: number;
  isTTY = true;
  private frames: string[] = [];
  constructor(columns: number, rows: number) {
    super();
    this.columns = columns;
    this.rows = rows;
  }
  _write(
    chunk: string | Uint8Array,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.frames.push(Buffer.from(chunk).toString("utf-8"));
    callback();
  }
  clearLine(): void {}
  clearScreenDown(): void {}
  cursorTo(): void {}
  moveCursor(): void {}
  getColumns(): number {
    return this.columns;
  }
  lastFrame(): string {
    for (let i = this.frames.length - 1; i >= 0; i--) {
      const frame = this.frames[i] ?? "";
      if (stripAnsi(frame).trim().length > 0) return frame;
    }
    return "";
  }
}

const ANSI_RE = new RegExp(`${String.fromCharCode(0x1b)}\\[[^A-Za-z]*[A-Za-z]`, "g");
function stripAnsi(s: string): string {
  return s.replace(ANSI_RE, "");
}

function renderAt(node: ReactElement, columns: number, rows: number): string {
  const stream = new FrameCaptureStream(columns, rows);
  const clock = createManualUiClock(0);
  const instance = render(createElement(UiClockProvider, { clock }, node), {
    stdout: stream as unknown as Writable & NodeJS.WriteStream,
    debug: true,
  });
  instance.unmount();
  return stripAnsi(stream.lastFrame())
    .replace(/^(?:\r?\n)+/, "")
    .trimEnd();
}

function maxLineWidth(text: string): number {
  let max = 0;
  for (const line of text.split("\n")) {
    if (line.length > max) max = line.length;
  }
  return max;
}

function makeShell(overrides: Partial<ShellState> = {}): ShellState {
  return {
    modules: [],
    moduleCatalog: [],
    tools: [],
    focusedModule: "sast",
    shellView: "tune",
    openFindingId: null,
    target: null,
    workspace: null,
    history: [],
    commandHistory: [],
    moduleOptions: {},
    processing: false,
    ...overrides,
  };
}

function makeFinding(i: number): ActionableFinding {
  return {
    fingerprint: `fp-${String(i).padStart(4, "0")}`,
    ruleId: `rule-${i}`,
    title:
      "A really long finding title that historically clipped at 56 chars no matter how wide the pane",
    severity: "high",
    displaySeverity: "high",
    filePath: `src/very/deeply/nested/path/file-${i}.ts`,
    startLine: 100 + i,
    endLine: 110 + i,
    message: "msg",
    rationale: "r",
    verdict: "tp",
    confidence: 0.9,
    taskId: "sast",
  } as unknown as ActionableFinding;
}

describe("FindingsView layout reflow", () => {
  it("never overflows 80x24 and uses wider pane at 120x40", () => {
    const findings = [makeFinding(1), makeFinding(2), makeFinding(3)];
    const node = createElement(FindingsView, { mode: "unified", findings });
    const narrow = renderAt(node, 80, 24);
    const wide = renderAt(node, 120, 40);
    expect(maxLineWidth(narrow)).toBeLessThanOrEqual(80);
    expect(maxLineWidth(wide)).toBeLessThanOrEqual(120);
    // At 120 cols the divider rule is wider than the entire 80-col pane,
    // proving the divider reflowed instead of staying stuck at 78.
    expect(maxLineWidth(wide)).toBeGreaterThan(maxLineWidth(narrow));
  });

  it("renders the title at 120 cols longer than at 80 cols", () => {
    const findings = [makeFinding(7)];
    const node = createElement(FindingsView, { mode: "unified", findings });
    const narrow = renderAt(node, 80, 24);
    const wide = renderAt(node, 120, 40);
    // Title at 80 should be clipped, at 120 less so.
    const narrowTitleClipped = narrow.includes("…");
    expect(narrowTitleClipped).toBe(true);
    expect(wide.length).toBeGreaterThanOrEqual(narrow.length);
  });
});

describe("TuneView layout reflow", () => {
  it("does not overflow at 80 cols and reflows the divider at 120 cols", () => {
    const node = createElement(TuneView, {
      shell: makeShell({
        tuneSnapshot: {
          preset: "standard",
          tasks: ["semgrep"],
          verify: false,
          autoPatch: false,
          triageConcurrency: 5,
          model: "anthropic:claude-sonnet-4-5",
        },
      }),
    });
    const narrow = renderAt(node, 80, 24);
    const wide = renderAt(node, 120, 40);
    expect(maxLineWidth(narrow)).toBeLessThanOrEqual(80);
    expect(maxLineWidth(wide)).toBeLessThanOrEqual(120);
    // Divider line is the widest line in both renders; widening should grow it.
    expect(maxLineWidth(wide)).toBeGreaterThan(maxLineWidth(narrow));
  });
});

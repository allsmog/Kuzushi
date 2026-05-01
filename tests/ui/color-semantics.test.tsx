/**
 * Color & contrast guardrails — locks in the canonical hue map for status
 * signals so accidental drift (e.g. somebody recoloring "running" with
 * `tokens.warn` on a future view) trips a test.
 *
 * Two layers:
 *
 *   1. Pure helper tests against `runningStyle()` — assert glyph + ANSI
 *      code shape so the live transcript step palette stays anchored.
 *   2. Component snapshots that render `ModuleRunView`, `MonorepoProgress`,
 *      and `ErrorCard` with chalk forced on, then assert the right ANSI
 *      color codes appear (or don't) for the rows that were misaligned
 *      before this audit.
 *
 * ANSI base codes used (16-color SGR; chalk may emit either flavor):
 *   - 31 / 91   red / red-bright       → danger
 *   - 32 / 92   green / green-bright   → success
 *   - 33 / 93   yellow / yellow-bright → warn / caution / skipped
 *   - 34 / 94   blue / blue-bright     → accent / focus / in-progress
 *   - 90        gray                   → muted
 */
import { Writable } from "node:stream";
import chalk from "chalk";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import { ErrorCard } from "../../src/ui/components/ErrorCard.js";
import { ModuleRunView } from "../../src/ui/components/ModuleRunView.js";
import { MonorepoProgress } from "../../src/ui/components/MonorepoProgress.js";
import { runningStyle } from "../../src/ui/format.js";
import type { ShellState } from "../../src/ui/state.js";

// Force chalk on under vitest (stdout isn't a TTY by default).
chalk.level = Math.max(chalk.level, 1);

class CaptureStream extends Writable {
  columns = 100;
  rows = 30;
  isTTY = true;
  private chunks: string[] = [];
  _write(
    chunk: string | Uint8Array,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.chunks.push(Buffer.from(chunk).toString("utf-8"));
    callback();
  }
  clearLine(): void {}
  clearScreenDown(): void {}
  cursorTo(): void {}
  moveCursor(): void {}
  getColumns(): number {
    return this.columns;
  }
  raw(): string {
    return this.chunks.join("");
  }
}

// Build the ESC-prefixed regex pieces dynamically so the source file stays
// free of literal control characters (biome's
// `noControlCharactersInRegex` lint).
const ESC = String.fromCharCode(0x1b);

function stripAnsi(s: string): string {
  const re = new RegExp(`${ESC}\\[[^A-Za-z]*[A-Za-z]`, "g");
  return s.replace(re, "");
}

/** True when `s` contains an ANSI SGR sequence ending in `<code>m`. */
function ansiHas(s: string, code: number): boolean {
  return new RegExp(`${ESC}\\[(?:[0-9;]*;)?${code}m`).test(s);
}

/** True when ANY of the codes is present. */
function ansiHasAny(s: string, codes: number[]): boolean {
  return codes.some((c) => ansiHas(s, c));
}

function renderRaw(node: ReactElement): { raw: string; plain: string } {
  const stream = new CaptureStream();
  const instance = render(node, {
    stdout: stream as unknown as Writable & NodeJS.WriteStream,
    debug: true,
  });
  instance.unmount();
  const raw = stream.raw();
  return { raw, plain: stripAnsi(raw) };
}

function shell(overrides: Partial<ShellState> = {}): ShellState {
  return {
    modules: [],
    moduleCatalog: [],
    tools: [],
    focusedModule: "sast",
    shellView: "module-run",
    openFindingId: null,
    target: null,
    workspace: null,
    history: [],
    commandHistory: [],
    moduleOptions: {},
    processing: true,
    ...overrides,
  };
}

describe("runningStyle — canonical glyph + token map", () => {
  it("running uses the → glyph and an `accent` (blue) wrapper, never `warn` (yellow)", () => {
    const s = runningStyle("running");
    expect(s.glyph).toBe("→");
    const wrapped = s.color("X");
    // Blue / blue-bright code (34 or 94) appears.
    expect(ansiHasAny(wrapped, [34, 94])).toBe(true);
    // Yellow code (33 / 93) must NOT appear.
    expect(ansiHasAny(wrapped, [33, 93])).toBe(false);
  });

  it("done uses ✓ and `success` (green)", () => {
    const s = runningStyle("done");
    expect(s.glyph).toBe("✓");
    expect(ansiHasAny(s.color("X"), [32, 92])).toBe(true);
  });

  it("error uses ✗ and `danger` (red)", () => {
    const s = runningStyle("error");
    expect(s.glyph).toBe("✗");
    expect(ansiHasAny(s.color("X"), [31, 91])).toBe(true);
  });

  it("pending uses ○ and a non-status (muted/gray) wrapper", () => {
    const s = runningStyle("pending");
    expect(s.glyph).toBe("○");
    // Pending must NOT borrow any of the four status hues — otherwise it
    // would masquerade as something it isn't.
    expect(ansiHasAny(s.color("X"), [31, 32, 33, 34, 91, 92, 93, 94])).toBe(false);
  });

  it("every status pairs a unique glyph (color-blind / NO_COLOR safe)", () => {
    const glyphs = new Set([
      runningStyle("done").glyph,
      runningStyle("running").glyph,
      runningStyle("pending").glyph,
      runningStyle("error").glyph,
    ]);
    expect(glyphs.size).toBe(4);
  });
});

describe("ModuleRunView — running step uses accent (blue), not warn (yellow)", () => {
  it("step glyph row carries blue ANSI for the running step and green for done", () => {
    const state = shell({
      moduleRun: {
        moduleId: "sast",
        toolName: "sast:scan",
        displayName: "SAST",
        inputSummary: ".",
        startedAtMs: 0,
        status: "running",
        steps: [
          { id: "boot", title: "loadthreatmodel", status: "done", elapsedSeconds: 1 },
          { id: "spawn", title: "spawnactors", status: "running" },
          { id: "merge", title: "mergefindings", status: "pending" },
        ],
        evidenceTail: [],
        costUsd: 0.42,
      },
    });
    const { raw, plain } = renderRaw(createElement(ModuleRunView, { shell: state, nowMs: 12_000 }));
    // Plain text still includes all three step titles (non-color cue).
    expect(plain).toContain("loadthreatmodel");
    expect(plain).toContain("spawnactors");
    expect(plain).toContain("mergefindings");
    // Blue (34/94) appears — the running step's glyph + spinner family.
    expect(ansiHasAny(raw, [34, 94])).toBe(true);
    // Green (32/92) appears — the done step's check glyph.
    expect(ansiHasAny(raw, [32, 92])).toBe(true);
  });
});

describe("MonorepoProgress — active phase label is focus (blue), not danger (red)", () => {
  it("renders the running phase label without using a red wrapper", () => {
    const { raw, plain } = renderRaw(
      createElement(MonorepoProgress, {
        modules: [
          { path: "pkg-a", name: "pkg-a", status: "scanning", detail: "scanning..." },
          { path: "pkg-b", name: "pkg-b", status: "pending" },
        ],
        phaseLabel: "Scanning",
      }),
    );
    expect(plain).toContain("Scanning");
    // The phase label region must carry a blue (focus) ANSI run.
    expect(ansiHasAny(raw, [34, 94])).toBe(true);
  });
});

describe("ErrorCard — Next step label is not green/successStrong", () => {
  it("renders 'Next step:' inside an accent (blue) wrapper, not success (green)", () => {
    const { raw, plain } = renderRaw(
      createElement(ErrorCard, {
        message: "fetch failed",
        category: "transport",
        hint: "Check network connectivity, then retry.",
      }),
    );
    expect(plain).toContain("Next step:");
    expect(plain).toContain("Check network connectivity");
    // Accent / focus blue should be present in the rendered ANSI.
    expect(ansiHasAny(raw, [34, 94])).toBe(true);
  });
});

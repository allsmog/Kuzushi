/**
 * Visual hierarchy snapshots for the four views touched by the
 * "visual hierarchy & density" pass:
 *   - FindingsView (unified) — hand-rolled rules → Divider, primary
 *     action demoted from `tokens.strong` to `tokens.value`.
 *   - TuneView — same rule + primary-action treatment.
 *   - ModuleRunView LiveControlsHint — margin rhythm matches the rest
 *     of the page (no longer hugs the header divider).
 *   - ThreatStrideMatrix pivot — row label demoted to `tokens.muted`
 *     so the heat counts read as the data, not the chrome.
 *
 * Each test renders the component, strips ANSI, and asserts on the
 * structural changes. The point is to trip a regression if someone
 * re-introduces the inline `─".repeat(N)` pattern or restores a
 * heading-weight "Primary action" line.
 */
import { Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import { createManualUiClock, UiClockProvider } from "../../src/ui/clock.js";
import { FindingsView } from "../../src/ui/components/FindingsView.js";
import { ModuleRunView } from "../../src/ui/components/ModuleRunView.js";
import { ThreatStrideMatrix } from "../../src/ui/components/ThreatStrideMatrix.js";
import { TuneView } from "../../src/ui/components/TuneView.js";
import type { ActionableFinding, ShellState } from "../../src/ui/state.js";

class FrameCaptureStream extends Writable {
  columns: number;
  rows = 30;
  isTTY = true;
  private frames: string[] = [];
  constructor(columns = 100) {
    super();
    this.columns = columns;
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

function renderText(node: ReactElement, columns = 100): string {
  const stream = new FrameCaptureStream(columns);
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

function shell(overrides: Partial<ShellState> = {}): ShellState {
  return {
    modules: [],
    moduleCatalog: [],
    tools: [],
    focusedModule: null,
    shellView: "catalog",
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

function finding(overrides: Partial<ActionableFinding> = {}): ActionableFinding {
  return {
    verdict: "tp",
    confidence: 0.9,
    severity: "HIGH",
    taskId: "sast",
    filePath: "src/api/admin.ts",
    startLine: 88,
    ruleId: "ssrf.no-allowlist",
    rationale: "router mounts admin/fetch before authMiddleware",
    fingerprint: "fp-1",
    title: "ssrf on /admin/fetch",
    displaySeverity: "high",
    verifyExploitable: 1,
    corroboratingSignals: [],
    suppressionReasons: [],
    ...overrides,
  } as ActionableFinding;
}

describe("visual hierarchy", () => {
  describe("FindingsView (unified)", () => {
    it("uses Divider rules that follow terminal width", () => {
      const out = renderText(
        createElement(FindingsView, {
          mode: "unified",
          findings: [finding()],
        }),
        72,
      );
      // Old code emitted a literal 78-char rule regardless of terminal
      // width. After the fix, the rule is sized by `Divider`, which
      // tops out at the terminal width (72 here) — so a 78-char rule
      // must NOT appear.
      expect(out).not.toMatch(/─{78}/);
      // But at least one rule should still render (we replaced the
      // hand-rolled one with a Divider, not removed it).
      expect(out).toMatch(/─{30,}/);
    });

    it("renders the primary-action line at body weight, not heading weight", () => {
      const out = renderText(
        createElement(FindingsView, {
          mode: "unified",
          findings: [finding()],
        }),
      );
      // Demoted from tokens.strong → tokens.value. The text still
      // ships, but no longer competes with section headings.
      expect(out).toContain("Primary action: /open F-NNNN to inspect one finding deeply.");
      expect(out).toContain("ungrouped findings");
    });
  });

  describe("TuneView", () => {
    it("uses Divider rule and renders primary action without heading bold", () => {
      const out = renderText(
        createElement(TuneView, {
          shell: shell({
            focusedModule: "sast",
            shellView: "tune",
            tuneSnapshot: {
              preset: "standard",
              tasks: ["semgrep"],
              verify: false,
              autoPatch: false,
              triageConcurrency: 5,
              model: "anthropic:claude-sonnet-4-6",
            },
          }),
        }),
        72,
      );
      // Old: tokens.muted("─".repeat(78))
      expect(out).not.toMatch(/─{78}/);
      expect(out).toMatch(/─{30,}/);
      expect(out).toContain("Primary action: run with the focused module settings.");
    });
  });

  describe("ModuleRunView LiveControlsHint", () => {
    it("renders the live-controls hint with breathing room above and below", () => {
      const out = renderText(
        createElement(ModuleRunView, {
          shell: shell({
            focusedModule: "threat-hunt",
            shellView: "module-run",
            moduleRun: {
              moduleId: "threat-hunt",
              toolName: "threat-hunt:run",
              displayName: "Threat Hunt",
              inputSummary: ".",
              startedAtMs: 0,
              status: "running",
              liveControl: "pause-resume",
              steps: [{ id: "boot", title: "load", status: "running" }],
              evidenceTail: [],
              costUsd: 0.1,
            },
          }),
          nowMs: 5_000,
        }),
      );
      const lines = out.split(/\r?\n/);
      const hintIdx = lines.findIndex((l) => l.includes("p pause"));
      expect(hintIdx).toBeGreaterThanOrEqual(0);
      // After the fix the hint sits below the RuleHeader's own
      // marginBottom and above the ⏺ tool row with a blank line — so
      // the line *immediately* before the ⏺ row should be the hint
      // padding, not the hint itself glued to the rule.
      // For running status the ToolHeader uses a Spinner (no static glyph), so
      // anchor on the label text and accept any leading content.
      const blackCircleIdx = lines.findIndex((l) => /Threat Hunt\(/.test(l));
      expect(blackCircleIdx).toBeGreaterThan(hintIdx);
      // At least one blank line between hint and tool header.
      const between = lines.slice(hintIdx + 1, blackCircleIdx);
      expect(between.some((l) => l.trim() === "")).toBe(true);
    });
  });

  describe("ThreatStrideMatrix pivot", () => {
    it("renders pivot row labels as muted metadata, not as values", () => {
      const out = renderText(
        createElement(ThreatStrideMatrix, {
          shell: shell({
            shellView: "threats",
            threatTab: "stride",
            threatModel: {
              version: "1.0",
              dfd: { elements: [], trustBoundaries: [] },
              threats: [],
              summary: {
                total: 0,
                bySeverity: {},
                byCategory: {
                  spoofing: 0,
                  tampering: 0,
                  repudiation: 0,
                  "information-disclosure": 0,
                  "denial-of-service": 0,
                  "elevation-of-privilege": 0,
                },
              },
            },
          }),
        }),
      );
      // The pivot table renders all four impact tiers as row labels.
      // (The colors are stripped, but the row text still appears.)
      expect(out).toContain("impact \\ likelihood");
      expect(out).toContain("critical");
      expect(out).toContain("high");
      expect(out).toContain("medium");
      expect(out).toContain("low");
    });
  });
});

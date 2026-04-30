import { Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import { App } from "../../src/ui/App.js";
import { createManualUiClock, UiClockProvider } from "../../src/ui/clock.js";
import { FindingsView } from "../../src/ui/components/FindingsView.js";
import { PipelineIndicator } from "../../src/ui/components/PipelineIndicator.js";
import { createUIStore, type ResultLine, type ShellState } from "../../src/ui/state.js";

class FrameCaptureStream extends Writable {
  columns: number;
  rows: number;
  isTTY = true;
  private frames: string[] = [];

  constructor(columns = 80, rows = 24) {
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

  lastFrame(): string {
    for (let i = this.frames.length - 1; i >= 0; i--) {
      const frame = this.frames[i] ?? "";
      if (stripAnsi(frame).trim().length > 0) return frame;
    }
    return "";
  }
}

function renderToString(node: ReactElement, columns = 80, rows = 24): string {
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

// biome-ignore lint/suspicious/noControlCharactersInRegex: strips ANSI for stable assertions
const ANSI_RE = /\u001b(?:\[[0-9;?]*[ -/]*[@-~]|][^\u0007]*(?:\u0007|\u001b\\))/g;

function stripAnsi(s: string): string {
  return s.replace(ANSI_RE, "");
}

function stubShell(overrides: Partial<ShellState> = {}): ShellState {
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

describe("Ink flicker bounds", () => {
  it("clips App output to the terminal viewport", () => {
    const store = createUIStore();
    store.update({
      mode: "shell",
      shellSplashShown: true,
      shell: stubShell({
        moduleCatalog: Array.from({ length: 20 }, (_, i) => ({
          id: `module-${i}`,
          displayName: `Module ${i}`,
          category: "offense",
          description: `long module description ${i}`,
          toolCount: 1,
        })),
      }),
    });

    const out = renderToString(createElement(App, { store }), 64, 8);
    expect(out.split("\n").length).toBeLessThanOrEqual(8);
  });

  it("bounds compact running findings to recent rows", () => {
    const results: ResultLine[] = Array.from({ length: 40 }, (_, i) => ({
      kind: "triage",
      verdict: "tp",
      confidence: 0.9,
      costUsd: 0.001,
      fingerprint: `fp-${String(i).padStart(3, "0")}`,
      index: i + 1,
      total: 40,
    }));

    const out = renderToString(createElement(FindingsView, { results }), 80, 18);

    expect(out).toContain("earlier triage results");
    expect(out).not.toContain("fp-000");
    expect(out).toContain("fp-039");
  });

  it("collapses completed pipeline subtasks when row budget is tight", () => {
    const out = renderToString(
      createElement(PipelineIndicator, {
        rowBudget: 8,
        stages: [
          {
            id: "scan",
            label: "Scan",
            status: "active",
            detail: "running",
            startedAt: 0,
            subTasks: [
              ...Array.from({ length: 16 }, (_, i) => ({
                id: `done-${i}`,
                label: `done-${i}`,
                status: "done" as const,
              })),
              { id: "active-task", label: "active-task", status: "active" as const },
            ],
          },
          { id: "report", label: "Report", status: "pending", subTasks: [] },
        ],
      }),
      80,
      18,
    );

    expect(out).toContain("active-task");
    expect(out).toContain("+");
    expect(out).toContain("hidden");
    expect(out).not.toContain("done-15");
  });
});

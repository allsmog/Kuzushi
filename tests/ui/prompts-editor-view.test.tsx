/**
 * PromptsEditorView snapshots — verify the prompts table renders with
 * source labels and that the after-vim "Saved prompt override" card
 * shows when `lastSavedAt` is fresh.
 */
import { Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import type { PromptAuditRow } from "../../src/copilot/prompt-edit.js";
import { createManualUiClock, UiClockProvider } from "../../src/ui/clock.js";
import { PromptsEditorView } from "../../src/ui/components/PromptsEditorView.js";
import type { ShellState } from "../../src/ui/state.js";

class FrameCaptureStream extends Writable {
  columns = 100;
  rows = 24;
  isTTY = true;
  private frames: string[] = [];
  _write(chunk: string | Uint8Array, _e: BufferEncoding, cb: (e?: Error | null) => void): void {
    this.frames.push(Buffer.from(chunk).toString("utf-8"));
    cb();
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

function renderText(node: ReactElement): string {
  const stream = new FrameCaptureStream();
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
    focusedModule: "threat-hunt",
    shellView: "prompts-editor",
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

const SAMPLE_ROWS: PromptAuditRow[] = [
  {
    moduleId: "threat-hunt",
    toolName: "threat-hunt:run",
    verb: "run",
    promptKey: "THREAT_HUNT_PROMPT" as const,
    effective: {
      promptKey: "THREAT_HUNT_PROMPT" as const,
      toolName: "threat-hunt:run",
      source: "default",
    },
  },
  {
    moduleId: "threat-hunt",
    toolName: "threat-hunt:run",
    verb: "actor",
    promptKey: "THREAT_HUNT_PROMPT" as const,
    effective: {
      promptKey: "THREAT_HUNT_PROMPT" as const,
      toolName: "threat-hunt:run",
      source: "file",
      filePath: "/repo/.kuzushi/prompts/threat-hunt/actor.md",
      byteLen: 384,
    },
  },
];

describe("PromptsEditorView", () => {
  it("renders an empty list with the status strip when no prompts are exposed", () => {
    const out = renderText(createElement(PromptsEditorView, { shell: shell(), rows: [] }));
    expect(out).toContain("0 prompts");
    expect(out).toContain("No prompt overrides for this module.");
  });

  it("renders the table with default + local-edit rows", () => {
    const out = renderText(createElement(PromptsEditorView, { shell: shell(), rows: SAMPLE_ROWS }));
    expect(out).toContain("2 prompts · 1 local edit");
    expect(out).toContain("run");
    expect(out).toContain("default");
    expect(out).toContain("actor");
    expect(out).toContain("local edit");
    // Action verbs are listed.
    expect(out).toContain("edit <name>");
    expect(out).toContain("reset <name>");
  });

  it("shows the after-vim Saved prompt override card while fresh", () => {
    const now = 1_000_000;
    const state = shell({
      promptsEditor: {
        audit: [],
        lastSavedAt: now - 1_000,
        lastSaved: {
          name: "actor",
          path: "/repo/.kuzushi/prompts/threat-hunt/actor.md",
          size: 412,
        },
      },
    });
    const out = renderText(
      createElement(PromptsEditorView, { shell: state, rows: [], nowMs: now }),
    );
    expect(out).toContain("Saved prompt override");
    expect(out).toContain("actor");
    expect(out).toContain("412 bytes");
    expect(out).toContain("active");
  });

  it("hides the Saved card once the TTL window has elapsed", () => {
    const now = 1_000_000;
    const state = shell({
      promptsEditor: {
        audit: [],
        lastSavedAt: now - 30_000,
        lastSaved: {
          name: "actor",
          path: "/repo/.kuzushi/prompts/threat-hunt/actor.md",
          size: 12,
        },
      },
    });
    const out = renderText(
      createElement(PromptsEditorView, { shell: state, rows: [], nowMs: now }),
    );
    expect(out).not.toContain("Saved prompt override");
  });
});

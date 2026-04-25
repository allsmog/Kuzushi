/**
 * ModuleRunView snapshots — verify the breadcrumb header, ⏺ tool row,
 * step glyphs, and per-actor cards land where the v3 mock expects.
 *
 * Uses the same FrameCaptureStream / Ink-render harness as
 * `component-snapshots.test.tsx`. Output is ANSI-stripped before
 * assertions so `toContain` checks stay stable across themes.
 */
import { Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import { createManualUiClock, UiClockProvider } from "../../src/ui/clock.js";
import { ModuleRunView } from "../../src/ui/components/ModuleRunView.js";
import type { AgentActivityLine, ShellState } from "../../src/ui/state.js";

class FrameCaptureStream extends Writable {
  columns = 100;
  rows = 30;
  isTTY = true;
  private frames: string[] = [];
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

// biome-ignore lint/suspicious/noControlCharactersInRegex: strip ANSI for stable text matching
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

function activity(partial: Partial<AgentActivityLine> = {}): AgentActivityLine {
  return { kind: "tool-start", index: 0, total: 1, ...partial };
}

describe("ModuleRunView", () => {
  it("renders the empty state when shell.moduleRun is null", () => {
    const out = renderText(createElement(ModuleRunView, { shell: shell({ moduleRun: null }) }));
    expect(out).toContain("kuzushi/threat-hunt/run");
    expect(out).toContain("No active run for this module yet.");
  });

  it("renders header + steps + meta row for a running threat-hunt", () => {
    const state = shell({
      moduleRun: {
        moduleId: "threat-hunt",
        toolName: "threat-hunt:run",
        displayName: "Threat Hunt",
        inputSummary: ".",
        startedAtMs: 0,
        status: "running",
        steps: [
          { id: "boot", title: "load threat model", status: "done", elapsedSeconds: 1 },
          { id: "spawn", title: "spawn 3 actors", status: "running" },
          { id: "merge", title: "merge findings", status: "pending" },
        ],
        evidenceTail: [],
        costUsd: 0.42,
      },
    });
    const out = renderText(createElement(ModuleRunView, { shell: state, nowMs: 12_000 }));
    expect(out).toContain("kuzushi/threat-hunt/run");
    expect(out).toMatch(/(?:⏺|●) Threat Hunt\(\.\)/);
    expect(out).toContain("steps");
    expect(out).toContain("load threat model");
    expect(out).toContain("spawn 3 actors");
    expect(out).toContain("merge findings");
    expect(out).toContain("cost");
    expect(out).toContain("$0.42");
  });

  it("renders the actors block for threat-hunt with active + queued cards", () => {
    const state = shell({
      moduleRun: {
        moduleId: "threat-hunt",
        toolName: "threat-hunt:run",
        startedAtMs: 0,
        status: "running",
        steps: [],
        evidenceTail: [],
      },
    });
    const map = new Map<string, AgentActivityLine[]>([
      [
        "threat-hunt:Authenticated_User:0",
        [
          activity({ kind: "tool-start", toolName: "Read", detail: "src/api.ts" }),
          activity({ kind: "tool-complete", toolName: "Read", detail: "138 lines" }),
        ],
      ],
      [
        "threat-hunt:Anonymous_Visitor:0",
        [activity({ kind: "tool-start", toolName: "Grep", detail: "auth" })],
      ],
    ]);
    const out = renderText(
      createElement(ModuleRunView, {
        shell: state,
        nowMs: 5_000,
        agentActivity: map,
      }),
    );
    expect(out).toContain("actors");
    // Fingerprints sort alphabetically — Anonymous_Visitor lands at index 0,
    // Authenticated_User at index 1, so the short ids are derived in that order.
    expect(out).toContain("ANON-01");
    expect(out).toContain("AUTH-02");
    expect(out).toContain("Authenticated User");
    expect(out).toContain("Anonymous Visitor");
    // Keybind footer hint should be visible
    expect(out).toContain("1–4 drill into actor");
  });
});

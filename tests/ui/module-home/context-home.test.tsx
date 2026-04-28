/**
 * ContextHome — Status / Actions / Last run.
 *
 * Verifies snapshot age formatting + the actions block surfaces the
 * regen verbs the slash router accepts.
 */
import { Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import { createManualUiClock, UiClockProvider } from "../../../src/ui/clock.js";
import { ContextHome } from "../../../src/ui/components/module-home/context-home.js";
import type { ContextSnapshot, ShellState } from "../../../src/ui/state.js";

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
    focusedModule: "context",
    shellView: "module",
    openFindingId: null,
    target: "/repo",
    workspace: "demo-app",
    history: [],
    commandHistory: [],
    moduleOptions: {},
    processing: false,
    ...overrides,
  };
}

describe("ContextHome", () => {
  it("renders the empty status block when no snapshot has landed", () => {
    const out = renderText(createElement(ContextHome, { shell: shell() }));
    expect(out).toContain("kuzushi/context");
    expect(out).toContain("status");
    expect(out).toContain("(none yet) — run /context build");
    expect(out).toContain("actions");
    expect(out).toContain("regen <slice>");
    expect(out).toContain("/use threat-model");
    expect(out).toContain("never run for this workspace");
  });

  it("summarizes generated + stale slices when a snapshot exists", () => {
    const snapshot: ContextSnapshot = {
      target: "demo-app",
      timestamp: Date.now() - 10 * 60_000,
      discovery: "auto",
      options: { enrichment: true },
      generatedSlices: ["repo", "app-model"],
      staleSlices: ["enrichment"],
    };
    const out = renderText(
      createElement(ContextHome, { shell: shell({ contextSnapshot: snapshot }) }),
    );
    expect(out).toContain("generated");
    expect(out).toContain("repo");
    expect(out).toContain("app-model");
    expect(out).toContain("stale");
    expect(out).toContain("enrichment");
    expect(out).toContain("regen stale");
    expect(out).toContain("1 stale slice(s)");
  });
});

/**
 * ActorTranscriptView snapshots — exercise tool-start / tool-complete /
 * thinking / finding interleaves and verify the synthesized ★ Finding
 * rows appear when `actorFingerprint` matches.
 */
import { Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import type { Finding } from "../../src/scanners/types.js";
import { createManualUiClock, UiClockProvider } from "../../src/ui/clock.js";
import { ActorTranscriptView } from "../../src/ui/components/ActorTranscriptView.js";
import type { AgentActivityLine, ShellState } from "../../src/ui/state.js";

class FrameCaptureStream extends Writable {
  columns = 100;
  rows = 32;
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
    focusedModule: "carlini-threat-hunt",
    shellView: "actor-detail",
    openFindingId: null,
    target: null,
    workspace: null,
    history: [],
    commandHistory: [],
    moduleOptions: {},
    processing: true,
    focusedActor: "carlini-threat-hunt:Authenticated_User:0",
    moduleRun: {
      moduleId: "carlini-threat-hunt",
      toolName: "carlini-threat-hunt:run",
      startedAtMs: 0,
      status: "running",
      steps: [],
      evidenceTail: [],
      costUsd: 0.18,
    },
    ...overrides,
  };
}

function activity(partial: Partial<AgentActivityLine> = {}): AgentActivityLine {
  return { kind: "tool-start", index: 0, total: 1, ...partial };
}

describe("ActorTranscriptView", () => {
  it("renders an empty placeholder when no actor is focused", () => {
    const out = renderText(
      createElement(ActorTranscriptView, {
        shell: shell({ focusedActor: null }),
      }),
    );
    expect(out).toContain("kuzushi/carlini-threat-hunt/run/—");
    expect(out).toContain("(no activity yet)");
  });

  it("interleaves tool/result/thinking/finding rows for the focused actor", () => {
    const map = new Map<string, AgentActivityLine[]>([
      [
        "carlini-threat-hunt:Authenticated_User:0",
        [
          activity({ kind: "tool-start", toolName: "Read", detail: "src/api/admin.ts" }),
          activity({ kind: "tool-complete", toolName: "Read", detail: "138 lines, 4.2KB" }),
          activity({ kind: "reasoning", detail: "checking allowlist" }),
          activity({ kind: "finding-preview", detail: "SSRF on /admin/fetch" }),
        ],
      ],
      [
        "carlini-threat-hunt:Anonymous_Visitor:0",
        [activity({ kind: "tool-start", toolName: "Grep" })],
      ],
    ]);
    const out = renderText(
      createElement(ActorTranscriptView, {
        shell: shell(),
        agentActivity: map,
      }),
    );
    expect(out).toContain("Carlini Threat Hunt(. as <Authenticated User>)");
    // Tool-start / -complete / -reasoning / -finding-preview should each
    // produce one row in the transcript.
    expect(out).toMatch(/Read\(src\/api\/admin\.ts\)/);
    expect(out).toContain("138 lines, 4.2KB");
    expect(out).toContain("Thinking — checking allowlist");
    expect(out).toContain("Finding — SSRF on /admin/fetch");
    // Other actors strip should mention the queued ANON-02 actor.
    expect(out).toContain("Other actors");
    expect(out).toContain("ANON");
  });

  it("synthesizes ★ Finding rows from findings whose actorFingerprint matches", () => {
    const map = new Map<string, AgentActivityLine[]>([
      [
        "carlini-threat-hunt:Authenticated_User:0",
        [activity({ kind: "tool-start", toolName: "Read", detail: "x.ts" })],
      ],
    ]);
    const findings: Finding[] = [
      {
        taskId: "carlini-threat-hunt",
        fingerprint: "abcd1234",
        ruleId: "ssrf",
        filePath: "src/api/admin.ts",
        startLine: 88,
        severity: "HIGH",
        message: "SSRF in /admin/fetch",
        scannerConfidence: "HIGH",
        subcategory: [],
        likelihood: "HIGH",
        impact: "HIGH",
        cwe: ["CWE-918"],
        score: 9,
        actorFingerprint: "carlini-threat-hunt:Authenticated_User:0",
      },
      {
        taskId: "carlini-threat-hunt",
        fingerprint: "deadbeef",
        ruleId: "noise",
        filePath: "src/other.ts",
        startLine: 1,
        severity: "LOW",
        message: "Should not appear",
        scannerConfidence: "LOW",
        subcategory: [],
        likelihood: "LOW",
        impact: "LOW",
        cwe: [],
        score: 1,
        actorFingerprint: "carlini-threat-hunt:Other:0",
      },
    ];
    const out = renderText(
      createElement(ActorTranscriptView, {
        shell: shell(),
        agentActivity: map,
        findings,
      }),
    );
    expect(out).toContain("Finding — SSRF in /admin/fetch");
    // Findings stamped to other actors must not bleed into this view.
    expect(out).not.toContain("Should not appear");
  });
});

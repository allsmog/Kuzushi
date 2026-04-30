/**
 * CarliniThreatHuntHome — readiness/scope/actions blocks rendered against a
 * stub threat-model document so `actorsFromDocument` can partition
 * actors into ready/deferred buckets.
 */
import { Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import type { ThreatModelDocument } from "../../../src/agents/tasks/threat-modeling/types.js";
import { createManualUiClock, UiClockProvider } from "../../../src/ui/clock.js";
import { CarliniThreatHuntHome } from "../../../src/ui/components/module-home/carlini-threat-hunt-home.js";
import type { ShellState } from "../../../src/ui/state.js";

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
    focusedModule: "carlini-threat-hunt",
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

function makeStride(elementId: string, impact: "critical" | "high" | "medium", i: number) {
  return {
    id: `t-${i}`,
    actorIds: [elementId],
    entrypointIds: [],
    targetElementIds: [elementId],
    flowIds: [],
    category: "spoofing" as const,
    title: `t${i}`,
    description: "",
    attackVector: "/",
    preconditions: [],
    impact,
    likelihood: "medium" as const,
    existingMitigations: [],
    missingMitigations: [],
    relatedCwe: [],
    affectedFiles: [],
  };
}

function doc(): ThreatModelDocument {
  return {
    version: "2.0",
    dfd: {
      nodes: [
        {
          id: "ext-1",
          type: "external-entity",
          name: "Authenticated User",
          description: "logged-in",
          trustZone: "external",
        },
        {
          id: "ext-2",
          type: "external-entity",
          name: "Anonymous Visitor",
          description: "no auth",
          trustZone: "external",
        },
      ],
      flows: [],
      trustBoundaries: [],
    },
    threats: [makeStride("ext-1", "critical", 1), makeStride("ext-2", "medium", 2)],
    summary: { total: 2, bySeverity: {}, byCategory: {} as never },
  } as unknown as ThreatModelDocument;
}

describe("CarliniThreatHuntHome", () => {
  it("shows the no-context advisory when no snapshot has landed", () => {
    const out = renderText(createElement(CarliniThreatHuntHome, { shell: shell() }));
    expect(out).toContain("kuzushi/carlini-threat-hunt");
    expect(out).toContain("readiness");
    expect(out).toContain("missing — /use context, then run .");
    expect(out).toContain("missing — /context build");
    expect(out).toContain("missing — /use threat-model, then run .");
    expect(out).toContain("missing DFD");
    expect(out).toContain("(no actors yet)");
    expect(out).toContain("scope");
    expect(out).toContain("actions");
    expect(out).toContain("/use threat-model");
    expect(out).toContain("then run . to write .kuzushi/threat-model.json");
    expect(out).toContain("/context build");
    expect(out).toContain("run --changed");
  });

  it("partitions ready vs deferred actors when a threat model is loaded", () => {
    const out = renderText(
      createElement(CarliniThreatHuntHome, {
        shell: shell({ threatModel: doc() }),
      }),
    );
    expect(out).toContain("readiness");
    expect(out).toContain("2 nodes");
    // 1 actor has a CRITICAL threat; the other only has MEDIUM → deferred.
    expect(out).toContain("1 ready · 1 deferred");
  });
});

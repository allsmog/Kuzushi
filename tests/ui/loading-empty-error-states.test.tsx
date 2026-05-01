/**
 * Loading / empty / error state coverage for the Ink TUI views touched
 * in the Phase D polish pass:
 *
 *   - ModuleCatalog · empty (no modules loaded)
 *   - OptionsView · empty (no view loaded)
 *   - PromptsEditorView · empty (no prompt rows)
 *   - ThreatDfdView · empty (no threat model + no context snapshot)
 *   - DiffSinceView · error (git diff failure)
 *   - ContextBuildView · loading (running phases) + idle + failed
 *   - ModuleRunView · idle + error
 *   - ActorTranscriptView · empty (no actor focused)
 *   - CostView · empty (no cost data)
 *
 * These assert the structural strings the operator sees — slash command
 * hints, badges, "Next step:" recovery — rather than full snapshots so
 * unrelated layout drift doesn't trip the suite.
 */

import { Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import { ActorTranscriptView } from "../../src/ui/components/ActorTranscriptView.js";
import { ContextBuildView } from "../../src/ui/components/ContextBuildView.js";
import { CostView } from "../../src/ui/components/CostView.js";
import { DiffSinceView } from "../../src/ui/components/DiffSinceView.js";
import { ModuleCatalog } from "../../src/ui/components/ModuleCatalog.js";
import { ModuleRunView } from "../../src/ui/components/ModuleRunView.js";
import { OptionsView } from "../../src/ui/components/OptionsView.js";
import { PromptsEditorView } from "../../src/ui/components/PromptsEditorView.js";
import { ThreatDfdView } from "../../src/ui/components/ThreatDfdView.js";
import type { ContextBuildState, ShellState } from "../../src/ui/state.js";

class FrameCaptureStream extends Writable {
  columns: number;
  rows: number;
  isTTY = true;
  private frames: string[] = [];

  constructor(columns = 100, rows = 30) {
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

// biome-ignore lint/suspicious/noControlCharactersInRegex: ANSI strip
const ANSI_RE = /(?:\[[0-9;?]*[ -/]*[@-~]|][^]*(?:|\\))/g;

function stripAnsi(s: string): string {
  return s.replace(ANSI_RE, "");
}

function renderToString(node: ReactElement, columns = 100, rows = 30): string {
  const stream = new FrameCaptureStream(columns, rows);
  const instance = render(node, {
    stdout: stream as unknown as Writable & NodeJS.WriteStream,
    debug: true,
  });
  instance.unmount();
  return stripAnsi(stream.lastFrame())
    .replace(/^(?:\r?\n)+/, "")
    .trimEnd();
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
  } as ShellState;
}

describe("Loading / empty / error states", () => {
  it("ModuleCatalog · empty catalog renders 'No modules loaded' with --load hint", () => {
    const shell = stubShell({ moduleCatalog: [] });
    const out = renderToString(createElement(ModuleCatalog, { shell }));
    expect(out).toContain("No modules loaded");
    expect(out).toContain("--load");
  });

  it("OptionsView · no view loaded renders module-scoped empty state", () => {
    const shell = stubShell({
      focusedModule: "sast",
      shellView: "options",
      optionsView: undefined,
    });
    const out = renderToString(createElement(OptionsView, { shell }));
    expect(out).toContain("No options to show");
    expect(out).toContain("show options");
  });

  it("PromptsEditorView · no prompt rows shows the prompts-none empty state", () => {
    const shell = stubShell({
      focusedModule: "sast",
      shellView: "prompts-editor",
      promptsEditor: { audit: [] },
    });
    const out = renderToString(createElement(PromptsEditorView, { shell }));
    expect(out).toContain("No prompt keys");
    expect(out).toContain("/prompts");
  });

  it("ThreatDfdView · empty workspace routes through threat-model-missing copy", () => {
    const shell = stubShell({
      shellView: "threats",
      threatTab: "dfd",
      threatModel: undefined,
      contextSnapshot: undefined,
    });
    const out = renderToString(createElement(ThreatDfdView, { shell }));
    expect(out).toContain("data flow");
    // Recovery hint must reference /scan or /threats edit.
    expect(out).toMatch(/\/scan|\/threats edit/);
  });

  it("DiffSinceView · git error renders an ErrorCard with /since hint", () => {
    const shell = stubShell({
      shellView: "diff-since",
      diffSince: {
        ref: "bogus-ref",
        changedFiles: [],
        error: "fatal: bad revision 'bogus-ref'",
      },
    });
    const out = renderToString(createElement(DiffSinceView, { shell, summary: null }));
    expect(out).toContain("git diff failed");
    expect(out).toContain("Next step:");
    expect(out).toContain("/since");
  });

  it("ContextBuildView · idle (no build) shows EmptyState with /context build action", () => {
    const shell = stubShell({ shellView: "context-build" });
    const out = renderToString(createElement(ContextBuildView, { shell }));
    expect(out).toContain("No build in progress");
    expect(out).toContain("/context build");
  });

  it("ContextBuildView · failed build renders the ErrorCard banner", () => {
    const cb: ContextBuildState = {
      runId: "run-1",
      repoRoot: "/repo",
      startedAtMs: 0,
      status: "failed",
      errorMessage: "walk failed: ENOENT /repo/missing",
      phases: {
        manifests: { status: "done" },
        walk: { status: "failed" },
        "path-signals": { status: "pending" },
        grep: { status: "pending" },
        assemble: { status: "pending" },
      },
      manifests: {},
      pillars: { architecture: {}, trust: {} },
      pathSignals: [],
      tail: [],
      tailExpanded: false,
    } as unknown as ContextBuildState;
    const shell = stubShell({ shellView: "context-build", contextBuild: cb });
    const out = renderToString(createElement(ContextBuildView, { shell }), 120, 40);
    expect(out).toContain("Context build failed");
    expect(out).toContain("walk failed");
    // ErrorCard surfaces a code prefix and a Next step CTA.
    expect(out).toContain("E_CONTEXT_BUILD");
    expect(out).toContain("Next step:");
  });

  it("ContextBuildView · running shows phase indicators (loading state)", () => {
    const cb: ContextBuildState = {
      runId: "run-1",
      repoRoot: "/repo",
      startedAtMs: Date.now() - 1500,
      status: "running",
      phases: {
        manifests: { status: "done", durationMs: 300 },
        walk: { status: "running" },
        "path-signals": { status: "pending" },
        grep: { status: "pending" },
        assemble: { status: "pending" },
      },
      manifests: {
        "package.json": "found",
        "go.mod": "miss",
        pyproject: "miss",
        "Cargo.toml": "miss",
        "native-build": "miss",
      },
      pillars: { architecture: {}, trust: {} },
      pathSignals: [],
      tail: [],
      tailExpanded: false,
    } as unknown as ContextBuildState;
    const shell = stubShell({ shellView: "context-build", contextBuild: cb });
    const out = renderToString(createElement(ContextBuildView, { shell }), 120, 40);
    expect(out).toContain("running");
    expect(out).toContain("walk repo");
    // Operator sees this is in-flight, not failed/empty.
    expect(out).not.toContain("No build in progress");
    expect(out).not.toContain("Context build failed");
  });

  it("ModuleRunView · no active run shows module-run-idle empty state", () => {
    const shell = stubShell({
      focusedModule: "sast",
      shellView: "module-run",
      moduleRun: undefined,
    });
    const out = renderToString(createElement(ModuleRunView, { shell }));
    expect(out).toContain("No active run");
    expect(out).toMatch(/run|scan/);
  });

  it("ModuleRunView · error status renders an ErrorCard", () => {
    const shell = stubShell({
      focusedModule: "sast",
      shellView: "module-run",
      moduleRun: {
        moduleId: "sast",
        toolName: "sast:scan",
        displayName: "SAST Scan",
        inputSummary: ".",
        startedAtMs: 0,
        completedAtMs: 5000,
        status: "error",
        steps: [],
        evidenceTail: [],
      } as unknown as NonNullable<ShellState["moduleRun"]>,
    });
    const out = renderToString(createElement(ModuleRunView, { shell }), 120, 30);
    expect(out).toContain("SAST Scan failed");
    expect(out).toContain("E_TOOL_RUN");
    expect(out).toContain("Next step:");
  });

  it("ActorTranscriptView · no actor focused shows actor-none-focused empty state", () => {
    const shell = stubShell({
      focusedActor: null,
      shellView: "actor-detail",
    });
    const out = renderToString(createElement(ActorTranscriptView, { shell }));
    expect(out).toContain("No actor focused");
    expect(out).toContain("/back");
  });

  it("CostView · no cost data shows the cost-no-data empty state", () => {
    const out = renderToString(createElement(CostView, { results: [], runningCostUsd: 0 }));
    expect(out).toContain("No cost data");
    expect(out).toContain("Ctrl+C");
  });
});

import { Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import { createManualUiClock, UiClockProvider } from "../../src/ui/clock.js";
import {
  ContextBuildView,
  domainStatusLabel,
  formatDurationMs,
  formatMmSs,
  manifestGlyph,
  phaseGlyph,
  phaseStatusLabel,
  progressBar,
} from "../../src/ui/components/ContextBuildView.js";
import { KeybindingsProvider } from "../../src/ui/hooks/useKeybindings.js";
import {
  type ContextBuildState,
  initContextBuildState,
  type ShellState,
} from "../../src/ui/state.js";

// ── Ink render harness (copied from component-snapshots.test.tsx) ──────────

class FrameCaptureStream extends Writable {
  columns: number;
  rows: number;
  isTTY = true;
  private frames: string[] = [];
  constructor(columns = 100, rows = 40) {
    super();
    this.columns = columns;
    this.rows = rows;
  }
  _write(chunk: string | Uint8Array, _enc: BufferEncoding, cb: (err?: Error | null) => void): void {
    this.frames.push(Buffer.from(chunk).toString("utf-8"));
    cb();
  }
  clearLine(): void {}
  clearScreenDown(): void {}
  cursorTo(): void {}
  moveCursor(): void {}
  lastFrame(): string {
    for (let i = this.frames.length - 1; i >= 0; i--) {
      const f = this.frames[i] ?? "";
      if (stripAnsi(f).trim().length > 0) return f;
    }
    return "";
  }
}

// biome-ignore lint/suspicious/noControlCharactersInRegex: strip ANSI for stable snapshots
const ANSI_RE = /(?:\[[0-9;?]*[ -/]*[@-~]|][^]*(?:|\\))/g;
function stripAnsi(s: string): string {
  return s.replace(ANSI_RE, "");
}

function renderToString(node: ReactElement, columns = 100): string {
  const stream = new FrameCaptureStream(columns);
  const clock = createManualUiClock(new Date("2026-04-23T14:08:15").getTime());
  const instance = render(
    createElement(UiClockProvider, { clock }, createElement(KeybindingsProvider, null, node)),
    {
      stdout: stream as unknown as Writable & NodeJS.WriteStream,
      debug: true,
    },
  );
  instance.unmount();
  return stripAnsi(stream.lastFrame())
    .replace(/^(?:\r?\n)+/, "")
    .trimEnd();
}

function stubShell(contextBuild: ContextBuildState | undefined): ShellState {
  return {
    modules: [],
    tools: [],
    focusedModule: null,
    shellView: "context-build",
    openFindingId: null,
    target: "./acme-api",
    workspace: "acme-api",
    history: [],
    commandHistory: [],
    moduleOptions: {},
    processing: contextBuild?.status === "running",
    contextBuild,
  };
}

function midGrepState(): ContextBuildState {
  const started = new Date("2026-04-23T14:08:03").getTime();
  return {
    runId: "9a21",
    repoRoot: "~/src/acme-api",
    startedAtMs: started,
    status: "running",
    phases: {
      manifests: { status: "done", startedAtMs: started, durationMs: 140 },
      walk: { status: "done", startedAtMs: started + 140, durationMs: 110 },
      "path-signals": { status: "done", startedAtMs: started + 250, durationMs: 20 },
      grep: { status: "running", startedAtMs: started + 270 },
      assemble: { status: "pending" },
    },
    manifests: {
      "package.json": "found",
      "go.mod": "miss",
      pyproject: "miss",
      "Cargo.toml": "miss",
      "native-build": "miss",
    },
    walk: { entries: 1847, dirs: 214, sourceFiles: 1102, cap: 4000 },
    pathSignals: ["auth/", "middleware/", "Dockerfile"],
    grep: {
      filesDone: 614,
      filesTotal: 1102,
      workers: 16,
      domainCap: 50,
      domains: [
        { name: "crypto-import", matches: 7, status: "active" },
        { name: "auth-session", matches: 31, status: "active" },
        { name: "protocol-parser", matches: 0, status: "skipped-no-ext" },
        { name: "unsafe-memory", matches: 50, status: "capped" },
      ],
    },
    pillars: {
      architecture: {
        languages: ["TypeScript"],
        frameworks: ["Next.js", "Express", "GraphQL"],
        entryPoints: ["src/pages/api/*", "src/server.ts"],
        ormOrDb: ["Prisma"],
      },
      trust: {
        sanitizationLibs: ["helmet", "DOMPurify"],
        authPatterns: ["JWT", "session-based"],
      },
    },
    tail: [
      { tsMs: started + 142, message: "probe   package.json → found" },
      { tsMs: started + 260, message: "path    auth/ middleware/ Dockerfile" },
      { tsMs: started + 281, message: "grep    spawn 16 workers over 1102 files" },
    ],
    tailExpanded: false,
  };
}

// ── View snapshots ─────────────────────────────────────────────────────────

describe("ContextBuildView", () => {
  it("initial state — all phases pending", () => {
    // Use a fixed runId so the snapshot is deterministic (the seed helper's
    // runId includes one random nibble by design).
    const state: ContextBuildState = {
      ...initContextBuildState("~/src/acme-api", new Date("2026-04-23T14:08:03").getTime()),
      runId: "TEST",
      tail: [],
    };
    const out = renderToString(createElement(ContextBuildView, { shell: stubShell(state) }));
    expect(out).toMatchSnapshot();
  });

  it("mid-grep — phases 1-3 done, phase 4 running with partial domain table", () => {
    const out = renderToString(
      createElement(ContextBuildView, { shell: stubShell(midGrepState()) }),
    );
    expect(out).toMatchSnapshot();
  });

  it("complete — all phases done, scan-context.json written", () => {
    const base = midGrepState();
    const completed: ContextBuildState = {
      ...base,
      status: "done",
      scanContextPath: "~/src/acme-api/.kuzushi/scan-context.json",
      totalMatches: 88,
      phases: {
        manifests: base.phases.manifests,
        walk: base.phases.walk,
        "path-signals": base.phases["path-signals"],
        grep: { status: "done", startedAtMs: base.phases.grep.startedAtMs, durationMs: 11_623 },
        assemble: { status: "done", startedAtMs: base.startedAtMs + 12_000, durationMs: 80 },
      },
      grep: {
        ...base.grep!,
        filesDone: base.grep!.filesTotal,
      },
    };
    const out = renderToString(createElement(ContextBuildView, { shell: stubShell(completed) }));
    expect(out).toMatchSnapshot();
  });
});

// ── Pure helper tests ──────────────────────────────────────────────────────

describe("ContextBuildView — pure helpers", () => {
  it("phaseGlyph covers all statuses", () => {
    expect(phaseGlyph("done").plain).toBe("✓");
    expect(phaseGlyph("running").plain).toBe("▸");
    expect(phaseGlyph("failed").plain).toBe("✗");
    expect(phaseGlyph("pending").plain).toBe("○");
  });

  it("phaseStatusLabel returns a label per status", () => {
    expect(stripAnsi(phaseStatusLabel({ status: "done" }))).toBe("done");
    expect(stripAnsi(phaseStatusLabel({ status: "running" }))).toBe("running");
    expect(stripAnsi(phaseStatusLabel({ status: "failed" }))).toBe("failed");
    expect(stripAnsi(phaseStatusLabel({ status: "pending" }))).toBe("pending");
  });

  it("manifestGlyph maps result to symbol", () => {
    expect(stripAnsi(manifestGlyph("found"))).toBe("✓");
    expect(stripAnsi(manifestGlyph("miss"))).toBe("—");
    expect(stripAnsi(manifestGlyph(undefined))).toBe("·");
  });

  it("domainStatusLabel covers all statuses", () => {
    expect(stripAnsi(domainStatusLabel("active"))).toBe("active");
    expect(stripAnsi(domainStatusLabel("capped"))).toBe("capped — this is fine");
    expect(stripAnsi(domainStatusLabel("skipped-no-ext"))).toBe("skipped (no matching ext)");
    expect(stripAnsi(domainStatusLabel("pending"))).toBe("pending");
  });

  it("progressBar always emits exactly `width` cells", () => {
    expect(progressBar(0, 100, 10)).toBe("▱▱▱▱▱▱▱▱▱▱");
    expect(progressBar(100, 100, 10)).toBe("▰▰▰▰▰▰▰▰▰▰");
    expect(progressBar(50, 100, 10)).toBe("▰▰▰▰▰▱▱▱▱▱");
    expect(progressBar(0, 0, 6)).toBe("▱▱▱▱▱▱");
    expect(progressBar(10, 0, 4)).toBe("▱▱▱▱");
  });

  it("formatMmSs formats mm:ss from ms", () => {
    expect(formatMmSs(0)).toBe("00:00");
    expect(formatMmSs(1_500)).toBe("00:01");
    expect(formatMmSs(65_000)).toBe("01:05");
    expect(formatMmSs(3_600_000)).toBe("60:00");
    expect(formatMmSs(-5)).toBe("00:00");
  });

  it("formatDurationMs always uses seconds", () => {
    expect(formatDurationMs(140)).toBe("0.14s");
    expect(formatDurationMs(1_234)).toBe("1.23s");
    expect(formatDurationMs(9_900)).toBe("9.90s");
    expect(formatDurationMs(12_345)).toBe("12.3s");
    expect(formatDurationMs(120_000)).toBe("120s");
  });
});

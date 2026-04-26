/**
 * Snapshot tests for the six highest-visibility Ink components shipped
 * in Phases A/B/C. Rather than a real `ink-testing-library` dependency
 * we use Ink's built-in `{ stdout }` hook to render into a capturing
 * Writable stream. Output is stripped of ANSI and trimmed before
 * snapshotting so the stored value is plain readable text that diffs
 * cleanly when the component layout changes.
 *
 * The point of these snapshots is *not* pixel-perfect stability — it's
 * to give us a failing-test trip-wire when someone accidentally changes
 * a component's structural output (missing labels, reordered sections,
 * dropped keybind hints). Regenerate with `vitest -u` when the change
 * is intentional.
 */

import { Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import { createManualUiClock, UiClockProvider } from "../../src/ui/clock.js";
import { BannerSplash } from "../../src/ui/components/BannerSplash.js";
import { CopilotShell } from "../../src/ui/components/CopilotShell.js";
import { FindingCard } from "../../src/ui/components/FindingCard.js";
import { ModuleCatalog } from "../../src/ui/components/ModuleCatalog.js";
import { ModuleHome } from "../../src/ui/components/ModuleHome.js";
import { PlanCard } from "../../src/ui/components/PlanCard.js";
import { ThreatDfdView } from "../../src/ui/components/ThreatDfdView.js";
import { BLACK_CIRCLE } from "../../src/ui/glyphs.js";
import { KeybindFooter } from "../../src/ui/primitives/KeybindFooter.js";
import { type ActionableFinding, createUIStore, type ShellState } from "../../src/ui/state.js";
import { createAbortStoryEvent, createShellStoryEvent } from "../../src/ui/task-story.js";

// ---------------------------------------------------------------------------
// Render harness
// ---------------------------------------------------------------------------

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

  clearLine(): void {
    // no-op test stub
  }

  clearScreenDown(): void {
    // no-op test stub
  }

  cursorTo(): void {
    // no-op test stub
  }

  moveCursor(): void {
    // no-op test stub
  }

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

// biome-ignore lint/suspicious/noControlCharactersInRegex: strips ANSI for stable snapshots
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

function stubFinding(overrides: Partial<ActionableFinding> = {}): ActionableFinding {
  return {
    verdict: "tp",
    confidence: 0.92,
    severity: "high",
    taskId: "sast",
    filePath: "src/api/admin.ts",
    startLine: 88,
    ruleId: "ssrf.no-allowlist",
    rationale:
      "Router mounts /admin/fetch before authMiddleware; handler calls fetch(req.query.url) with no allowlist.",
    fingerprint: "02160000abcd",
    title: "ssrf on /admin/fetch",
    displaySeverity: "high",
    verifyExploitable: 1,
    verifyPocPayload: "curl -s $BASE/admin/fetch?url=http://169.254.169.254/",
    corroboratingSignals: [],
    suppressionReasons: [],
    ...overrides,
  } as ActionableFinding;
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

describe("Ink component snapshots", () => {
  it("BannerSplash — wordmark + tip", () => {
    const out = renderToString(
      createElement(BannerSplash, {
        workspace: "acme-api",
        target: "./acme-api",
        tip: "example tip for snapshot stability",
      }),
    );
    expect(out).toMatchSnapshot();
  });

  it("ModuleCatalog — grouped by category with last-run chips", () => {
    const shell = stubShell({
      workspace: "acme-api",
      target: "./acme-api",
      moduleCatalog: [
        {
          id: "sast",
          displayName: "SAST",
          category: "offense",
          description: "40+ task pipeline",
          toolCount: 10,
          lastRunSummary: "ran 2h · 4 tp",
        },
        {
          id: "randori",
          displayName: "Randori",
          category: "intel",
          description: "PASTA threat model",
          toolCount: 4,
          lastRunSummary: "ran 2h · 12 threats",
        },
        {
          id: "shinsa",
          displayName: "Shinsa",
          category: "governance",
          description: "ISO 27001 + NIST 800-53",
          toolCount: 3,
        },
      ],
    });
    const out = renderToString(createElement(ModuleCatalog, { shell }));
    expect(out).toMatchSnapshot();
  });

  it("ModuleHome — tools table + last-run summary", () => {
    const shell = stubShell({
      focusedModule: "sast",
      shellView: "module",
      moduleCatalog: [
        {
          id: "sast",
          displayName: "SAST",
          category: "offense",
          description: "40+ task pipeline",
          toolCount: 2,
          lastRunSummary: "ran 2h · 4 tp",
          toolSummaries: [
            {
              name: "sast:scan",
              verb: "scan",
              description: "run the full pipeline",
              headless: true,
            },
            {
              name: "sast:triage",
              verb: "triage",
              description: "re-triage one finding",
              headless: true,
            },
          ],
        },
      ],
    });
    const out = renderToString(createElement(ModuleHome, { shell }));
    expect(out).toMatchSnapshot();
  });

  it("ModuleHome — collapses tools and last-run while processing", () => {
    const shell = stubShell({
      focusedModule: "context",
      shellView: "module",
      processing: true,
      moduleCatalog: [
        {
          id: "context",
          displayName: "Context",
          category: "intel",
          description: "Builds the application context snapshot.",
          toolCount: 1,
          toolSummaries: [
            {
              name: "context:build",
              verb: "build",
              description: "Generate the application context snapshot",
              headless: true,
            },
          ],
        },
      ],
    });
    const out = renderToString(createElement(ModuleHome, { shell }));
    // Header strip stays visible so the operator knows where they are.
    expect(out).toContain("intel");
    expect(out).toContain("Builds the application context snapshot");
    // Tools table + last-run sections are suppressed during the run.
    expect(out).not.toContain("TOOL NAME");
    expect(out).not.toContain("last run");
    expect(out).not.toContain("never run for this workspace");
  });

  it("ModuleHome — hides advanced pipeline steps and shows the hint line", () => {
    // Uses `sast` here because `context` and `threat-hunt` route through
    // the v3 module-home registry (Status / Actions / Last run), which
    // intentionally drops the tools table. Modules without a custom home
    // still render the legacy table + hidden-count hint.
    const shell = stubShell({
      focusedModule: "sast",
      shellView: "module",
      moduleCatalog: [
        {
          id: "sast",
          displayName: "SAST",
          category: "offense",
          description: "Static analysis with corroborating signals.",
          toolCount: 3,
          toolSummaries: [
            {
              name: "sast:scan",
              verb: "scan",
              description: "Run the canonical SAST scan",
              headless: true,
            },
            {
              name: "sast:context-gatherer",
              verb: "context-gatherer",
              description: "Internal DAG node: Context Gatherer",
              headless: true,
              hidden: true,
            },
            {
              name: "sast:app-model-build",
              verb: "app-model-build",
              description: "Internal DAG node: Application Model",
              headless: true,
              hidden: true,
            },
          ],
        },
      ],
    });
    const out = renderToString(createElement(ModuleHome, { shell }));
    // Only the public verb should appear — hidden ones must stay out of the table.
    expect(out).toContain("scan");
    expect(out).not.toContain("context-gatherer");
    expect(out).not.toContain("app-model-build");
    // Hint line announces the hidden count.
    expect(out).toContain("2 advanced pipeline steps");
    expect(out).toContain("/tools --all");
    // Status strip shows visible-tool count (1), not total (3).
    expect(out).toContain("1 tools");
  });

  it("CopilotShell — processing context run uses one live row and compact footer", () => {
    const store = createUIStore();
    const phase = createShellStoryEvent(
      {
        kind: "phase",
        status: "running",
        importance: "primary",
        message: "phase 1 (S1/S2/S3 scope)",
        runId: "run-1",
        turnId: "turn-1",
      },
      0,
    );
    store.update({
      mode: "shell",
      shell: {
        ...stubShell({
          focusedModule: "context",
          shellView: "module",
          processing: true,
          moduleCatalog: [
            {
              id: "context",
              displayName: "Context",
              category: "intel",
              description: "Builds the application context snapshot.",
              toolCount: 1,
              toolSummaries: [
                {
                  name: "context:build",
                  verb: "build",
                  description: "Generate the application context snapshot",
                  headless: true,
                },
              ],
            },
          ],
          history: [
            {
              type: "input",
              text: "run .",
              prompt: "kuzushi/context> ",
              timestamp: 0,
            },
            {
              type: "tool-call",
              id: "tc-context",
              tool: "context:build",
              displayName: "Build Context",
              inputHint: ".",
              text: "⏺ Build Context(.)",
              status: "running",
              timestamp: 0,
              liveActivities: [
                { id: "la-1", text: 'Glob "src/**/*" (200 files)' },
                { id: "la-2", text: "Read package.json (134 lines)" },
              ],
            },
          ],
          currentTool: {
            name: "context:build",
            displayName: "Build Context",
            startedAt: 0,
            lastEventAt: 0,
            historyEntryId: "tc-context",
            phase: phase.message,
            storyTail: [phase],
          },
          taskStory: {
            activeTurnId: "turn-1",
            activeRunIds: ["run-1"],
            startedAt: 0,
            abortStatus: "idle",
            events: [phase],
          },
        }),
      },
    });

    const out = renderToString(createElement(CopilotShell, { store }), 84);

    expect(out.match(/Build Context/g) ?? []).toHaveLength(1);
    // BLACK_CIRCLE is platform-dependent (`⏺` on macOS, `●` elsewhere).
    expect(out).toContain(`${BLACK_CIRCLE} Build Context(.)`);
    expect(out).toContain('⎿  Glob "src/**/*" (200 files)');
    expect(out).toContain("context · running · Ctrl+C interrupt · Ctrl+O details");
    expect(out).not.toContain("context home");
    expect(out).not.toContain("intel · 1 tools");
    expect(out).not.toContain("you are in");
    expect(out).not.toContain("task active");
  });

  it("CopilotShell — does not replay the welcome splash after shell remount", () => {
    const store = createUIStore();
    store.update({
      mode: "shell",
      shellSplashShown: true,
      shell: {
        ...stubShell({
          focusedModule: "sast",
          shellView: "module",
          processing: false,
          history: [],
        }),
      },
    });

    const out = renderToString(createElement(CopilotShell, { store }), 84);

    expect(out).toContain("sast home");
    expect(out).not.toContain("agentic SAST orchestration");
  });

  it("CopilotShell — hides aborted task status after returning idle", () => {
    const store = createUIStore();
    const aborted = createShellStoryEvent(
      createAbortStoryEvent("tool execution", "aborted", { turnId: "turn-1" }),
      65_000,
    );
    store.update({
      mode: "shell",
      shellSplashShown: true,
      shell: {
        ...stubShell({
          focusedModule: "sast",
          shellView: "module",
          processing: false,
          taskStory: {
            activeTurnId: "turn-1",
            activeRunIds: [],
            startedAt: 1_000,
            endedAt: 65_000,
            abortStatus: "aborted",
            abortReason: "tool execution",
            events: [aborted],
          },
        }),
      },
    });

    const out = renderToString(createElement(CopilotShell, { store }), 84);

    expect(out).not.toContain("sast · aborted");
    expect(out).not.toContain("Ctrl+C interrupt");
  });

  it("CopilotShell — task story shows frozen aborted elapsed without live controls", () => {
    const store = createUIStore();
    const aborted = createShellStoryEvent(
      createAbortStoryEvent("tool execution", "aborted", { turnId: "turn-1" }),
      66_000,
    );
    store.update({
      mode: "shell",
      shellSplashShown: true,
      shell: {
        ...stubShell({
          focusedModule: "sast",
          shellView: "task-story",
          processing: false,
          taskStory: {
            activeTurnId: "turn-1",
            activeRunIds: [],
            startedAt: 1_000,
            endedAt: 66_000,
            abortStatus: "aborted",
            abortReason: "tool execution",
            events: [aborted],
          },
        }),
      },
    });

    const out = renderToString(createElement(CopilotShell, { store }), 84);

    expect(out).toContain("sast · aborted · 01:05");
    expect(out).not.toContain("Ctrl+C interrupt");
  });

  it("CopilotShell — live tail is viewport-aware with overflow hint", () => {
    const store = createUIStore();
    store.update({
      mode: "shell",
      shell: {
        ...stubShell({
          focusedModule: "context",
          shellView: "module",
          processing: true,
          history: [
            {
              type: "tool-call",
              id: "tc-context",
              tool: "context:build",
              displayName: "Build Context",
              inputHint: ".",
              text: "⏺ Build Context(.)",
              status: "running",
              timestamp: 0,
              liveActivitiesDropped: 4,
              liveActivities: Array.from({ length: 18 }, (_, index) => ({
                id: `la-${index}`,
                text: `step ${17 - index}`,
              })),
            },
          ],
          currentTool: {
            name: "context:build",
            displayName: "Build Context",
            startedAt: 0,
            lastEventAt: 0,
            historyEntryId: "tc-context",
          },
        }),
      },
    });

    const out = renderToString(createElement(CopilotShell, { store }), 84, 18);

    expect(out).toContain("+14 earlier updates · Ctrl+O details");
    expect(out).toContain("step 10");
    expect(out).toContain("step 17");
    expect(out).not.toContain("step 9");
  });

  it("KeybindFooter — divider fits narrow terminals", () => {
    const out = renderToString(
      createElement(KeybindFooter, {
        bindings: [
          { keys: "Ctrl+C", label: "Interrupt" },
          { keys: "Ctrl+O", label: "Details", secondary: true },
        ],
      }),
      44,
    );
    const lines = out.split(/\r?\n/).filter((line) => line.trim().length > 0);

    expect(lines[0]?.length).toBeLessThanOrEqual(44);
    expect(lines.filter((line) => /^─+$/.test(line))).toHaveLength(1);
    expect(out).toContain("[Ctrl+C] Interrupt");
    expect(out).toContain("[Ctrl+O] Details");
  });

  it("FindingCard linear — state strip + evidence + timeline", () => {
    const out = renderToString(
      createElement(FindingCard, { finding: stubFinding(), mode: "linear" }),
    );
    expect(out).toMatchSnapshot();
  });

  it("PlanCard — option diff table with unsupported row", () => {
    const out = renderToString(
      createElement(PlanCard, {
        plan: {
          reasoning: "Operator wants a harder run focused on admin routes.",
          changes: [
            { option: "preset", current: "standard", proposed: "deep", why: '"run harder"' },
            { option: "maxTurnsPerHunt", current: 20, proposed: 26, why: "give hunters slack" },
          ],
          unsupported: ["focus on auth"],
          roughCostDeltaUsd: 0.35,
          roughWallClockDeltaSeconds: 90,
          toolName: "sast:scan",
          producedAt: 0,
          planCostUsd: 0.0023,
          source: "console-agent/r1",
        },
      }),
    );
    expect(out).toMatchSnapshot();
  });

  it("ThreatDfdView — trust zones + boundaries + flows", () => {
    const shell = stubShell({
      shellView: "threats",
      threatTab: "dfd",
      threatModel: {
        version: "1.0",
        dfd: {
          elements: [
            {
              id: "E1",
              type: "external-entity",
              name: "attacker",
              description: "unauth caller",
              trustZone: "internet",
            },
            {
              id: "P1",
              type: "process",
              name: "admin router",
              description: "Express /admin/*",
              trustZone: "app-vpc",
            },
            {
              id: "D1",
              type: "data-store",
              name: "IMDS",
              description: "AWS instance metadata",
              trustZone: "aws-meta",
            },
            {
              id: "F1",
              type: "data-flow",
              name: "fetch",
              description: "",
              trustZone: "",
              source: "P1",
              target: "D1",
              protocol: "http",
              dataClassification: "cloud-cred",
            },
          ],
          trustBoundaries: [
            {
              id: "B1",
              name: "perimeter",
              innerZone: "app-vpc",
              outerZone: "internet",
              crossingFlows: ["F1"],
            },
          ],
        },
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
      threatModelSource: { path: "/tmp/threat-model.json", mtimeMs: 0 },
    });
    const out = renderToString(createElement(ThreatDfdView, { shell }));
    expect(out).toMatchSnapshot();
  });
});

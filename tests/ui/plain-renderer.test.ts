import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { describeEmptyState } from "../../src/ui/error-format.js";
import { baseFinding, baseShell, baseSummary } from "../../src/ui/mock-fixtures.js";
import { registerPlainTextRenderer } from "../../src/ui/plain-renderer.js";
import { createUIStore, type ShellPlan } from "../../src/ui/state.js";

/**
 * Test harness: capture plain-renderer output via an injected `write`
 * sink. This avoids monkey-patching console.log and lets us assert both
 * line ordering and ANSI-free output deterministically.
 */
function attach(store: ReturnType<typeof createUIStore>): {
  lines: string[];
  unsub: () => void;
} {
  const lines: string[] = [];
  const unsub = registerPlainTextRenderer(store, {
    write: (line: string) => {
      lines.push(line);
    },
  });
  return { lines, unsub };
}

/**
 * Legacy harness — patches console.log. Retained for the Phase-D.5 suite
 * below, which predates the injectable sink. New tests should prefer
 * `attach()` above.
 */
function captureConsole(): {
  lines: string[];
  restore: () => void;
} {
  const lines: string[] = [];
  const original = console.log;
  console.log = (...args: unknown[]) => {
    lines.push(args.map((a) => (typeof a === "string" ? a : String(a))).join(" "));
  };
  return {
    lines,
    restore: () => {
      console.log = original;
    },
  };
}

const prevNoColor = process.env.NO_COLOR;

describe("plain-renderer Phase D.5 emitters", () => {
  beforeEach(() => {
    process.env.NO_COLOR = "1";
  });
  afterEach(() => {
    if (prevNoColor === undefined) delete process.env.NO_COLOR;
    else process.env.NO_COLOR = prevNoColor;
  });

  it("prints [shell] catalog on initial shell state", () => {
    const store = createUIStore();
    const cap = captureConsole();
    const unsub = registerPlainTextRenderer(store);
    store.update({ shell: baseShell({ moduleCatalog: [{} as never, {} as never] }) });
    unsub();
    cap.restore();
    expect(cap.lines.some((l) => l.includes("[shell] catalog · 2 modules"))).toBe(true);
  });

  it("prints [shell] module home on /use", () => {
    const store = createUIStore();
    const cap = captureConsole();
    const unsub = registerPlainTextRenderer(store);
    store.update({ shell: baseShell({ focusedModule: "sast", shellView: "module" }) });
    unsub();
    cap.restore();
    expect(cap.lines.some((l) => l.includes("[shell] module home (sast)"))).toBe(true);
    expect(cap.lines.some((l) => l.includes("## task selection"))).toBe(true);
    expect(cap.lines.some((l) => l.includes("commands: tasks"))).toBe(true);
  });

  it("emits typed shell history and terminal tool-call updates", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    const runningTool = {
      type: "tool-call" as const,
      id: "tc-1",
      tool: "sast:scan",
      displayName: "Scan",
      inputHint: "./repo",
      status: "running" as const,
      text: "⏺ Scan(./repo)",
      timestamp: 1,
    };

    store.update({
      mode: "shell",
      shell: baseShell({
        history: [
          { type: "input", text: "run scan", prompt: "kuzushi> ", timestamp: 0 },
          runningTool,
        ],
      }),
    });
    expect(lines).toContain("[input] kuzushi> run scan");
    expect(lines).toContain("[tool] Scan(./repo) started");

    lines.length = 0;
    store.update({
      shell: baseShell({
        history: [
          { type: "input", text: "run scan", prompt: "kuzushi> ", timestamp: 0 },
          {
            ...runningTool,
            status: "ok",
            elapsedSeconds: 4,
            resultOutput: "3 findings",
          },
        ],
      }),
    });
    unsub();

    expect(lines).toContain("[tool:ok] Scan · 3 findings · 4s");
    expect(lines).not.toContain("[input] kuzushi> run scan");
  });

  it("prints task story view with durable beats only", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);

    store.update({
      mode: "shell",
      shell: baseShell({
        shellView: "task-story",
        taskStory: {
          activeTurnId: "turn-1",
          activeRunIds: ["run-1"],
          startedAt: 1,
          abortStatus: "idle",
          events: [
            {
              id: "story-1",
              kind: "phase",
              status: "running",
              importance: "primary",
              message: "Building context",
              timestamp: 1,
            },
            {
              id: "story-2",
              kind: "activity",
              status: "running",
              importance: "debug",
              message: "Read · package.json",
              timestamp: 2,
            },
          ],
        },
      }),
    });
    unsub();

    const joined = lines.join("\n");
    expect(joined).toContain("# TASK STORY");
    expect(joined).toContain("[story:running] Building context");
    expect(joined).not.toContain("Read · package.json");
  });

  it("prints [threats] summary with element + threat counts", () => {
    const store = createUIStore();
    const cap = captureConsole();
    const unsub = registerPlainTextRenderer(store);
    store.update({
      shell: baseShell({
        shellView: "threats",
        threatTab: "stride",
        threatModel: {
          version: "2.0",
          dfd: {
            nodes: [
              { id: "P1", type: "process", name: "p", description: "", trustZone: "z" },
              { id: "E1", type: "external-entity", name: "e", description: "", trustZone: "z" },
            ],
            flows: [],
            trustBoundaries: [],
          },
          threats: [
            {
              id: "T1",
              targetElementIds: ["P1"],
              category: "spoofing",
              title: "",
              description: "",
              attackVector: "",
              preconditions: [],
              impact: "high",
              likelihood: "medium",
              existingMitigations: [],
              missingMitigations: [],
              relatedCwe: [],
              affectedFiles: [],
            },
          ],
          summary: {
            total: 1,
            bySeverity: {},
            byCategory: {
              spoofing: 1,
              tampering: 0,
              repudiation: 0,
              "information-disclosure": 0,
              "denial-of-service": 0,
              "elevation-of-privilege": 0,
            },
          },
        },
      }),
    });
    unsub();
    cap.restore();
    expect(
      cap.lines.some((l) => l.includes("[threats] stride · 2 nodes · 0 flows · 1 threats")),
    ).toBe(true);
  });

  it("prints [since <ref>] with changed-file count", () => {
    const store = createUIStore();
    const cap = captureConsole();
    const unsub = registerPlainTextRenderer(store);
    store.update({
      shell: baseShell({
        shellView: "findings",
        diffSince: { ref: "main", repoRoot: "/tmp", changedFiles: ["a.ts", "b.ts"] },
      }),
    });
    unsub();
    cap.restore();
    expect(cap.lines.some((l) => l.includes("[since main] 2 changed file(s)"))).toBe(true);
  });

  it("prints [plan] summary + first-3 changes when a plan lands", () => {
    const store = createUIStore();
    const cap = captureConsole();
    const unsub = registerPlainTextRenderer(store);
    const plan: ShellPlan = {
      reasoning: "x",
      changes: [
        { option: "preset", current: "standard", proposed: "deep", why: "a" },
        { option: "maxTurnsPerHunt", current: 20, proposed: 26, why: "b" },
      ],
      unsupported: ["focus on auth"],
      roughCostDeltaUsd: 0.35,
      roughWallClockDeltaSeconds: 90,
      toolName: "sast:scan",
      producedAt: 0,
      planCostUsd: 0.0023,
      source: "console-agent/r1",
    };
    store.update({ shell: baseShell({ pendingPlan: plan }) });
    unsub();
    cap.restore();
    const joined = cap.lines.join("\n");
    expect(joined).toContain("[plan] console-agent/r1");
    expect(joined).toContain("2 changes proposed");
    expect(joined).toContain("1 unsupported");
    expect(joined).toMatch(/preset:.*standard.*→.*deep/);
    expect(joined).toMatch(/maxTurnsPerHunt:.*20.*→.*26/);
  });
});

// ---------------------------------------------------------------------------
// Workstream 5 — plain-renderer parity with Ink views and overlays.
// ---------------------------------------------------------------------------

describe("plain-renderer view parity (Workstream 5)", () => {
  beforeEach(() => {
    process.env.NO_COLOR = "1";
  });
  afterEach(() => {
    if (prevNoColor === undefined) delete process.env.NO_COLOR;
    else process.env.NO_COLOR = prevNoColor;
  });

  it("catalog view emits '# CATALOG' heading", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({
      shell: baseShell({
        shellView: "catalog",
        moduleCatalog: [
          {
            id: "sast",
            displayName: "SAST",
            category: "offense",
            description: "static analysis",
            toolCount: 5,
          },
        ],
      }),
    });
    unsub();
    expect(lines).toContain("# CATALOG");
    expect(lines.join("\n")).toContain("## OFFENSE");
    expect(lines.join("\n")).toContain("- sast");
  });

  it("module view with no focused module routes through describeEmptyState", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({ shell: baseShell({ shellView: "module", focusedModule: null }) });
    unsub();
    const expected = describeEmptyState("module-none-focused");
    expect(lines).toContain(expected.title);
    expect(lines).toContain(expected.reason);
    expect(lines).toContain(expected.action);
  });

  it("module view with focused module prints tool list", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({
      shell: baseShell({
        shellView: "module",
        focusedModule: "sast",
        moduleCatalog: [
          {
            id: "sast",
            displayName: "SAST",
            category: "offense",
            description: "static analysis",
            toolCount: 2,
            toolSummaries: [
              { name: "sast:scan", verb: "scan", description: "Run scan", headless: true },
            ],
          },
        ],
      }),
    });
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("# MODULE  sast");
    expect(joined).toContain("## tools");
    expect(joined).toContain("- scan [headless]: Run scan");
  });

  it("tune view prints snapshot rows as label: value", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({
      shell: baseShell({
        shellView: "tune",
        focusedModule: "sast",
        tuneSnapshot: {
          preset: "deep",
          tasks: ["semgrep", "codeql"],
          verify: true,
          autoPatch: false,
          triageConcurrency: 3,
          model: "sonnet-4-6",
        },
      }),
    });
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("# TUNE  sast");
    expect(joined).toContain("preset: deep");
    expect(joined).toContain("tasks: semgrep, codeql");
    expect(joined).toContain("verify: on");
    expect(joined).toContain("autoPatch: off");
    expect(joined).toContain("triageConcurrency: 3");
  });

  it("options view prints option rows as the primary surface", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({
      shell: baseShell({
        shellView: "options",
        focusedModule: "context",
        optionsView: {
          toolName: "context:build",
          rows: [
            {
              optionName: "target",
              valueLabel: "/repo",
              defaultLabel: "—",
              description: "Path to the repository to analyze.",
              isSet: false,
            },
            {
              optionName: "model",
              valueLabel: "* anthropic:claude-sonnet-4-6",
              defaultLabel: "anthropic:claude-sonnet-4-6",
              description: "Model override for this session.",
              isSet: true,
            },
          ],
        },
      }),
    });
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("# OPTIONS  context");
    expect(joined).toContain("context:build · 2 options · 1 set");
    expect(joined).toContain("target: /repo");
    expect(joined).toContain("model: * anthropic:claude-sonnet-4-6");
    expect(joined).toContain("commands: set <option> <value>");
  });

  it("SAST task view prints task selection rows", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({
      shell: baseShell({
        shellView: "sast-tasks",
        focusedModule: "sast",
        sastTaskCursor: 1,
        tuneSnapshot: {
          preset: "standard",
          tasks: ["semgrep"],
          verify: false,
          autoPatch: false,
          triageConcurrency: 3,
          model: "sonnet-4-6",
        },
        moduleOptions: {
          "sast:scan": {
            disabledTasks: ["codeql"],
          },
        },
      }),
    });
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("# SAST TASKS");
    expect(joined).toContain("profile standard · auto + denylist");
    expect(joined).toContain("1 blocked");
    expect(joined).toContain("[x] enabled");
    expect(joined).toContain("active: codeql · Space allows codeql.");
    expect(joined).toContain("[ ] codeql");
  });

  it("findings view with no summary emits findings-never-scanned empty copy", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({ shell: baseShell({ shellView: "findings" }) });
    unsub();
    const expected = describeEmptyState("findings-never-scanned");
    expect(lines).toContain("# FINDINGS");
    expect(lines).toContain(expected.title);
    expect(lines).toContain(expected.action);
  });

  it("findings view with zero findings post-scan routes through findings-zero-after-scan", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({ phase: "summary", summary: baseSummary([]) });
    store.update({ shell: baseShell({ shellView: "findings" }) });
    unsub();
    const expected = describeEmptyState("findings-zero-after-scan");
    expect(lines).toContain(expected.title);
  });

  it("findings view lists F-NNNN aliases with severity tokens", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    const findings = [
      baseFinding({ fingerprint: "c000000000000001", displaySeverity: "critical", title: "SSRF" }),
      baseFinding({
        fingerprint: "h000000000000002",
        displaySeverity: "high",
        title: "SQL injection",
      }),
      baseFinding({
        fingerprint: "m000000000000003",
        displaySeverity: "medium",
        title: "Open redirect",
      }),
    ];
    store.update({ phase: "summary", summary: baseSummary(findings) });
    store.update({ shell: baseShell({ shellView: "findings" }) });
    unsub();
    const joined = lines.join("\n");
    // Severity order: critical > high > medium
    expect(joined).toContain("F-0001");
    expect(joined).toContain("F-0002");
    expect(joined).toContain("F-0003");
    expect(joined).toContain("SSRF");
    expect(joined).toMatch(/F-0001.*CRIT/);
    expect(joined).toMatch(/F-0002.*HIGH/);
    expect(joined).toMatch(/F-0003.*MED/);
    // counts line
    expect(joined).toContain("1 critical");
    expect(joined).toContain("1 high");
    expect(joined).toContain("1 medium");
  });

  it("finding view by F-NNNN alias prints severity/title/where labels", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    const finding = baseFinding({
      fingerprint: "abc1234567890000",
      displaySeverity: "high",
      title: "SQL injection in user lookup",
      filePath: "src/login.ts",
      startLine: 44,
      rationale: "Unsanitized input flows into SQL query.",
    });
    store.update({ phase: "summary", summary: baseSummary([finding]) });
    store.update({ shell: baseShell({ shellView: "finding", openFindingId: "F-0001" }) });
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("# FINDING  F-0001");
    expect(joined).toContain("severity: ");
    expect(joined).toMatch(/severity:.*HIGH/);
    expect(joined).toContain("title: SQL injection in user lookup");
    expect(joined).toContain("where: src/login.ts:44");
    expect(joined).toContain("rationale:");
    expect(joined).toContain("verdict: TP");
  });

  it("threat dfd tab with no threatModel routes through threat-model-missing empty copy", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({ shell: baseShell({ shellView: "threats", threatTab: "dfd" }) });
    unsub();
    const expected = describeEmptyState("threat-model-missing", { threatView: "dfd" });
    expect(lines).toContain("# THREATS  DFD");
    expect(lines).toContain(expected.title);
    expect(lines).toContain(expected.action);
  });

  it("threat stride tab prints per-category counts", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({
      shell: baseShell({
        shellView: "threats",
        threatTab: "stride",
        threatModel: {
          version: "1.0",
          dfd: { elements: [], trustBoundaries: [] },
          threats: [],
          summary: {
            total: 7,
            bySeverity: {},
            byCategory: {
              spoofing: 2,
              tampering: 1,
              repudiation: 0,
              "information-disclosure": 3,
              "denial-of-service": 0,
              "elevation-of-privilege": 1,
            },
          },
        },
      }),
    });
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("# THREATS  STRIDE");
    expect(joined).toContain("- spoofing: 2");
    expect(joined).toContain("- information-disclosure: 3");
  });

  it("threat stories tab prints narrative attacker stories (not STRIDE threats)", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({
      shell: baseShell({
        shellView: "threats",
        threatTab: "stories",
        threatModel: {
          version: "1.0",
          dfd: { elements: [], trustBoundaries: [] },
          threats: [
            {
              id: "T-1",
              elementId: "E1",
              category: "spoofing",
              title: "threat one",
              description: "desc",
              attackVector: "vec",
              preconditions: [],
              impact: "high",
              likelihood: "medium",
              existingMitigations: [],
              missingMitigations: [],
              relatedCwe: [],
              affectedFiles: [],
            },
            {
              id: "T-2",
              elementId: "E1",
              category: "tampering",
              title: "threat two",
              description: "desc",
              attackVector: "vec",
              preconditions: [],
              impact: "medium",
              likelihood: "low",
              existingMitigations: [],
              missingMitigations: [],
              relatedCwe: [],
              affectedFiles: [],
            },
          ],
          narrative: {
            overview: "overview",
            inputCategories: {
              attackerControlled: [],
              operatorControlled: [],
              developerControlled: [],
              externalServices: [],
              sandboxBoundary: [],
              assumptions: [],
            },
            attackerStories: [
              { title: "Story A", narrative: "a", mitigation: "m1", threatIds: ["T-1"] },
              { title: "Story B", narrative: "b", mitigation: "m2", threatIds: ["T-1", "T-2"] },
              { title: "Story C", narrative: "c", mitigation: "m3" },
            ],
            criticalityBuckets: { critical: [], high: [], medium: [], low: [] },
            outOfScope: [],
          },
          summary: {
            total: 2,
            bySeverity: { high: 1, medium: 1 },
            byCategory: {
              spoofing: 1,
              tampering: 1,
              repudiation: 0,
              "information-disclosure": 0,
              "denial-of-service": 0,
              "elevation-of-privilege": 0,
            },
          },
        },
      }),
    });
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("# THREATS  STORIES");
    expect(joined).toContain("total stories: 3");
    expect(joined).toContain("- Story A (1 linked threat)");
    expect(joined).toContain("- Story B (2 linked threats)");
    expect(joined).toContain("- Story C (0 linked threats)");
    expect(joined).not.toContain("threat one [high/medium]");
  });

  it("threat scope tab prints calibration, out-of-scope, and operator-edit counts", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({
      shell: baseShell({
        shellView: "threats",
        threatTab: "scope",
        threatModel: {
          version: "1.0",
          dfd: { elements: [], trustBoundaries: [] },
          threats: [],
          narrative: {
            overview: "overview",
            inputCategories: {
              attackerControlled: [],
              operatorControlled: [],
              developerControlled: [],
              externalServices: [],
              sandboxBoundary: [],
              assumptions: [],
            },
            attackerStories: [],
            criticalityBuckets: {
              critical: ["RCE in prod"],
              high: ["auth bypass", "tenant escape"],
              medium: [],
              low: ["non-sensitive metadata leak"],
            },
            outOfScope: ["supply-chain compromise", "physical access"],
          },
          userAnnotations: { T1: "accepted in lab env" },
          confirmedMitigations: ["mTLS on backend path"],
          dismissedThreats: ["T2", "T3"],
          summary: {
            total: 0,
            bySeverity: { critical: 0 },
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
    });
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("# THREATS  SCOPE");
    expect(joined).toContain("## criticality calibration");
    expect(joined).toContain("- critical: 1 example(s)");
    expect(joined).toContain("- high: 2 example(s)");
    expect(joined).toContain("out-of-scope items: 2");
    expect(joined).toContain("operator edits: 4 total");
    expect(joined).toContain("- annotations: 1");
    expect(joined).toContain("- confirmed mitigations: 1");
    expect(joined).toContain("- dismissed threats: 2");
  });

  it("threat summary tab prints its heading", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({
      shell: baseShell({
        shellView: "threats",
        threatTab: "summary",
        threatModel: {
          version: "1.0",
          dfd: { elements: [], trustBoundaries: [] },
          threats: [],
          summary: {
            total: 0,
            bySeverity: { critical: 0 },
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
    });
    unsub();
    expect(lines).toContain("# THREATS  SUMMARY");
  });

  it("threat views include recent agent actions when present", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({
      shell: baseShell({
        shellView: "threats",
        threatTab: "summary",
        threatModel: {
          version: "1.0",
          dfd: { elements: [], trustBoundaries: [] },
          threats: [],
          summary: {
            total: 0,
            bySeverity: { critical: 0 },
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
      agentActivity: new Map([
        [
          "fp-1",
          [
            {
              kind: "tool-progress",
              toolName: "carlini-threat-hunt",
              detail: "Enumerating top actors",
              index: 1,
              total: 3,
            },
            {
              kind: "tool-complete",
              toolName: "carlini-threat-hunt",
              detail: "Generated actor backlog",
              index: 2,
              total: 3,
            },
          ],
        ],
      ]),
    });
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("## agent actions");
    expect(joined).toContain("- carlini-threat-hunt: Generated actor backlog");
    expect(joined).toContain("- carlini-threat-hunt: Enumerating top actors");
  });
});

describe("plain-renderer overlays (Workstream 5)", () => {
  beforeEach(() => {
    process.env.NO_COLOR = "1";
  });
  afterEach(() => {
    if (prevNoColor === undefined) delete process.env.NO_COLOR;
    else process.env.NO_COLOR = prevNoColor;
  });

  it("plan-pending overlay prints 'apply? [y/n]' prompt line", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    const plan: ShellPlan = {
      reasoning: "x",
      changes: [{ option: "preset", current: "standard", proposed: "deep", why: "go deeper" }],
      unsupported: [],
      roughCostDeltaUsd: 0.5,
      roughWallClockDeltaSeconds: 60,
      toolName: "sast:scan",
      producedAt: 0,
      planCostUsd: 0.001,
      source: "planner/test",
    };
    store.update({ shell: baseShell({ pendingPlan: plan }) });
    unsub();
    expect(lines).toContain("apply? [y/n] ");
  });

  it("cost-cap halt overlay prints spent/cap and continue/abort prompt", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({
      costCapHalted: true,
      runningCostUsd: 2.35,
      costCapBudgetUsd: 2.0,
    });
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("[!] BUDGET EXCEEDED");
    expect(joined).toContain("spent: $2.35 of $2.00 cap (+$0.35 over)");
    expect(joined).toContain("continue (c) or abort (a)? ");
  });

  it("cost-cap halt prints once per armed halt (no duplicate on re-notify)", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({ costCapHalted: true, runningCostUsd: 1.0, costCapBudgetUsd: 0.5 });
    // Trigger another update that doesn't toggle costCapHalted.
    store.update({ runningCostUsd: 1.1 });
    unsub();
    const halts = lines.filter((l) => l.includes("BUDGET EXCEEDED"));
    expect(halts).toHaveLength(1);
  });

  it("rate-limit banner prints one-line '[throttled]' advisory", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({ throttle: { concurrency: 2, reason: "429 from anthropic" } });
    unsub();
    const match = lines.find((l) => l.includes("[throttled]"));
    expect(match).toBeDefined();
    expect(match).toContain("concurrency=2");
    expect(match).toContain("429 from anthropic");
  });

  it("rate-limit banner clears when throttle goes back to null", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({ throttle: { concurrency: 2, reason: "429" } });
    store.update({ throttle: null });
    unsub();
    expect(lines.some((l) => l.includes("[throttled] cleared"))).toBe(true);
  });
});

describe("plain-renderer output hygiene (Workstream 5)", () => {
  beforeEach(() => {
    process.env.NO_COLOR = "1";
  });
  afterEach(() => {
    if (prevNoColor === undefined) delete process.env.NO_COLOR;
    else process.env.NO_COLOR = prevNoColor;
  });

  it("emits no ANSI escape sequences under NO_COLOR", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    const plan: ShellPlan = {
      reasoning: "x",
      changes: [{ option: "preset", current: "standard", proposed: "deep", why: "a" }],
      unsupported: [],
      roughCostDeltaUsd: 0,
      roughWallClockDeltaSeconds: 0,
      toolName: "sast:scan",
      producedAt: 0,
      planCostUsd: 0.001,
      source: "planner/t",
    };
    // Drive every branch that emits styling: notices, results, shell views,
    // overlays. NO_COLOR should strip everything.
    store.update({ shell: baseShell({ shellView: "catalog" }) });
    store.update({
      shell: baseShell({
        shellView: "finding",
        openFindingId: "F-0001",
      }),
      summary: baseSummary([baseFinding({ displaySeverity: "critical", title: "c1" })]),
    });
    store.update({ shell: baseShell({ pendingPlan: plan }) });
    store.update({ throttle: { concurrency: 2, reason: "429" } });
    store.update({ costCapHalted: true, runningCostUsd: 1.0, costCapBudgetUsd: 0.5 });
    store.addResult({
      kind: "triage",
      verdict: "tp",
      confidence: 0.95,
      costUsd: 0.01,
      fingerprint: "abc123",
      index: 1,
      total: 3,
    });
    store.addNotice({ level: "warning", message: "sample notice" });
    unsub();
    // biome-ignore lint/suspicious/noControlCharactersInRegex: this test asserts ANSI-escape-free output
    const ansi = /\x1b\[/;
    for (const line of lines) {
      expect(ansi.test(line), `found ANSI escape in: ${JSON.stringify(line)}`).toBe(false);
    }
  });

  it("severity labels render as plain '■ CRIT / ▲ HIGH / ◆ MED ' without ANSI", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    const findings = [
      baseFinding({ fingerprint: "crit0", displaySeverity: "critical", title: "c" }),
      baseFinding({ fingerprint: "high0", displaySeverity: "high", title: "h" }),
      baseFinding({ fingerprint: "med00", displaySeverity: "medium", title: "m" }),
    ];
    store.update({ phase: "summary", summary: baseSummary(findings) });
    store.update({ shell: baseShell({ shellView: "findings" }) });
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("■ CRIT");
    expect(joined).toContain("▲ HIGH");
    expect(joined).toContain("◆ MED");
  });

  it("scan smoke: 3 findings flow from addResult → final summary render", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({ mode: "running", phase: "triaging", selectedForTriage: 3 });
    for (let i = 0; i < 3; i++) {
      store.addResult({
        kind: "triage",
        verdict: i < 2 ? "tp" : "fp",
        confidence: 0.9,
        costUsd: 0.01,
        fingerprint: `finger-${i}`,
        index: i + 1,
        total: 3,
      });
    }
    const findings = [
      baseFinding({ fingerprint: "finger-0", displaySeverity: "critical", title: "f0" }),
      baseFinding({ fingerprint: "finger-1", displaySeverity: "high", title: "f1" }),
      baseFinding({ fingerprint: "finger-2", displaySeverity: "medium", title: "f2" }),
    ];
    store.update({ phase: "summary", summary: baseSummary(findings) });
    unsub();
    const joined = lines.join("\n");
    // Triage stage banner
    expect(joined).toContain("Triaging 3 findings");
    // Per-result lines
    expect(joined).toContain("[1/3]");
    expect(joined).toContain("[2/3]");
    expect(joined).toContain("[3/3]");
    // Final summary block
    expect(joined).toContain("Kuzushi Scan Results");
    expect(joined).toContain("True positives:");
  });
});

describe("plain-renderer v3 views", () => {
  it("module-run idle prints the no-active-run advisory", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({
      shell: baseShell({
        shellView: "module-run",
        focusedModule: "carlini-threat-hunt",
      }),
    });
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("[run] carlini-threat-hunt · idle");
    expect(joined).toContain("# RUN");
    expect(joined).toContain("(no active run)");
  });

  it("module-run with steps prints the elapsed banner and step glyphs", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({
      shell: baseShell({
        shellView: "module-run",
        focusedModule: "carlini-threat-hunt",
        moduleRun: {
          moduleId: "carlini-threat-hunt",
          toolName: "carlini-threat-hunt:run",
          startedAtMs: Date.now() - 5_000,
          status: "running",
          steps: [
            { id: "boot", title: "load threat model", status: "done" },
            { id: "spawn", title: "spawn actor agents", status: "running" },
            { id: "merge", title: "merge findings", status: "pending" },
          ],
          evidenceTail: [],
        },
      }),
    });
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("[run] carlini-threat-hunt:carlini-threat-hunt:run");
    expect(joined).toContain("# RUN carlini-threat-hunt");
    expect(joined).toContain("status: running");
    expect(joined).toContain("✓ load threat model");
    expect(joined).toContain("→ spawn actor agents");
    expect(joined).toContain("○ merge findings");
  });

  it("module-run completed prints frozen status, cost, and concise findings", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    const findings = [
      baseFinding({
        fingerprint: "b-high",
        severity: "ERROR",
        filePath: "src/poc-executor/process.ts",
        startLine: 43,
        ruleId: "taint.command-injection",
        rationale: "Captured in scan-only mode — pending triage",
      }),
      baseFinding({
        fingerprint: "a-med",
        severity: "WARNING",
        filePath: "src/repo-walk.ts",
        startLine: 46,
        ruleId: "taint.path-traversal",
        rationale: "Captured in scan-only mode — pending triage",
      }),
    ];
    store.update({
      summary: baseSummary(findings),
      shell: baseShell({
        shellView: "module-run",
        focusedModule: "taint-iris",
        moduleRun: {
          moduleId: "taint-iris",
          source: "shell",
          toolName: "taint-iris:hunt",
          displayName: "Taint IRIS",
          startedAtMs: 0,
          completedAtMs: 1_146_000,
          status: "done",
          postProcessMode: "scan-only",
          findingCount: 2,
          costUsd: 3.16,
          steps: [
            { id: "taint-cwe-select", title: "taint-cwe-select", status: "done" },
            { id: "taint-iris", title: "taint-iris", status: "done", count: "2 findings" },
            { id: "report", title: "report", status: "done", count: "2 findings" },
          ],
          evidenceTail: [],
        },
      }),
    });
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("[run] taint-iris:taint-iris:hunt · 19m 6s · done");
    expect(joined).toContain("Taint IRIS complete · 2 findings · $3.16 · 19m 6s");
    expect(joined).toContain("scan-only: saved as needs_review; triage pending");
    expect(joined).toContain("F-0001");
    expect(joined).toContain("taint.command-injection");
    expect(joined).toContain("F-0002");
    expect(joined).toContain("taint.path-traversal");
    expect(joined).not.toContain("Captured in scan-only mode");
  });

  it("actor-detail with no focusedActor prints the (none) placeholder", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({
      shell: baseShell({
        shellView: "actor-detail",
        focusedModule: "carlini-threat-hunt",
        focusedActor: null,
      }),
    });
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("[actor] (none)");
    expect(joined).toContain("# ACTOR TRANSCRIPT");
    expect(joined).toContain("(no actor focused)");
    // Plain-text hint so non-TTY operators know how to leave the view.
    expect(joined).toContain("hint:");
    expect(joined).toContain("/back");
  });

  it("actor-detail emits one row per agent activity entry with the right glyph", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.addAgentActivity("carlini-threat-hunt:Authenticated_User:0", {
      kind: "tool-start",
      toolName: "Read",
      detail: "src/api.ts",
      index: 0,
      total: 1,
    });
    store.addAgentActivity("carlini-threat-hunt:Authenticated_User:0", {
      kind: "tool-complete",
      toolName: "Read",
      detail: "138 lines",
      index: 0,
      total: 1,
    });
    store.addAgentActivity("carlini-threat-hunt:Authenticated_User:0", {
      kind: "reasoning",
      detail: "checking sanitizers",
      index: 0,
      total: 1,
    });
    store.addAgentActivity("carlini-threat-hunt:Authenticated_User:0", {
      kind: "finding-preview",
      detail: "SSRF on /admin/fetch",
      index: 0,
      total: 1,
    });
    store.update({
      shell: baseShell({
        shellView: "actor-detail",
        focusedModule: "carlini-threat-hunt",
        focusedActor: "carlini-threat-hunt:Authenticated_User:0",
      }),
    });
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("[actor] carlini-threat-hunt:Authenticated_User:0 · 4 events");
    expect(joined).toContain("● Read");
    expect(joined).toContain("⎿ Read");
    expect(joined).toContain("✻ checking sanitizers");
    expect(joined).toContain("★ SSRF on /admin/fetch");
    // Hint line is appended after the transcript.
    expect(joined).toContain("hint: /back returns to module run");
  });

  it("prompts-editor empty list emits the (no prompt keys) advisory", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({
      shell: baseShell({
        shellView: "prompts-editor",
        focusedModule: "carlini-threat-hunt",
      }),
    });
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("[prompts] carlini-threat-hunt · 0 overrides");
    expect(joined).toContain("# PROMPTS");
    expect(joined).toContain("(no prompt keys)");
    expect(joined).toContain("hint: /back to return");
  });

  it("prompts-editor populated audit lists each verb + source", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({
      shell: baseShell({
        shellView: "prompts-editor",
        focusedModule: "carlini-threat-hunt",
        promptsEditor: {
          audit: [
            {
              moduleId: "carlini-threat-hunt",
              toolName: "carlini-threat-hunt:run",
              verb: "run",
              promptKey: "CARLINI_THREAT_HUNT_PROMPT",
              effective: {
                source: "file",
                filePath: "/repo/.kuzushi/prompts/carlini-threat-hunt/run.md",
              },
            },
          ],
        },
      }),
    });
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("[prompts] carlini-threat-hunt · 1 override");
    expect(joined).toContain("# PROMPTS");
    expect(joined).toContain("run  source=file");
    expect(joined).toContain(".kuzushi/prompts/carlini-threat-hunt/run.md");
  });
});

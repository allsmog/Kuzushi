import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { describeEmptyState } from "../../src/ui/error-format.js";
import { registerPlainTextRenderer } from "../../src/ui/plain-renderer.js";
import {
  type ActionableFinding,
  createUIStore,
  type ShellPlan,
  type ShellState,
  type SummaryData,
} from "../../src/ui/state.js";

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

function baseShell(overrides: Partial<ShellState> = {}): ShellState {
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

function baseFinding(overrides: Partial<ActionableFinding> = {}): ActionableFinding {
  return {
    verdict: "tp",
    confidence: 0.9,
    severity: "high",
    taskId: "sast",
    filePath: "src/x.ts",
    startLine: 10,
    ruleId: "test-rule",
    rationale: "sample rationale",
    fingerprint: "abcd1234ef567890",
    corroboratingSignals: [],
    suppressionReasons: [],
    ...overrides,
  };
}

function baseSummary(findings: ActionableFinding[] = []): SummaryData {
  return {
    repoName: "test-repo",
    verdictCounts: { tp: findings.length, fp: 0, needs_review: 0, by_design: 0 },
    totalTriaged: findings.length,
    triageCostUsd: 0,
    verificationCostUsd: 0,
    pocHarnessCostUsd: 0,
    variantAnalysisCostUsd: 0,
    exploitable: 0,
    notExploitable: 0,
    pocGenerated: 0,
    pocSkipped: 0,
    triageErrors: 0,
    verifyErrors: 0,
    pocHarnessErrors: 0,
    skippedLowConfidence: 0,
    skippedByFpFilter: 0,
    softSuppressedFindings: 0,
    skippedByLlmRescore: 0,
    corroboratedClusters: 0,
    verifyGateAutoAccepted: 0,
    verifyGateSkipped: 0,
    variantFindings: 0,
    dynamicConfirmed: 0,
    dynamicInteresting: 0,
    dynamicRejected: 0,
    dynamicErrors: 0,
    dynamicCostUsd: 0,
    incrementalCachedFiles: 0,
    incrementalRescannedFiles: 0,
    incrementalDepExpandedFiles: 0,
    patchGenerated: 0,
    patchVerified: 0,
    patchFailed: 0,
    patchErrors: 0,
    patchCostUsd: 0,
    budgetExceeded: false,
    failedTasks: [],
    tiPriorDegraded: false,
    exploitChains: [],
    actionableFindings: findings,
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
  });

  it("prints [threats] summary with element + threat counts", () => {
    const store = createUIStore();
    const cap = captureConsole();
    const unsub = registerPlainTextRenderer(store);
    store.update({
      shell: baseShell({
        shellView: "threat-stride",
        threatModel: {
          version: "1.0",
          dfd: {
            elements: [
              { id: "P1", type: "process", name: "p", description: "", trustZone: "z" },
              { id: "E1", type: "external-entity", name: "e", description: "", trustZone: "z" },
            ],
            trustBoundaries: [],
          },
          threats: [
            {
              id: "T1",
              elementId: "P1",
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
    expect(cap.lines.some((l) => l.includes("[threats] stride · 2 elements · 1 threats"))).toBe(
      true,
    );
  });

  it("prints [since <ref>] with changed-file count", () => {
    const store = createUIStore();
    const cap = captureConsole();
    const unsub = registerPlainTextRenderer(store);
    store.update({
      shell: baseShell({
        shellView: "diff-since",
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

  it("threat-dfd view with no threatModel routes through threat-model-missing empty copy", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({ shell: baseShell({ shellView: "threat-dfd" }) });
    unsub();
    const expected = describeEmptyState("threat-model-missing", { threatView: "dfd" });
    expect(lines).toContain("# THREATS  DFD");
    expect(lines).toContain(expected.title);
    expect(lines).toContain(expected.action);
  });

  it("threat-stride view prints per-category counts", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({
      shell: baseShell({
        shellView: "threat-stride",
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

  it("threat-stories prints narrative attacker stories (not STRIDE threats)", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({
      shell: baseShell({
        shellView: "threat-stories",
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

  it("threat-scope / threat-summary each print their heading", () => {
    const cases: Array<{
      view: ShellState["shellView"];
      head: string;
    }> = [
      { view: "threat-scope", head: "# THREATS  SCOPE" },
      { view: "threat-summary", head: "# THREATS  SUMMARY" },
    ];
    for (const c of cases) {
      const store = createUIStore();
      const { lines, unsub } = attach(store);
      store.update({
        shell: baseShell({
          shellView: c.view,
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
      expect(lines).toContain(c.head);
    }
  });

  it("diff-since view with no diffSince routes through diff-since-idle empty copy", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    store.update({ shell: baseShell({ shellView: "diff-since" }) });
    unsub();
    const expected = describeEmptyState("diff-since-idle");
    expect(lines).toContain("# DIFF SINCE  ?");
    expect(lines).toContain(expected.title);
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

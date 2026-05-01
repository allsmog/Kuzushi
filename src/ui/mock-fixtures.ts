/**
 * Mock fixtures for the Ink shell.
 *
 * These factories build minimal-but-valid `UIState` slices so tests and
 * the dev-only `scripts/mock-tui.ts` playthrough can seed a shell UI
 * without booting `CopilotCore`, the message bus, or any LLM.
 *
 * Promoted from private helpers in `tests/ui/plain-renderer.test.ts`.
 */
import type { ThreatModelDocument } from "../agents/tasks/threat-modeling/types.js";
import type {
  ActionableFinding,
  AgentActivityLine,
  ModuleRunSlice,
  PromptsEditorSlice,
  ShellHistoryEntry,
  ShellModuleCard,
  ShellState,
  SummaryData,
  TuneSnapshot,
} from "./state.js";

/** Deterministic 32-bit xorshift PRNG. Mirrors `perf/fixtures.ts` so mock
 * data stays repeatable across runs without crossing the src/ rootDir. */
function prng(seed: number): () => number {
  let s = seed | 0 || 0x9e3779b9;
  return () => {
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    return (s >>> 0) / 0xffffffff;
  };
}

const RULE_POOL = [
  "semgrep.xss",
  "semgrep.sqli",
  "semgrep.path-traversal",
  "semgrep.cmd-inject",
  "codeql.deserialization",
  "codeql.hardcoded-secret",
  "codeql.ssrf",
  "agentic.auth-bypass",
];

const FILE_POOL = [
  "src/api/login.ts",
  "src/api/admin.ts",
  "src/api/upload.ts",
  "src/worker/runner.ts",
  "src/auth/session.ts",
  "src/db/users.ts",
  "src/graphql/server.ts",
  "src/util/render.ts",
];

const ACTIONABLE_SEVERITY_POOL: Array<ActionableFinding["displaySeverity"]> = [
  "critical",
  "high",
  "medium",
  "low",
];

const ACTIONABLE_TITLE_POOL = [
  "SSRF in webhook fetcher",
  "SQL injection in user lookup",
  "Path traversal in file download",
  "Command injection in tag rendering",
  "Hardcoded secret in CI config",
  "Open redirect in login flow",
  "XXE in XML import",
  "Auth bypass via signed-cookie reuse",
  "Race condition in invite acceptance",
  "Deserialization gadget in cache",
];

/**
 * Build a minimal `ShellState` with all required fields. Pass `overrides`
 * to set view-specific fields (e.g. `shellView`, `focusedModule`,
 * `threatTab`). This is the canonical seed shape — view dispatchers in
 * `CopilotShell.tsx` early-return when fields they read are missing, so
 * always merge what the chosen `shellView` actually needs.
 */
export function baseShell(overrides: Partial<ShellState> = {}): ShellState {
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

/**
 * One `ActionableFinding` with sane defaults — override only the fields
 * the test cares about.
 */
export function baseFinding(overrides: Partial<ActionableFinding> = {}): ActionableFinding {
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

/**
 * Build a `SummaryData` with `actionableFindings = findings`. Counts and
 * cost fields zero out unless the caller cares.
 */
export function baseSummary(findings: ActionableFinding[] = []): SummaryData {
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

/**
 * Build N `ActionableFinding`s with realistic mixed severities using a
 * deterministic PRNG so the output is stable across runs.
 *
 * Severity mix covers all four buckets so virtualization tests render the
 * full spread of severity glyphs (`■ CRIT / ▲ HIGH / ◆ MED / ◇ LOW`).
 */
export function makeActionableFindings(count: number, seed = 42): ActionableFinding[] {
  const rng = prng(seed);
  const out: ActionableFinding[] = [];
  for (let i = 0; i < count; i++) {
    const severity = ACTIONABLE_SEVERITY_POOL[Math.floor(rng() * ACTIONABLE_SEVERITY_POOL.length)];
    const title = ACTIONABLE_TITLE_POOL[i % ACTIONABLE_TITLE_POOL.length];
    const filePath = FILE_POOL[Math.floor(rng() * FILE_POOL.length)];
    const ruleId = RULE_POOL[Math.floor(rng() * RULE_POOL.length)];
    const startLine = 1 + Math.floor(rng() * 400);
    out.push({
      verdict: "tp",
      confidence: 0.6 + rng() * 0.4,
      severity: severity ?? "medium",
      displaySeverity: severity,
      taskId: "sast",
      filePath,
      startLine,
      ruleId,
      rationale: `User-controlled input flows into ${ruleId.split(".")[1]} sink.`,
      fingerprint: `mock-${seed}-${i.toString(16).padStart(4, "0")}`,
      title: `${title} (#${i + 1})`,
      attackNarrative:
        "Attacker controls the input; sink runs without sanitization in the request path.",
      corroboratingSignals: [],
      suppressionReasons: [],
    } satisfies ActionableFinding);
  }
  return out;
}

/**
 * Build a deterministic `ThreatModelDocument` with two trust zones, four
 * nodes, and one threat per STRIDE category. Suitable for all
 * `threats-*` shell views.
 */
export function mockThreatModel(): ThreatModelDocument {
  return {
    version: "2.0",
    dfd: {
      nodes: [
        {
          id: "EE-user",
          type: "external-entity",
          name: "End User",
          description: "Browser session",
          trustZone: "internet",
        },
        {
          id: "P-api",
          type: "process",
          name: "API Server",
          description: "REST API gateway",
          trustZone: "app",
        },
        {
          id: "P-worker",
          type: "process",
          name: "Background Worker",
          description: "Async job runner",
          trustZone: "app",
        },
        {
          id: "DS-db",
          type: "data-store",
          name: "Postgres",
          description: "Primary database",
          trustZone: "data",
        },
      ],
      flows: [
        {
          id: "F1",
          name: "Browser API request",
          description: "End user sends HTTPS requests to the API server",
          sourceId: "EE-user",
          targetId: "P-api",
          protocol: "HTTPS",
          dataClassification: "session",
          trustBoundaryIds: ["TB-edge"],
        },
        {
          id: "F2",
          name: "API database query",
          description: "API reads and writes user records",
          sourceId: "P-api",
          targetId: "DS-db",
          protocol: "postgres",
          dataClassification: "PII",
          trustBoundaryIds: ["TB-data"],
        },
      ],
      trustBoundaries: [
        {
          id: "TB-edge",
          name: "Public edge",
          innerZone: "app",
          outerZone: "internet",
          crossingFlowIds: ["F1"],
        },
        {
          id: "TB-data",
          name: "Data plane",
          innerZone: "data",
          outerZone: "app",
          crossingFlowIds: ["F2"],
        },
      ],
    },
    threats: [
      {
        id: "T1",
        targetElementIds: ["P-api"],
        actorIds: ["EE-user"],
        flowIds: ["F1"],
        category: "spoofing",
        title: "Forged session token",
        description: "Attacker reuses an unrotated session cookie.",
        attackVector: "Steal cookie via XSS or shared device.",
        preconditions: ["session cookie not bound to client fingerprint"],
        impact: "high",
        likelihood: "medium",
        existingMitigations: ["HttpOnly + Secure flags"],
        missingMitigations: ["session rotation on privilege escalation"],
        relatedCwe: ["CWE-384"],
        affectedFiles: [{ filePath: "src/auth/session.ts", startLine: 42 }],
      },
      {
        id: "T2",
        targetElementIds: ["P-api"],
        actorIds: ["EE-user"],
        flowIds: ["F1"],
        category: "tampering",
        title: "Unsigned admin payload",
        description: "Admin write paths accept unsigned JSON.",
        attackVector: "MITM modifies request body in transit.",
        preconditions: ["TLS terminated upstream"],
        impact: "high",
        likelihood: "low",
        existingMitigations: [],
        missingMitigations: ["request signing on admin endpoints"],
        relatedCwe: ["CWE-345"],
        affectedFiles: [{ filePath: "src/api/admin.ts", startLine: 88 }],
      },
      {
        id: "T3",
        targetElementIds: ["P-worker"],
        actorIds: ["EE-user"],
        category: "repudiation",
        title: "Audit log gap on retry",
        description: "Job retries dedupe audit lines, hiding actor identity.",
        attackVector: "Trigger duplicate jobs to suppress audit visibility.",
        preconditions: ["dedup key includes actor id"],
        impact: "medium",
        likelihood: "medium",
        existingMitigations: [],
        missingMitigations: ["per-attempt audit emission"],
        relatedCwe: ["CWE-117"],
        affectedFiles: [{ filePath: "src/worker/runner.ts", startLine: 130 }],
      },
      {
        id: "T4",
        targetElementIds: ["DS-db"],
        actorIds: ["EE-user"],
        flowIds: ["F2"],
        category: "information-disclosure",
        title: "PII in log payloads",
        description: "Error logs include raw user records.",
        attackVector: "Logs aggregator search exposes records to support staff.",
        preconditions: ["log shipping bypasses redaction"],
        impact: "high",
        likelihood: "high",
        existingMitigations: ["redacted email field"],
        missingMitigations: ["redact phone + address fields"],
        relatedCwe: ["CWE-532"],
        affectedFiles: [{ filePath: "src/api/error-handler.ts", startLine: 24 }],
      },
      {
        id: "T5",
        targetElementIds: ["P-api"],
        actorIds: ["EE-user"],
        flowIds: ["F1"],
        category: "denial-of-service",
        title: "Unbounded query expansion",
        description: "GraphQL allows deeply nested queries without depth limits.",
        attackVector: "Attacker submits 30-level-deep query and exhausts CPU.",
        preconditions: ["no query-cost analysis"],
        impact: "medium",
        likelihood: "medium",
        existingMitigations: [],
        missingMitigations: ["depth + complexity limits"],
        relatedCwe: ["CWE-770"],
        affectedFiles: [{ filePath: "src/graphql/server.ts", startLine: 56 }],
      },
      {
        id: "T6",
        targetElementIds: ["P-worker"],
        actorIds: ["EE-user"],
        category: "elevation-of-privilege",
        title: "Privileged job runner",
        description: "Worker runs jobs as the database superuser role.",
        attackVector: "Compromise of worker process yields full DB control.",
        preconditions: ["worker bound to admin DB role"],
        impact: "critical",
        likelihood: "low",
        existingMitigations: ["network isolation"],
        missingMitigations: ["least-privilege DB role per job kind"],
        relatedCwe: ["CWE-269"],
        affectedFiles: [{ filePath: "src/worker/db.ts", startLine: 12 }],
      },
    ],
    summary: {
      total: 6,
      bySeverity: { critical: 1, high: 3, medium: 2 },
      byCategory: {
        spoofing: 1,
        tampering: 1,
        repudiation: 1,
        "information-disclosure": 1,
        "denial-of-service": 1,
        "elevation-of-privilege": 1,
      },
    },
    narrative: {
      overview:
        "Three-tier API + worker + Postgres. The API is internet-facing; the worker " +
        "trusts queue messages produced by the API.",
      inputCategories: {
        attackerControlled: ["HTTP request bodies", "query parameters", "uploaded files"],
        operatorControlled: ["env vars", "feature flags"],
        developerControlled: ["seed data", "migration scripts"],
        externalServices: ["Stripe webhooks", "S3 signed URLs"],
        sandboxBoundary: ["worker container ulimits", "DB role per service"],
        assumptions: ["TLS terminates at the edge proxy", "secrets manager never leaks to logs"],
      },
      attackerStories: [
        {
          title: "Session reuse via stolen cookie",
          narrative:
            "Mallory steals Alice's session via a public terminal. Without rotation on privilege escalation, " +
            "Mallory can elevate from member → admin without re-auth.",
          mitigation: "Rotate session ids on permission boundary changes.",
          threatIds: ["T1"],
        },
        {
          title: "Audit gap on duplicate jobs",
          narrative:
            "Eve fires the same admin action twice. The retry deduper hides the second call's audit trail, " +
            "so an investigator can't tell which actor did what.",
          mitigation: "Emit one audit line per attempt, not per logical event.",
          threatIds: ["T3"],
        },
        {
          title: "PII leak via support search",
          narrative:
            "Support agents search log aggregator and see customer phone numbers in error payloads.",
          mitigation: "Redact PII fields server-side before shipping logs.",
          threatIds: ["T4"],
        },
      ],
      criticalityBuckets: {
        critical: ["RCE in worker", "DB superuser compromise"],
        high: ["session forgery", "PII in logs", "admin payload tamper"],
        medium: ["DoS via expensive queries", "audit log gaps"],
        low: ["non-sensitive metadata leak"],
      },
      outOfScope: ["physical access", "supply-chain compromise of base image"],
    },
    userAnnotations: { T1: "tracked in JIRA SEC-211" },
    confirmedMitigations: ["HttpOnly + Secure on all session cookies"],
    dismissedThreats: [],
    userEdited: false,
  };
}

/**
 * Build a `ModuleRunSlice` with the requested step count + status. Caller
 * picks `status` to render running ('→'), done ('✓'), or pending ('○')
 * glyphs in `ModuleRunView`.
 */
export function mockModuleRun(
  opts: {
    moduleId?: string;
    toolName?: string;
    status?: ModuleRunSlice["status"];
    evidenceLines?: number;
    startedSecondsAgo?: number;
  } = {},
): ModuleRunSlice {
  const moduleId = opts.moduleId ?? "carlini-threat-hunt";
  const toolName = opts.toolName ?? `${moduleId}:run`;
  const status = opts.status ?? "running";
  const startedAtMs = Date.now() - (opts.startedSecondsAgo ?? 8) * 1000;
  const evidence = mockEvidenceLines(opts.evidenceLines ?? 6);

  return {
    moduleId,
    toolName,
    displayName: "Hunt",
    inputSummary: "./repo · 4 actors",
    startedAtMs,
    status,
    steps: [
      { id: "boot", title: "load threat model", status: "done", elapsedSeconds: 1 },
      {
        id: "spawn",
        title: "spawn actor agents",
        status: status === "running" ? "running" : "done",
        count: status === "running" ? "3/4 actors" : "4/4 actors",
      },
      {
        id: "merge",
        title: "merge findings",
        status: status === "done" ? "done" : "pending",
        count: status === "done" ? "12 paths" : undefined,
      },
    ],
    evidenceTail: evidence,
    costUsd: status === "done" ? 1.42 : 0.31,
    artifacts:
      status === "done"
        ? [
            { label: "summary", path: ".kuzushi/runs/abcd/summary.json", size: "12 KB" },
            { label: "trace", path: ".kuzushi/runs/abcd/triage.jsonl", size: "98 KB" },
          ]
        : undefined,
  };
}

/** Build a sequence of synthetic agent-activity lines. */
export function mockEvidenceLines(count: number): AgentActivityLine[] {
  const samples: Array<Omit<AgentActivityLine, "index" | "total">> = [
    { kind: "tool-start", toolName: "Read", detail: "src/api.ts" },
    { kind: "tool-complete", toolName: "Read", detail: "138 lines" },
    { kind: "reasoning", detail: "checking sanitizers in admin path" },
    { kind: "tool-start", toolName: "Grep", detail: '"sql.query\\("' },
    { kind: "tool-complete", toolName: "Grep", detail: "4 matches" },
    { kind: "finding-preview", detail: "SSRF on /admin/fetch" },
    { kind: "summary", detail: "actor concluded — 1 finding" },
    { kind: "tool-start", toolName: "Read", detail: "src/auth/session.ts" },
  ];
  const out: AgentActivityLine[] = [];
  for (let i = 0; i < count; i++) {
    const sample = samples[i % samples.length];
    out.push({ ...sample, index: i, total: count });
  }
  return out;
}

/**
 * Build a populated per-actor activity map, keyed by an actor fingerprint
 * the focused-actor drill-in expects (e.g. `carlini-threat-hunt:Authenticated_User:0`).
 */
export function mockAgentActivity(
  opts: { fingerprint?: string; count?: number } = {},
): Map<string, AgentActivityLine[]> {
  const fingerprint = opts.fingerprint ?? "carlini-threat-hunt:Authenticated_User:0";
  const lines = mockEvidenceLines(opts.count ?? 6);
  return new Map([[fingerprint, lines]]);
}

/** Build the v2 catalog cards for a small set of representative modules. */
export function mockShellModuleCards(): ShellModuleCard[] {
  return [
    {
      id: "sast",
      displayName: "SAST",
      category: "offense",
      description: "Static analysis (Semgrep + CodeQL).",
      rank: "great",
      toolCount: 2,
      lastRunAt: Date.now() - 2 * 60 * 60 * 1000,
      lastRunSummary: "ran 2h ago · 4 tp",
      toolSummaries: [
        {
          name: "sast:scan",
          verb: "scan",
          description: "Run static analysis over the repo.",
          headless: true,
        },
        {
          name: "sast:diff",
          verb: "diff",
          description: "Re-scan only files changed since a ref.",
          headless: true,
        },
      ],
    },
    {
      id: "carlini-threat-hunt",
      displayName: "Carlini Threat Hunt",
      category: "offense",
      description: "Per-actor agentic vulnerability hunting.",
      rank: "good",
      toolCount: 1,
      lastRunAt: Date.now() - 30 * 60 * 1000,
      lastRunSummary: "ran 30m ago · 12 paths",
      toolSummaries: [
        {
          name: "carlini-threat-hunt:run",
          verb: "run",
          description: "Spawn one agent per actor and hunt.",
          headless: false,
        },
      ],
    },
    {
      id: "context",
      displayName: "Context",
      category: "intel",
      description: "Repo + threat-model context generation.",
      rank: "normal",
      toolCount: 2,
      toolSummaries: [
        {
          name: "context:build",
          verb: "build",
          description: "Build scan context.",
          headless: true,
        },
        {
          name: "context:show",
          verb: "show",
          description: "Display the cached context.",
          headless: false,
        },
      ],
    },
    {
      id: "randori",
      displayName: "Randori",
      category: "governance",
      description: "Threat-model authoring (PASTA stages s1-s5).",
      rank: "good",
      toolCount: 1,
      toolSummaries: [
        {
          name: "randori:build",
          verb: "build",
          description: "Generate the DFD + STRIDE threat model.",
          headless: true,
        },
      ],
    },
  ];
}

/** Build a `TuneSnapshot` representative of a real config slice. */
export function mockTuneSnapshot(moduleId = "sast"): TuneSnapshot {
  return {
    preset: "standard",
    tasks: ["semgrep", "codeql", "agentic"],
    verify: true,
    autoPatch: false,
    triageConcurrency: 4,
    model: "claude-sonnet-4-6",
    houseRules: `# House rules for ${moduleId}\n- Treat repo paths under \`vendor/\` as third-party.\n- Skip findings older than 90 days.\n`,
    houseRulesPath: `.kuzushi/house-rules/${moduleId}.md`,
  };
}

/**
 * Build a few `ShellHistoryEntry` items including a completed `tool-call`
 * — exercises the `<Static>` partition in `CopilotShell.tsx:389-417` so
 * mock scenarios that show off history rendering get the same code path
 * as real sessions.
 */
export function mockShellHistoryEntries(): ShellHistoryEntry[] {
  return [
    {
      type: "input",
      text: "/use sast",
      prompt: "kuzushi > ",
      timestamp: Date.now() - 3 * 60_000,
    },
    {
      type: "output",
      text: "Focused on sast.",
      timestamp: Date.now() - 3 * 60_000 + 200,
    },
    {
      type: "input",
      text: "scan ./repo",
      prompt: "kuzushi sast > ",
      timestamp: Date.now() - 2 * 60_000,
    },
    {
      type: "tool-call",
      id: "tc-1",
      tool: "sast:scan",
      displayName: "Scan",
      inputHint: "./repo",
      status: "ok",
      elapsedSeconds: 18,
      resultOutput: "4 findings · 2 critical · 1 high",
      text: "⏺ Scan(./repo)",
      timestamp: Date.now() - 2 * 60_000 + 100,
    },
  ];
}

/**
 * Build a populated `PromptsEditorSlice` audit table for the module's single
 * exposed run prompt.
 */
export function mockPromptsEditor(moduleId = "carlini-threat-hunt"): PromptsEditorSlice {
  return {
    audit: [
      {
        moduleId,
        toolName: `${moduleId}:run`,
        verb: "run",
        promptKey: "CARLINI_THREAT_HUNT_PROMPT",
        effective: { source: "default" },
      },
    ],
  };
}

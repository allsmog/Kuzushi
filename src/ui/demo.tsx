#!/usr/bin/env tsx
/**
 * Visual test harness for the Kuzushi terminal UI.
 *
 * Full pipeline simulation (default):
 *   pnpm tsx src/ui/demo.tsx
 *
 * Single shell-view snapshot (Ink UI v2 screens):
 *   pnpm tsx src/ui/demo.tsx --shell-view=catalog
 *   pnpm tsx src/ui/demo.tsx --shell-view=module
 *   pnpm tsx src/ui/demo.tsx --shell-view=tune
 *   pnpm tsx src/ui/demo.tsx --shell-view=findings
 *   pnpm tsx src/ui/demo.tsx --shell-view=finding
 */
import { render } from "ink";
import { createElement } from "react";
import { App } from "./App.js";
import type {
  ActionableFinding,
  ShellModuleCard,
  ShellModuleToolSummary,
  ShellView,
  SummaryData,
} from "./state.js";
import { createUIStore, type UIStore } from "./state.js";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function parseShellViewArg(): ShellView | null {
  const arg = process.argv.find((a) => a.startsWith("--shell-view="));
  if (!arg) return null;
  const value = arg.split("=")[1] ?? "";
  if (
    value === "catalog" ||
    value === "module" ||
    value === "tune" ||
    value === "findings" ||
    value === "finding"
  ) {
    return value;
  }
  console.error(`Unknown shell-view: ${value}`);
  process.exit(2);
}

async function main(): Promise<void> {
  const shellViewArg = parseShellViewArg();
  const store = createUIStore();
  const instance = render(createElement(App, { store }));

  if (shellViewArg) {
    await runShellViewDemo(store, shellViewArg);
    await sleep(60_000);
    instance.unmount();
    return;
  }

  // --- Banner ---
  store.update({ bannerShown: true });
  await sleep(800);

  // --- Config banner ---
  store.update({
    configBanner: {
      model: "anthropic:claude-opus",
      tasks: ["semgrep", "codeql", "agentic"],
      severity: ["ERROR", "WARNING"],
      concurrency: 5,
      backend: "pi-ai",
    },
  });
  await sleep(600);

  // --- Init pipeline stages ---
  store.initStages([
    { id: "scan", label: "Scan" },
    { id: "triage", label: "Triage" },
    { id: "verify", label: "Verify" },
    { id: "poc", label: "PoC Harness" },
    { id: "report", label: "Report" },
  ]);
  store.activateStage("scan", "semgrep, codeql, agentic");
  store.update({
    phase: "scanning",
    tasks: ["semgrep", "codeql", "agentic"],
  });

  // --- Individual scanner sub-tasks start in parallel ---
  store.upsertSubTask("scan", {
    id: "semgrep",
    label: "semgrep",
    status: "active",
    startedAt: Date.now(),
  });
  store.upsertSubTask("scan", {
    id: "codeql",
    label: "codeql",
    status: "active",
    startedAt: Date.now(),
  });
  store.upsertSubTask("scan", {
    id: "agentic",
    label: "agentic",
    status: "pending",
  });
  await sleep(1500);

  // Semgrep finishes first
  store.upsertSubTask("scan", {
    id: "semgrep",
    label: "semgrep",
    status: "done",
    elapsedMs: 1500,
  });
  await sleep(800);

  // Agentic starts
  store.upsertSubTask("scan", {
    id: "agentic",
    label: "agentic",
    status: "active",
    startedAt: Date.now(),
  });
  await sleep(1200);

  // CodeQL finishes
  store.upsertSubTask("scan", {
    id: "codeql",
    label: "codeql",
    status: "done",
    elapsedMs: 3500,
  });
  await sleep(800);

  // Agentic finishes
  store.upsertSubTask("scan", {
    id: "agentic",
    label: "agentic",
    status: "done",
    elapsedMs: 2000,
  });
  await sleep(500);

  // --- Scan complete ---
  store.update({
    totalFindings: 200,
    selectedForTriage: 15,
    startBannerShown: true,
    repoName: "my-app",
  });
  await sleep(500);

  // --- Triage start ---
  store.activateStage("triage", "15 findings via claude-opus");
  store.update({
    phase: "triaging",
    model: "anthropic:claude-opus",
    selectedForTriage: 15,
    progress: { current: 0, total: 15 },
  });
  await sleep(600);

  // --- Simulate triage with agent activity ---
  const fingerprints = [
    "a1b2c3d4e5f6",
    "f6e5d4c3b2a1",
    "111222333444",
    "555666777888",
    "999000aabbcc",
    "ddeeff112233",
    "aabbccddeeff",
    "112233445566",
    "778899001122",
    "334455667788",
    "990011223344",
    "556677889900",
    "abcdef123456",
    "654321fedcba",
    "abcabc123123",
  ];

  const verdicts: Array<"tp" | "fp" | "needs_review"> = [
    "tp",
    "fp",
    "fp",
    "needs_review",
    "fp",
    "fp",
    "tp",
    "fp",
    "fp",
    "needs_review",
    "fp",
    "fp",
    "tp",
    "fp",
    "fp",
  ];

  for (let i = 0; i < 15; i++) {
    const fp = fingerprints[i]!;

    // Agent activity
    store.addAgentActivity(fp, {
      kind: "tool-start",
      toolName: "Read",
      detail: `Reading src/api/handler-${i}.ts`,
      index: i + 1,
      total: 15,
    });
    await sleep(200);

    store.addAgentActivity(fp, {
      kind: "tool-progress",
      toolName: "Grep",
      elapsedSeconds: 1.2 + Math.random() * 2,
      index: i + 1,
      total: 15,
    });
    await sleep(200);

    store.addAgentActivity(fp, {
      kind: "tool-complete",
      detail:
        i % 3 === 0 ? "Found unsanitized input in query builder" : "No injection vector found",
      index: i + 1,
      total: 15,
    });
    await sleep(100);

    // Result
    store.addResult({
      kind: "triage",
      verdict: verdicts[i],
      confidence: 0.6 + Math.random() * 0.35,
      costUsd: 0.01 + Math.random() * 0.04,
      fingerprint: fp,
      index: i + 1,
      total: 15,
      attempts: i === 3 ? 2 : undefined,
    });
    store.clearAgentActivity(fp);
    store.updateStageDetail("triage", `${i + 1}/15 findings via claude-opus`);
    await sleep(150);
  }

  await sleep(500);

  // --- Verification start ---
  store.activateStage("verify", "3 findings via claude-opus");
  store.update({
    phase: "verifying",
    progress: { current: 0, total: 3 },
    results: [],
  });
  await sleep(400);

  // Simulate verification
  for (let i = 0; i < 3; i++) {
    const fp = fingerprints[i === 0 ? 0 : i === 1 ? 6 : 12]!;

    store.addAgentActivity(fp, {
      kind: "tool-start",
      toolName: "Bash",
      detail: `curl localhost:3000/api/test-${i}`,
      index: i + 1,
      total: 3,
    });
    await sleep(300);

    store.addAgentActivity(fp, {
      kind: "tool-complete",
      detail:
        i < 2 ? "Exploit confirmed — response contains injected data" : "No exploitation possible",
      index: i + 1,
      total: 3,
    });
    await sleep(200);

    store.addResult({
      kind: "verify",
      exploitable: i < 2,
      costUsd: 0.03 + Math.random() * 0.02,
      fingerprint: fp,
      index: i + 1,
      total: 3,
    });
    store.clearAgentActivity(fp);
    store.updateStageDetail("verify", `${i + 1}/3 findings via claude-opus`);
    await sleep(200);
  }

  await sleep(500);

  // --- PoC Harness ---
  store.activateStage("poc", "2 harnesses via claude-opus");
  store.update({
    phase: "poc",
    progress: { current: 0, total: 2 },
    results: [],
  });
  await sleep(400);

  for (let i = 0; i < 2; i++) {
    const fp = fingerprints[i === 0 ? 0 : 6]!;
    store.addResult({
      kind: "poc",
      skipped: false,
      parsed: true,
      costUsd: 0.05,
      fingerprint: fp,
      index: i + 1,
      total: 2,
    });
    store.updateStageDetail("poc", `${i + 1}/2 harnesses via claude-opus`);
    await sleep(300);
  }

  await sleep(500);

  // --- Summary ---
  store.activateStage("report");
  store.completeStage("report");

  const summaryData: SummaryData = {
    repoName: "my-app",
    verdictCounts: { tp: 3, fp: 10, needs_review: 2, by_design: 0 },
    totalTriaged: 15,
    triageCostUsd: 0.42,
    verificationCostUsd: 0.11,
    pocHarnessCostUsd: 0.1,
    variantAnalysisCostUsd: 0,
    exploitable: 2,
    notExploitable: 1,
    pocGenerated: 2,
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
    exploitChains: [
      {
        id: "chain-1",
        name: "Stored XSS via template injection",
        overallSeverity: "CRITICAL",
        steps: [
          {
            role: "entry",
            description: "User-controlled input via POST /api/comments",
            findingFingerprint: "a1b2c3d4e5f6",
          },
          {
            role: "propagation",
            description: "Data flows through template engine",
            findingFingerprint: "555666777888",
          },
          {
            role: "sink",
            description: "Rendered directly in user's browser",
            findingFingerprint: "aabbccddeeff",
          },
        ],
        preconditions: ["User can submit comments"],
        impactDescription: "Full account takeover via session cookie theft",
      },
    ],
    actionableFindings: makeFakeFindings(),
  };

  store.update({
    phase: "summary",
    summary: summaryData,
  });

  // Let the user see the summary
  await sleep(10000);
  instance.unmount();
}

function makeFakeFindings(): ActionableFinding[] {
  return [
    {
      verdict: "tp",
      confidence: 0.92,
      severity: "ERROR",
      taskId: "semgrep",
      filePath: "src/api/users.ts",
      startLine: 42,
      ruleId: "javascript.express.security.sql-injection",
      rationale:
        "User input from `req.body.name` flows directly into `db.query()` without parameterization, enabling **SQL injection** (CWE-89).",
      fingerprint: "a1b2c3d4e5f6",
      verifyExploitable: 1,
      verifyPocPayload: "' OR 1=1 --",
      verifyAttackVector: "HTTP POST /api/users",
      corroboratingSignals: [
        {
          taskId: "codeql",
          ruleId: "js/sql-injection",
          filePath: "src/api/users.ts",
          startLine: 42,
          cwe: ["CWE-89"],
          score: 78,
        },
        {
          taskId: "agentic",
          ruleId: "deep-semantic/sqli",
          filePath: "src/api/users.ts",
          startLine: 40,
          cwe: ["CWE-89"],
          score: 65,
        },
      ],
      suppressionReasons: [],
    },
    {
      verdict: "tp",
      confidence: 0.85,
      severity: "WARNING",
      taskId: "semgrep",
      filePath: "src/auth/login.ts",
      startLine: 78,
      ruleId: "javascript.express.security.timing-attack",
      rationale:
        "Password comparison uses `===` instead of `crypto.timingSafeEqual()`, potentially leaking info via *timing side-channel* (CWE-208).",
      fingerprint: "aabbccddeeff",
      verifyExploitable: 1,
      corroboratingSignals: [],
      suppressionReasons: [],
    },
    {
      verdict: "needs_review",
      confidence: 0.65,
      severity: "WARNING",
      taskId: "codeql",
      filePath: "src/utils/crypto.ts",
      startLine: 15,
      ruleId: "javascript.crypto.weak-hash",
      rationale:
        "SHA-1 used for hashing — may be acceptable for non-security purposes but should be reviewed.",
      fingerprint: "999000aabbcc",
      corroboratingSignals: [],
      suppressionReasons: [],
    },
  ];
}

// ---------------------------------------------------------------------------
// Shell-view demos — scripted snapshots for the Ink UI v2 screens so we can
// eyeball each layout without running the full pipeline simulation.
// ---------------------------------------------------------------------------

function demoModuleCatalog(): ShellModuleCard[] {
  const sastTools: ShellModuleToolSummary[] = [
    { name: "sast:scan", verb: "scan", description: "run the full pipeline", headless: true },
    { name: "sast:semgrep", verb: "semgrep", description: "semgrep task only", headless: true },
    {
      name: "sast:codeql",
      verb: "codeql",
      description: "codeql task only (opt-in)",
      headless: true,
    },
    { name: "sast:triage", verb: "triage", description: "re-triage one finding", headless: true },
    {
      name: "sast:verify",
      verb: "verify",
      description: "construct + run PoC harness",
      headless: true,
    },
    { name: "sast:patch", verb: "patch", description: "generate + verify a fix", headless: true },
    {
      name: "sast:findings",
      verb: "findings",
      description: "list / filter / export",
      headless: true,
    },
    {
      name: "sast:context",
      verb: "context",
      description: "detected stack / frameworks",
      headless: true,
    },
    {
      name: "sast:threat-hunt",
      verb: "threat-hunt",
      description: "adversarial agents guided by randori",
      headless: true,
    },
    {
      name: "sast:taint-iris",
      verb: "taint-iris",
      description: "LLM-driven CodeQL taint (ICLR 2025)",
      headless: true,
    },
  ];

  return [
    {
      id: "sast",
      displayName: "SAST",
      category: "offense",
      description: "40+ task pipeline · semgrep · codeql · agentic",
      toolCount: sastTools.length,
      toolSummaries: sastTools,
      lastRunSummary: "ran  2h  · 4 tp",
      lastRunAt: Date.now() - 2 * 60 * 60 * 1000,
    },
    {
      id: "vuln-scout",
      displayName: "Vuln-scout",
      category: "offense",
      description: "whitebox pentest — agentic taint + source-to-sink",
      toolCount: 8,
      lastRunSummary: "ran  1d",
      lastRunAt: Date.now() - 24 * 60 * 60 * 1000,
    },
    {
      id: "tob",
      displayName: "Trail of Bits skills",
      category: "offense",
      description: "fp-check, sharp-edges, variants",
      toolCount: 3,
    },
    {
      id: "prompt-armor",
      displayName: "Prompt Armor",
      category: "offense",
      description: "LLM red teaming — 80+ attack plugins, 25+ mutations",
      toolCount: 12,
    },
    {
      id: "variant-hunter",
      displayName: "Variant Hunter",
      category: "offense",
      description: "lift a confirmed finding to a signature, hunt variants",
      toolCount: 2,
      lastRunSummary: "ran  2h",
    },
    {
      id: "n-day-diff",
      displayName: "n-day diff hunter",
      category: "offense",
      description: "CVE diff → patch-shape search → variant hunt",
      toolCount: 2,
    },
    {
      id: "randori",
      displayName: "Randori",
      category: "intel",
      description: "PASTA threat model · S1–S4 · STRIDE · ATT&CK mapped",
      toolCount: 4,
      lastRunSummary: "ran  2h  · 12 threats",
    },
    {
      id: "shinsa",
      displayName: "Shinsa",
      category: "governance",
      description: "ISO 27001 Annex A + NIST 800-53 Rev 5",
      toolCount: 3,
    },
    {
      id: "augur",
      displayName: "Augur",
      category: "offense",
      description: "[ext] neuro-symbolic SAST · IRIS taint · ICLR 2025",
      toolCount: 2,
      external: true,
    },
  ];
}

function demoFindings(): ActionableFinding[] {
  return [
    {
      verdict: "tp",
      confidence: 0.92,
      severity: "critical",
      displaySeverity: "critical",
      taskId: "sast",
      filePath: "src/api/admin.ts",
      startLine: 24,
      ruleId: "auth.missing-middleware",
      rationale: "auth gap on /admin/*",
      fingerprint: "02150000abcd",
      title: "auth gap on /admin/*",
      corroboratingSignals: [],
      suppressionReasons: [],
    },
    {
      verdict: "tp",
      confidence: 0.9,
      severity: "high",
      displaySeverity: "high",
      taskId: "sast",
      filePath: "src/api/admin.ts",
      startLine: 88,
      ruleId: "ssrf.no-allowlist",
      rationale:
        "Router mounts /admin/fetch before authMiddleware; handler calls fetch(req.query.url) with no allowlist, so an unauthenticated caller can reach 169.254.169.254 (AWS IMDS) and harvest creds.",
      fingerprint: "02160000abcd",
      title: "ssrf on /admin/fetch",
      verifyExploitable: 1,
      verifyPocPayload: "curl -s $BASE/admin/fetch?url=http://169.254.169.254/latest/meta-data/",
      corroboratingSignals: [],
      suppressionReasons: [],
    },
    {
      verdict: "tp",
      confidence: 0.88,
      severity: "high",
      displaySeverity: "high",
      taskId: "sast",
      filePath: "src/worker/queue.ts",
      startLine: 55,
      ruleId: "deserialization.unsafe",
      rationale: "upload queue deserializes attacker-controlled payloads without validation",
      fingerprint: "02180000abcd",
      title: "deserialization on upload queue",
      corroboratingSignals: [],
      suppressionReasons: [],
    },
  ];
}

async function runShellViewDemo(store: UIStore, view: ShellView): Promise<void> {
  const moduleCatalog = demoModuleCatalog();
  const findings = demoFindings();
  const focusedModule = view === "catalog" ? null : "sast";

  const summary: SummaryData | null =
    view === "findings" || view === "finding" ? buildDemoSummary(findings) : null;

  store.update({
    mode: "shell",
    bannerShown: true,
    ...(summary ? { summary } : {}),
    shell: {
      modules: moduleCatalog.map((m) => m.id),
      moduleCatalog,
      tools: moduleCatalog.flatMap((m) => m.toolSummaries?.map((t) => t.name) ?? []),
      focusedModule,
      shellView: view,
      openFindingId: view === "finding" ? "F-0216" : null,
      target: "./acme-api",
      workspace: "acme-api",
      tuneSnapshot: {
        preset: "deep",
        tasks: ["semgrep", "codeql", "agentic", "iris-taint"],
        verify: true,
        autoPatch: false,
        triageConcurrency: 5,
        model: "anthropic:claude-sonnet-4-6",
        houseRules:
          "Pay extra attention to /admin/* — previously behind a reverse-proxy auth layer that was removed last sprint. Our webhook HMAC check was historically weak; scrutinise it.",
        houseRulesPath: ".kuzushi/house-rules/sast.md",
      },
      history: [],
      commandHistory: [],
      moduleOptions: {},
      processing: false,
    },
  });

  return;
}

function buildDemoSummary(findings: ActionableFinding[]): SummaryData {
  {
    const summary: SummaryData = {
      repoName: "acme-api",
      verdictCounts: { tp: 3, fp: 0, needs_review: 0, by_design: 0 },
      totalTriaged: 3,
      triageCostUsd: 0.11,
      verificationCostUsd: 0.05,
      pocHarnessCostUsd: 0,
      variantAnalysisCostUsd: 0,
      exploitable: 1,
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
      exploitChains: [
        {
          id: "C-01",
          name: "admin auth bypass → SSRF → IMDS exfil",
          overallSeverity: "CRITICAL",
          preconditions: ["unauthenticated HTTP access"],
          impactDescription:
            "unauthenticated caller reaches cloud metadata and harvests credentials",
          steps: [
            {
              findingFingerprint: "f02150000000",
              role: "entry",
              description: "admin auth gap",
            },
            {
              findingFingerprint: "f02160000000",
              role: "pivot",
              description: "ssrf to IMDS",
            },
          ],
        },
      ],
      actionableFindings: findings,
    };
    return summary;
  }
}

main().catch(console.error);

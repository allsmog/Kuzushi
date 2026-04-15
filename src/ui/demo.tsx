#!/usr/bin/env tsx
/**
 * Visual test harness for the Kuzushi terminal UI.
 *
 * Run with: pnpm tsx src/ui/demo.tsx
 *
 * Simulates a full pipeline run with fake data to verify all UI components
 * render correctly. No real scans, DB, or agent runtime needed.
 */
import { render } from "ink";
import { createElement } from "react";
import { App } from "./App.js";
import { createUIStore } from "./state.js";
import type { SummaryData, ActionableFinding } from "./state.js";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function main(): Promise<void> {
  const store = createUIStore();
  const instance = render(createElement(App, { store }));

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
    id: "semgrep", label: "semgrep", status: "active", startedAt: Date.now(),
  });
  store.upsertSubTask("scan", {
    id: "codeql", label: "codeql", status: "active", startedAt: Date.now(),
  });
  store.upsertSubTask("scan", {
    id: "agentic", label: "agentic", status: "pending",
  });
  await sleep(1500);

  // Semgrep finishes first
  store.upsertSubTask("scan", {
    id: "semgrep", label: "semgrep", status: "done", elapsedMs: 1500,
  });
  await sleep(800);

  // Agentic starts
  store.upsertSubTask("scan", {
    id: "agentic", label: "agentic", status: "active", startedAt: Date.now(),
  });
  await sleep(1200);

  // CodeQL finishes
  store.upsertSubTask("scan", {
    id: "codeql", label: "codeql", status: "done", elapsedMs: 3500,
  });
  await sleep(800);

  // Agentic finishes
  store.upsertSubTask("scan", {
    id: "agentic", label: "agentic", status: "done", elapsedMs: 2000,
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
    model: "claude-opus",
    selectedForTriage: 15,
    progress: { current: 0, total: 15 },
  });
  await sleep(600);

  // --- Simulate triage with agent activity ---
  const fingerprints = [
    "a1b2c3d4e5f6", "f6e5d4c3b2a1", "111222333444",
    "555666777888", "999000aabbcc", "ddeeff112233",
    "aabbccddeeff", "112233445566", "778899001122",
    "334455667788", "990011223344", "556677889900",
    "abcdef123456", "654321fedcba", "abcabc123123",
  ];

  const verdicts: Array<"tp" | "fp" | "needs_review"> = [
    "tp", "fp", "fp", "needs_review", "fp",
    "fp", "tp", "fp", "fp", "needs_review",
    "fp", "fp", "tp", "fp", "fp",
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
      detail: i % 3 === 0 ? "Found unsanitized input in query builder" : "No injection vector found",
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
      detail: i < 2 ? "Exploit confirmed — response contains injected data" : "No exploitation possible",
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
    pocHarnessCostUsd: 0.10,
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
          { role: "entry", description: "User-controlled input via POST /api/comments", findingFingerprint: "a1b2c3d4e5f6" },
          { role: "propagation", description: "Data flows through template engine", findingFingerprint: "555666777888" },
          { role: "sink", description: "Rendered directly in user's browser", findingFingerprint: "aabbccddeeff" },
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
      rationale: "User input from req.body.name flows directly into SQL query without parameterization or sanitization, enabling SQL injection attacks.",
      fingerprint: "a1b2c3d4e5f6",
      verifyExploitable: 1,
      verifyPocPayload: "' OR 1=1 --",
      verifyAttackVector: "HTTP POST /api/users",
      corroboratingSignals: [{ taskId: "codeql" }],
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
      rationale: "Password comparison uses === instead of constant-time comparison, potentially leaking information via timing side-channel.",
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
      rationale: "SHA-1 used for hashing — may be acceptable for non-security purposes but should be reviewed.",
      fingerprint: "999000aabbcc",
      corroboratingSignals: [],
      suppressionReasons: [],
    },
  ];
}

main().catch(console.error);

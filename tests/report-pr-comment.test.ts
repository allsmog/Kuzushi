import { describe, expect, it } from "vitest";
import { buildPrComment } from "../src/report-pr-comment.js";
import type { ActionableFinding, SummaryData } from "../src/ui/state.js";

function mkFinding(partial: Partial<ActionableFinding>): ActionableFinding {
  return {
    verdict: "tp",
    confidence: 0.9,
    severity: "high",
    taskId: "sast",
    filePath: "src/a.ts",
    startLine: 1,
    ruleId: "rule/x",
    rationale: "",
    fingerprint: "aaaaaaaaaa",
    corroboratingSignals: [],
    suppressionReasons: [],
    ...partial,
  } as ActionableFinding;
}

function mkSummary(partial: Partial<SummaryData>): SummaryData {
  return {
    repoName: "acme-api",
    verdictCounts: { tp: 3, fp: 1, needs_review: 0, by_design: 0 },
    totalTriaged: 4,
    triageCostUsd: 0.1,
    verificationCostUsd: 0.2,
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
    exploitChains: [],
    actionableFindings: [],
    ...partial,
  };
}

describe("buildPrComment", () => {
  it("renders a header with the repo name and run link when provided", () => {
    const out = buildPrComment(mkSummary({}), {
      repoName: "acme-api",
      runUrl: "https://ci.example/runs/7f3a",
    });
    expect(out).toContain("Kuzushi scan");
    expect(out).toContain("acme-api");
    expect(out).toContain("[run](https://ci.example/runs/7f3a)");
  });

  it("shows verdict counts and exploitable badge", () => {
    const out = buildPrComment(mkSummary({}));
    expect(out).toContain("**3** tp");
    expect(out).toContain("**1 exploitable**");
  });

  it("renders the findings table with severity badges", () => {
    const summary = mkSummary({
      actionableFindings: [
        mkFinding({
          verdict: "tp",
          displaySeverity: "critical",
          title: "ssrf on /admin/fetch",
          filePath: "src/api/admin.ts",
          startLine: 88,
          fingerprint: "aa",
        }),
        mkFinding({
          verdict: "tp",
          displaySeverity: "high",
          title: "deser on upload queue",
          filePath: "src/worker/queue.ts",
          startLine: 55,
          fingerprint: "bb",
        }),
        mkFinding({
          verdict: "fp",
          displaySeverity: "high",
          title: "timing attack?",
          fingerprint: "cc",
        }),
      ],
    });
    const out = buildPrComment(summary);
    expect(out).toContain("🟥 CRIT");
    expect(out).toContain("🟧 HIGH");
    expect(out).toContain("ssrf on /admin/fetch");
    expect(out).toContain("src/api/admin.ts:88");
    // fp entries shouldn't surface in the top-TP table
    expect(out).not.toContain("timing attack?");
  });

  it("falls back to a no-TP message when nothing is true-positive", () => {
    const summary = mkSummary({
      verdictCounts: { tp: 0, fp: 2, needs_review: 0, by_design: 0 },
      actionableFindings: [
        mkFinding({ verdict: "fp", fingerprint: "aa" }),
        mkFinding({ verdict: "fp", fingerprint: "bb" }),
      ],
    });
    const out = buildPrComment(summary);
    expect(out).toContain("No true-positive findings");
  });

  it("formats cost line with total USD and optional duration/PoCs", () => {
    const out = buildPrComment(mkSummary({ pocGenerated: 2, variantFindings: 4 }), {
      elapsedMs: 90_000,
    });
    expect(out).toContain("💸");
    expect(out).toContain("$0.30");
    expect(out).toContain("1m 30s");
    expect(out).toContain("2 PoCs");
    expect(out).toContain("4 variants");
  });

  it("escapes pipes and newlines in titles so the markdown table stays intact", () => {
    const summary = mkSummary({
      actionableFindings: [
        mkFinding({
          verdict: "tp",
          title: "title with | pipe\nand newline",
          fingerprint: "aa",
        }),
      ],
    });
    const out = buildPrComment(summary);
    expect(out).toContain("title with \\| pipe and newline");
  });
});

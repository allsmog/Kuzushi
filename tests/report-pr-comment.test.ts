import { describe, expect, it } from "vitest";
import { buildPrComment } from "../src/report-pr-comment.js";
import type { ExploitChain } from "../src/types.js";
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

  it("renders no findings table cleanly when actionable list is empty", () => {
    const out = buildPrComment(
      mkSummary({ verdictCounts: { tp: 0, fp: 0, needs_review: 0, by_design: 0 } }),
    );
    expect(out).toContain("No findings triaged");
  });

  it("renders a single high-severity finding with CWE column", () => {
    const summary = mkSummary({
      verdictCounts: { tp: 1, fp: 0, needs_review: 0, by_design: 0 },
      exploitable: 1,
      actionableFindings: [
        mkFinding({
          verdict: "tp",
          displaySeverity: "critical",
          title: "ssrf on /admin/fetch",
          filePath: "src/api/admin.ts",
          startLine: 88,
          fingerprint: "aa",
          cwe: ["CWE-918"],
          remediation: "Validate URL host on allow-list before fetch.",
        }),
      ],
    });
    const out = buildPrComment(summary, { runUrl: "https://ci.example/runs/7f3a" });
    expect(out).toContain("**1 critical**");
    expect(out).toContain("CWE-918");
    expect(out).toContain("[F-0001](https://ci.example/runs/7f3a#F-0001)");
    // Remediation hint surfaces below the row.
    expect(out).toContain("Validate URL host on allow-list before fetch.");
    // Single finding => no truncation footer.
    expect(out).not.toContain("more findings");
  });

  it("emits a 'Top findings (N of M)' header and truncation footer when truncated", () => {
    const findings: ActionableFinding[] = [];
    for (let i = 0; i < 12; i++) {
      findings.push(
        mkFinding({
          verdict: "tp",
          displaySeverity: "high",
          fingerprint: `fp${String(i).padStart(2, "0")}`,
          title: `f-${i}`,
        }),
      );
    }
    const summary = mkSummary({ actionableFindings: findings });
    const out = buildPrComment(summary, { topN: 5 });
    expect(out).toContain("Top findings (5 of 12)");
    expect(out).toContain("**7** more findings");
    // Footer reports truncated count.
    expect(out).toContain("7 truncated");
  });

  it("includes a 'New in this PR' lead block when changedFiles is supplied", () => {
    const summary = mkSummary({
      actionableFindings: [
        mkFinding({
          verdict: "tp",
          displaySeverity: "critical",
          title: "ssrf",
          filePath: "src/api/admin.ts",
          startLine: 88,
          fingerprint: "aa",
        }),
        mkFinding({
          verdict: "tp",
          displaySeverity: "high",
          title: "old issue",
          filePath: "src/legacy/x.ts",
          startLine: 12,
          fingerprint: "bb",
        }),
      ],
    });
    const out = buildPrComment(summary, { changedFiles: ["src/api/admin.ts"] });
    expect(out).toContain("New in this PR");
    expect(out).toContain("🆕 **1 new in this PR**");
    // Old issue still appears in the global table but not in the new-in-pr block.
    expect(out.split("New in this PR")[1]).toContain("ssrf");
  });

  it("renders an exploit-chain block above the findings table", () => {
    const chain: ExploitChain = {
      id: "chain-1",
      name: "ssrf-to-rce",
      overallSeverity: "CRITICAL",
      preconditions: [],
      impactDescription: "RCE as worker process",
      narrative: "Unauthenticated SSRF stages payload that the queue deserialises.",
      steps: [
        {
          findingFingerprint: "aa",
          role: "entry",
          description: "ssrf",
          filePath: "src/api/admin.ts",
          startLine: 88,
        },
        {
          findingFingerprint: "bb",
          role: "sink",
          description: "deser",
          filePath: "src/worker/queue.ts",
          startLine: 55,
        },
      ],
    };
    const summary = mkSummary({
      exploitable: 1,
      exploitChains: [chain],
      actionableFindings: [
        mkFinding({
          verdict: "tp",
          displaySeverity: "critical",
          title: "ssrf",
          filePath: "src/api/admin.ts",
          startLine: 88,
          fingerprint: "aa",
        }),
        mkFinding({
          verdict: "tp",
          displaySeverity: "high",
          title: "deser",
          filePath: "src/worker/queue.ts",
          startLine: 55,
          fingerprint: "bb",
        }),
      ],
    });
    const out = buildPrComment(summary);
    expect(out).toContain("Exploit chain");
    expect(out).toContain("C-01");
    expect(out).toContain("Unauthenticated SSRF stages payload");
    expect(out).toContain("**Impact:** RCE as worker process");
    // Renders in chain-block-then-findings-table order.
    expect(out.indexOf("C-01")).toBeLessThan(out.indexOf("Top findings"));
  });

  it("renders per-phase cost breakdown when phase costs are non-zero", () => {
    const out = buildPrComment(
      mkSummary({
        triageCostUsd: 0.12,
        verificationCostUsd: 0.34,
        pocHarnessCostUsd: 0.05,
      }),
    );
    expect(out).toContain("triage $0.12");
    expect(out).toContain("verify $0.34");
    expect(out).toContain("poc $0.05");
    expect(out).toContain("total **$0.51**");
  });

  it("includes reproducibility footer fields when provided", () => {
    const out = buildPrComment(mkSummary({}), {
      kuzushiVersion: "0.22.1",
      runId: "abcdef1234567890",
      model: "anthropic:claude-sonnet-4-6",
      gitSha: "deadbeefcafe1234",
    });
    expect(out).toContain("Kuzushi 0.22.1");
    expect(out).toContain("run `abcdef12`");
    expect(out).toContain("model `anthropic:claude-sonnet-4-6`");
    expect(out).toContain("git `deadbee`");
  });

  it("excludes suppressed findings from the table and counts", () => {
    const summary = mkSummary({
      actionableFindings: [
        mkFinding({
          verdict: "tp",
          displaySeverity: "critical",
          title: "live finding",
          filePath: "src/a.ts",
          fingerprint: "aa",
        }),
        mkFinding({
          verdict: "tp",
          displaySeverity: "critical",
          title: "snoozed finding",
          filePath: "src/b.ts",
          fingerprint: "bb",
          suppressed: true,
        }),
      ],
    });
    const out = buildPrComment(summary);
    expect(out).toContain("live finding");
    expect(out).not.toContain("snoozed finding");
    expect(out).toContain("**1 critical**");
  });
});

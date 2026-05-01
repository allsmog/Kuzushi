import { describe, expect, it } from "vitest";
import { attachCiStream } from "../../src/ui/ci-stream.js";
import { createUIStore } from "../../src/ui/state.js";

function captureLines(): { lines: string[]; write: (l: string) => void } {
  const lines: string[] = [];
  return {
    lines,
    write: (l) => {
      lines.push(l);
    },
  };
}

describe("attachCiStream", () => {
  it("emits no lines until running mode", () => {
    const store = createUIStore();
    const cap = captureLines();
    const unsub = attachCiStream(store, { write: cap.write });
    store.update({ repoName: "acme-api" });
    expect(cap.lines).toEqual([]);
    unsub();
  });

  it("announces scan start, phase, stage, and summary", () => {
    const store = createUIStore();
    const cap = captureLines();
    const unsub = attachCiStream(store, { write: cap.write });

    store.update({ mode: "running", repoName: "acme-api" });
    store.initStages([{ id: "scan", label: "Scan" }]);
    store.update({ phase: "scanning" });
    store.activateStage("scan");
    store.completeStage("scan");
    store.update({ phase: "done", mode: "summary" });

    const joined = cap.lines.join("\n");
    expect(joined).toContain("scan: acme-api started");
    expect(joined).toContain("phase:");
    expect(joined).toContain("stage: scan → active");
    expect(joined).toContain("stage: scan → done");
    unsub();
  });

  it("deduplicates finding events per fingerprint", () => {
    const store = createUIStore();
    const cap = captureLines();
    const unsub = attachCiStream(store, { write: cap.write });
    store.update({ mode: "running", repoName: "repo" });

    for (let i = 0; i < 3; i++) {
      store.addResult({
        kind: "triage",
        verdict: "tp",
        confidence: 0.9,
        costUsd: 0.01,
        fingerprint: "abc",
        index: 1,
        total: 1,
      });
    }
    const findingLines = cap.lines.filter((l) => l.includes("finding:"));
    expect(findingLines).toHaveLength(1);
    unsub();
  });

  it("emitFindings=false suppresses per-finding lines", () => {
    const store = createUIStore();
    const cap = captureLines();
    const unsub = attachCiStream(store, { write: cap.write, emitFindings: false });
    store.update({ mode: "running", repoName: "repo" });
    store.addResult({
      kind: "triage",
      verdict: "tp",
      fingerprint: "xyz",
      index: 1,
      total: 1,
    });
    expect(cap.lines.filter((l) => l.includes("finding:"))).toHaveLength(0);
    unsub();
  });

  it("appends run-context fields to the start line when supplied", () => {
    const store = createUIStore();
    const cap = captureLines();
    const unsub = attachCiStream(store, {
      write: cap.write,
      runContext: {
        runId: "abcdef1234567890",
        kuzushiVersion: "0.22.1",
        model: "anthropic:claude-sonnet-4-6",
        gitSha: "deadbeefcafe1234",
      },
    });
    store.update({ mode: "running", repoName: "acme-api" });
    const startLine = cap.lines.find((l) => l.includes("scan: acme-api started")) ?? "";
    expect(startLine).toContain("run=abcdef12");
    expect(startLine).toContain("kuzushi=0.22.1");
    expect(startLine).toContain("model=anthropic:claude-sonnet-4-6");
    expect(startLine).toContain("git=deadbee");
    unsub();
  });

  it("emits a final result: line with verdict and exit hint when summary fires", () => {
    const store = createUIStore();
    const cap = captureLines();
    const unsub = attachCiStream(store, { write: cap.write });

    store.update({ mode: "running", repoName: "acme-api" });
    store.update({
      mode: "summary",
      phase: "done",
      summary: {
        repoName: "acme-api",
        verdictCounts: { tp: 1, fp: 0, needs_review: 0, by_design: 0 },
        totalTriaged: 1,
        triageCostUsd: 0,
        verificationCostUsd: 0,
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
        actionableFindings: [
          {
            verdict: "tp",
            confidence: 0.9,
            severity: "critical",
            taskId: "sast",
            filePath: "src/a.ts",
            startLine: 1,
            ruleId: "rule/x",
            rationale: "",
            fingerprint: "aa",
            corroboratingSignals: [],
            suppressionReasons: [],
            displaySeverity: "critical",
          },
        ],
      },
    });

    const resultLine = cap.lines.find((l) => l.includes("result:"));
    expect(resultLine).toBeDefined();
    expect(resultLine).toContain("fail");
    expect(resultLine).toContain("1 critical");
    expect(resultLine).toContain("exit_hint=1");
    unsub();
  });

  it("emits result: pass exit_hint=0 when no tp findings and no failed tasks", () => {
    const store = createUIStore();
    const cap = captureLines();
    const unsub = attachCiStream(store, { write: cap.write });
    store.update({ mode: "running", repoName: "repo" });
    store.update({
      mode: "summary",
      phase: "done",
      summary: {
        repoName: "repo",
        verdictCounts: { tp: 0, fp: 0, needs_review: 0, by_design: 0 },
        totalTriaged: 0,
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
        actionableFindings: [],
      },
    });
    const resultLine = cap.lines.find((l) => l.includes("result:")) ?? "";
    expect(resultLine).toContain("pass");
    expect(resultLine).toContain("exit_hint=0");
    unsub();
  });

  it("emits one error: line per failed task in the summary", () => {
    const store = createUIStore();
    const cap = captureLines();
    const unsub = attachCiStream(store, { write: cap.write });
    store.update({ mode: "running", repoName: "repo" });
    store.update({
      mode: "summary",
      phase: "done",
      summary: {
        repoName: "repo",
        verdictCounts: { tp: 0, fp: 0, needs_review: 0, by_design: 0 },
        totalTriaged: 0,
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
        failedTasks: ["semgrep", "codeql"],
        tiPriorDegraded: false,
        exploitChains: [],
        actionableFindings: [],
      },
    });
    const errorLines = cap.lines.filter((l) => l.includes("error:"));
    expect(errorLines).toHaveLength(2);
    expect(errorLines[0]).toContain("task=semgrep");
    expect(errorLines[1]).toContain("task=codeql");
    const resultLine = cap.lines.find((l) => l.includes("result:")) ?? "";
    expect(resultLine).toContain("fail");
    expect(resultLine).toContain("2 failed-tasks");
    unsub();
  });
});

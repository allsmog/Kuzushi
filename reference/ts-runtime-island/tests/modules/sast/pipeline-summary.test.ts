import { describe, expect, it } from "vitest";
import type { PipelineResult } from "../../../src/cli/commands/scan-pipeline.js";
import { summarizePipelineResult } from "../../../src/modules/sast/pipeline-summary.js";

function baseResult(overrides: Partial<PipelineResult> = {}): PipelineResult {
  return {
    runId: "run-abc",
    status: "complete",
    stats: {
      tasks: [],
      totalFindings: 0,
      queuedForTriage: 0,
      skippedAlreadyTriaged: 0,
      triaged: 0,
      triageErrors: 0,
      startedAt: "2026-04-22T00:00:00Z",
      completedAt: "2026-04-22T00:01:00Z",
    },
    ...overrides,
  };
}

describe("summarizePipelineResult", () => {
  it("returns a single-line summary on clean completion (full post-process)", () => {
    const result = baseResult({
      stats: { ...baseResult().stats!, totalFindings: 12, triaged: 5, totalCostUsd: 0.42 },
    });
    const summary = summarizePipelineResult({
      result,
      repoName: "acme",
      label: "Scan",
      postProcessMode: "full",
    });
    expect(summary).toBe("Scan complete: acme — 12 findings, 5 triaged ($0.42)");
  });

  it("omits triaged count in scan-only mode", () => {
    const result = baseResult({
      stats: { ...baseResult().stats!, totalFindings: 12, triaged: 0 },
    });
    const summary = summarizePipelineResult({
      result,
      repoName: "acme",
      label: "Semgrep",
      postProcessMode: "scan-only",
    });
    expect(summary).toBe("Semgrep complete: acme — 12 findings");
  });

  it("returns a cancelled summary when aborted", () => {
    const result = baseResult({ aborted: true });
    const summary = summarizePipelineResult({
      result,
      repoName: "acme",
      label: "Scan",
      postProcessMode: "full",
    });
    expect(summary).toBe("Scan cancelled: acme");
  });

  it("groups API-key-sensitive failed tasks into one skip line", () => {
    const result = baseResult({
      stats: {
        ...baseResult().stats!,
        totalFindings: 27,
        failedTasks: ["triage", "patch", "verify"],
      },
    });
    const summary = summarizePipelineResult({
      result,
      repoName: "acme",
      label: "Scan",
      postProcessMode: "full",
    });
    expect(summary).toContain("Scan complete with warnings: acme — 27 findings");
    expect(summary).toContain("3 tasks skipped — requires API key for AI analysis");
    expect(summary).toContain("Run ID: run-abc");
    expect(summary).not.toContain("tasks failed:");
  });

  it("separately lists non-API-key failures with first-3 + overflow count", () => {
    const result = baseResult({
      stats: {
        ...baseResult().stats!,
        failedTasks: ["alpha", "beta", "gamma", "delta", "epsilon"],
      },
    });
    const summary = summarizePipelineResult({
      result,
      repoName: "acme",
      label: "Scan",
      postProcessMode: "full",
    });
    expect(summary).toContain("5 tasks failed: alpha, beta, gamma (+2 more)");
  });

  it("renders both API-key skips and other failures side by side", () => {
    const result = baseResult({
      stats: {
        ...baseResult().stats!,
        failedTasks: ["triage", "alpha", "patch"],
      },
    });
    const summary = summarizePipelineResult({
      result,
      repoName: "acme",
      label: "Scan",
      postProcessMode: "full",
    });
    expect(summary).toContain("2 tasks skipped — requires API key for AI analysis");
    expect(summary).toContain("1 task failed: alpha");
  });

  it("surfaces the error message on non-complete status", () => {
    const result = baseResult({
      status: "error",
      error: "disk full",
      stats: { ...baseResult().stats!, totalFindings: 0 },
    });
    const summary = summarizePipelineResult({
      result,
      repoName: "acme",
      label: "Scan",
      postProcessMode: "full",
    });
    expect(summary).toContain("Scan finished with errors: acme");
    expect(summary).toContain("disk full");
    expect(summary).toContain("Run ID: run-abc");
  });

  it("shows findings count even on error status when stats are present", () => {
    const result = baseResult({
      status: "error",
      error: "worker crashed",
      stats: { ...baseResult().stats!, totalFindings: 7, triaged: 2 },
    });
    const summary = summarizePipelineResult({
      result,
      repoName: "acme",
      label: "Scan",
      postProcessMode: "full",
    });
    expect(summary).toContain("7 findings, 2 triaged");
    expect(summary).toContain("worker crashed");
  });

  it("reports dead-lettered events when present", () => {
    const result = baseResult({
      stats: { ...baseResult().stats!, deadLetterCount: 4 },
    });
    const summary = summarizePipelineResult({
      result,
      repoName: "acme",
      label: "Scan",
      postProcessMode: "full",
    });
    expect(summary).toContain("4 events dead-lettered");
  });

  it("surfaces legacy IRIS inconclusive status instead of clean completion", () => {
    const result = baseResult({
      stats: {
        ...baseResult().stats!,
        legacyIrisDegradation: {
          type: "legacy-inconclusive",
          reason: "no-findings-and-no-generated-query-artifacts",
          message:
            "Legacy taint-iris returned 0 findings without generated CodeQL query artifacts; treat as inconclusive, not clean.",
        },
      },
    });
    const summary = summarizePipelineResult({
      result,
      repoName: "lab",
      label: "Taint IRIS",
      postProcessMode: "scan-only",
    });

    expect(summary).toContain("Taint IRIS inconclusive: lab — 0 findings");
    expect(summary).toContain("treat as inconclusive, not clean");
  });

  it("singularizes task/event counts at 1", () => {
    const result = baseResult({
      stats: {
        ...baseResult().stats!,
        failedTasks: ["triage"],
        deadLetterCount: 1,
      },
    });
    const summary = summarizePipelineResult({
      result,
      repoName: "acme",
      label: "Scan",
      postProcessMode: "full",
    });
    expect(summary).toContain("1 task skipped");
    expect(summary).toContain("1 event dead-lettered");
  });
});

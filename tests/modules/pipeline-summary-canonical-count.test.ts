/**
 * Regression test for v0.21 followup M5 — three different finding counts
 * (sub-step 41, summary 32, DB 33) for the same run. The fix funnels the
 * summary line through an optional `canonicalFindingCount` so the operator-
 * visible "complete: <repo> — N findings" matches the persisted DB count
 * rather than the pre-persistence in-memory stat.
 */

import { describe, expect, it } from "vitest";
import type { PipelineResult } from "../../src/cli/commands/scan-pipeline.js";
import { summarizePipelineResult } from "../../src/modules/sast/pipeline-summary.js";

function baseResult(overrides: Partial<PipelineResult> = {}): PipelineResult {
  return {
    runId: "run-123",
    status: "complete",
    aborted: false,
    error: null,
    stats: {
      totalFindings: 32,
      triaged: 0,
      totalCostUsd: 1.5,
      failedTasks: [],
      deadLetterCount: 0,
    },
    ...overrides,
  } as unknown as PipelineResult;
}

describe("summarizePipelineResult — canonical finding count (M5)", () => {
  it("uses result.stats.totalFindings when no canonical override is provided", () => {
    const summary = summarizePipelineResult({
      result: baseResult(),
      repoName: "kuzushi",
      label: "Threat hunt",
      postProcessMode: "scan-only",
    });
    expect(summary).toContain("32 findings");
  });

  it("prefers canonicalFindingCount over result.stats.totalFindings when both differ", () => {
    const summary = summarizePipelineResult({
      result: baseResult(),
      repoName: "kuzushi",
      label: "Threat hunt",
      postProcessMode: "scan-only",
      canonicalFindingCount: 33, // DB-derived; differs from in-memory 32
    });
    expect(summary).toContain("33 findings");
    expect(summary).not.toContain("32 findings");
  });

  it("treats canonicalFindingCount of 0 as a valid override (not falsy fallback)", () => {
    const summary = summarizePipelineResult({
      result: baseResult({ stats: { totalFindings: 99 } as PipelineResult["stats"] }),
      repoName: "kuzushi",
      label: "Threat hunt",
      postProcessMode: "scan-only",
      canonicalFindingCount: 0,
    });
    expect(summary).toContain("0 findings");
    expect(summary).not.toContain("99 findings");
  });

  it("falls back to 0 when stats are missing and no override is provided", () => {
    const summary = summarizePipelineResult({
      result: baseResult({ stats: null as unknown as PipelineResult["stats"] }),
      repoName: "kuzushi",
      label: "Threat hunt",
      postProcessMode: "scan-only",
    });
    expect(summary).toContain("0 findings");
  });
});

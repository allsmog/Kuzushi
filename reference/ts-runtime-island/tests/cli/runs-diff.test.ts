import { describe, expect, it } from "vitest";
import { diffRuns, formatDiff } from "../../src/cli/commands/runs-diff.js";
import type { PipelineRunRecord } from "../../src/store.js";

function mkRun(runId: string, findings: Array<Record<string, unknown>>): PipelineRunRecord {
  return {
    runId,
    repo: "/repo/a",
    moduleId: null,
    toolName: null,
    resumeLabel: null,
    startedAt: "2026-01-01T00:00:00Z",
    status: "complete",
    configJson: "{}",
    scanOptsJson: "{}",
    findingsJson: JSON.stringify(findings),
    contextJson: null,
    totalCostUsd: 0,
    completedAt: "2026-01-01T00:01:00Z",
    updatedAt: "2026-01-01T00:01:00Z",
    metricsJson: null,
    assertionsJson: null,
    promptHash: null,
  } as PipelineRunRecord;
}

describe("runs-diff", () => {
  it("classifies findings as added / removed / drifted / stable", () => {
    const runA = mkRun("a", [
      { fingerprint: "fp-shared-1", verdict: "tp", displaySeverity: "high", confidence: 0.9 },
      { fingerprint: "fp-shared-2", verdict: "fp", displaySeverity: "low", confidence: 0.3 },
      { fingerprint: "fp-removed", verdict: "tp", displaySeverity: "medium", confidence: 0.7 },
      // Drifted: same fp, different verdict
      { fingerprint: "fp-drift", verdict: "tp", displaySeverity: "high", confidence: 0.9 },
    ]);
    const runB = mkRun("b", [
      { fingerprint: "fp-shared-1", verdict: "tp", displaySeverity: "high", confidence: 0.9 },
      { fingerprint: "fp-shared-2", verdict: "fp", displaySeverity: "low", confidence: 0.3 },
      { fingerprint: "fp-added", verdict: "tp", displaySeverity: "critical", confidence: 0.95 },
      // Drifted: same fp, different verdict
      { fingerprint: "fp-drift", verdict: "fp", displaySeverity: "high", confidence: 0.4 },
    ]);

    const result = diffRuns(runA, runB);
    expect(result.added.map((r) => r.fingerprint)).toEqual(["fp-added"]);
    expect(result.removed.map((r) => r.fingerprint)).toEqual(["fp-removed"]);
    expect(result.drifted).toHaveLength(1);
    expect(result.drifted[0]!.fingerprint).toBe("fp-drift");
    expect(result.drifted[0]!.changes.map((c) => c.field).sort()).toEqual(
      ["confidence", "verdict"].sort(),
    );
    expect(result.stableCount).toBe(2);
  });

  it("handles empty findings on either side", () => {
    const empty = mkRun("empty", []);
    const populated = mkRun("populated", [
      { fingerprint: "x", verdict: "tp", displaySeverity: "high" },
    ]);
    const noToYes = diffRuns(empty, populated);
    expect(noToYes.added).toHaveLength(1);
    expect(noToYes.removed).toEqual([]);
    expect(noToYes.drifted).toEqual([]);
    expect(noToYes.stableCount).toBe(0);

    const yesToNo = diffRuns(populated, empty);
    expect(yesToNo.added).toEqual([]);
    expect(yesToNo.removed).toHaveLength(1);
  });

  it("ignores entries without a fingerprint", () => {
    const a = mkRun("a", [{ ruleId: "r1" }, { fingerprint: "ok", verdict: "tp" }]);
    const b = mkRun("b", [{ fingerprint: "ok", verdict: "tp" }]);
    const result = diffRuns(a, b);
    expect(result.removed).toEqual([]);
    expect(result.stableCount).toBe(1);
  });

  it("formatDiff includes counts header and section labels", () => {
    const a = mkRun("a", [{ fingerprint: "old", verdict: "tp", displaySeverity: "high" }]);
    const b = mkRun("b", [{ fingerprint: "new", verdict: "tp", displaySeverity: "high" }]);
    const out = formatDiff(diffRuns(a, b));
    expect(out).toContain("+1 new");
    expect(out).toContain("-1 fixed");
    expect(out).toContain("Fixed");
    expect(out).toContain("New");
  });

  it("treats missing severity / verdict as drift when one side has them", () => {
    const a = mkRun("a", [{ fingerprint: "x" }]);
    const b = mkRun("b", [{ fingerprint: "x", verdict: "tp", displaySeverity: "high" }]);
    const result = diffRuns(a, b);
    expect(result.drifted).toHaveLength(1);
  });
});

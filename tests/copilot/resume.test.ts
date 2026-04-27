import { describe, expect, it } from "vitest";
import {
  isResumableRun,
  runMatchesTool,
  selectResumeCandidates,
} from "../../src/copilot/resume.js";
import type { ModuleTool } from "../../src/modules/types.js";
import type { PipelineRunRecord } from "../../src/store.js";

function tool(name: string, pipelineTasks: "any" | string[]): ModuleTool {
  return {
    name,
    description: name,
    inputSchema: { type: "object", additionalProperties: true },
    headless: true,
    runLifecycle: {
      persistence: "pipeline-checkpoint",
      resume: "checkpoint",
      pipelineTasks,
    },
    async execute() {
      return { ok: true, output: "ok" };
    },
  };
}

function run(
  runId: string,
  status: PipelineRunRecord["status"],
  tasks: string[] | undefined,
  patch: Partial<PipelineRunRecord> = {},
): PipelineRunRecord {
  return {
    runId,
    repo: "/repo",
    moduleId: patch.moduleId ?? null,
    toolName: patch.toolName ?? null,
    resumeLabel: patch.resumeLabel ?? null,
    startedAt: patch.startedAt ?? `2026-04-27T10:00:0${runId.slice(-1)}.000Z`,
    status,
    configJson: "{}",
    scanOptsJson: JSON.stringify({ severity: ["high"], excludePatterns: [], fresh: false, tasks }),
    findingsJson: patch.findingsJson === undefined ? "[]" : patch.findingsJson,
    contextJson: patch.contextJson ?? null,
    totalCostUsd: patch.totalCostUsd ?? 0,
    completedAt: patch.completedAt ?? null,
    updatedAt: patch.updatedAt ?? patch.startedAt ?? `2026-04-27T10:00:0${runId.slice(-1)}.000Z`,
    metricsJson: null,
    assertionsJson: null,
    promptHash: null,
  };
}

describe("resume selection", () => {
  it("includes active/interrupted checkpointed runs and excludes terminal or empty runs", () => {
    expect(isResumableRun(run("run-1", "triaging", ["semgrep"]))).toBe(true);
    expect(isResumableRun(run("run-2", "interrupted", ["semgrep"]))).toBe(true);
    expect(isResumableRun(run("run-3", "complete", ["semgrep"]))).toBe(false);
    expect(isResumableRun(run("run-4", "error", ["semgrep"]))).toBe(false);
    expect(isResumableRun(run("run-5", "aborted", ["semgrep"]))).toBe(false);
    expect(isResumableRun(run("run-6", "interrupted", ["semgrep"], { findingsJson: null }))).toBe(
      false,
    );
  });

  it("matches legacy task metadata for sast, semgrep, and threat-hunt tools", () => {
    const sast = tool("sast:scan", "any");
    const semgrep = tool("semgrep:scan", ["semgrep"]);
    const threatHunt = tool("threat-hunt:run", ["threat-hunt"]);

    expect(runMatchesTool(run("run-1", "triaging", ["semgrep"]), "sast", sast)).toBe(true);
    expect(runMatchesTool(run("run-2", "triaging", ["semgrep"]), "semgrep", semgrep)).toBe(true);
    expect(
      runMatchesTool(run("run-3", "triaging", ["threat-hunt"]), "threat-hunt", threatHunt),
    ).toBe(true);
    expect(runMatchesTool(run("run-4", "triaging", ["semgrep"]), "threat-hunt", threatHunt)).toBe(
      false,
    );
  });

  it("prefers the latest compatible candidate", () => {
    const semgrep = tool("semgrep:scan", ["semgrep"]);
    const candidates = selectResumeCandidates(
      [
        run("run-1", "interrupted", ["semgrep"], { startedAt: "2026-04-27T10:00:00.000Z" }),
        run("run-2", "triaging", ["semgrep"], { startedAt: "2026-04-27T11:00:00.000Z" }),
      ],
      "semgrep",
      semgrep,
    );
    expect(candidates.map((candidate) => candidate.runId)).toEqual(["run-2", "run-1"]);
  });
});

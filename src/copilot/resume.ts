import { ACTIVE_PIPELINE_RUN_STATUSES, type PipelineRunStatus } from "../contracts.js";
import type { ModuleTool } from "../modules/types.js";
import type { PipelineRunRecord } from "../store.js";
import { safeJsonParse } from "../utils/safe-json.js";

const RESUMABLE_STATUSES = new Set<PipelineRunStatus>([
  ...ACTIVE_PIPELINE_RUN_STATUSES,
  "interrupted",
]);

export function toolSupportsCheckpointResume(tool: ModuleTool | undefined): tool is ModuleTool {
  return tool?.runLifecycle?.resume === "checkpoint";
}

export function runHasCheckpoint(
  run: Pick<PipelineRunRecord, "findingsJson" | "contextJson">,
): boolean {
  return Boolean(
    (typeof run.findingsJson === "string" && run.findingsJson.trim().length > 0) ||
      (typeof run.contextJson === "string" && run.contextJson.trim().length > 0),
  );
}

export function isResumableRun(run: PipelineRunRecord): boolean {
  return RESUMABLE_STATUSES.has(run.status) && runHasCheckpoint(run);
}

export function runTasks(run: Pick<PipelineRunRecord, "scanOptsJson">): string[] {
  const parsed = safeJsonParse<unknown>(run.scanOptsJson, null);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return [];
  const tasks = (parsed as Record<string, unknown>)["tasks"];
  return Array.isArray(tasks)
    ? tasks.filter((task): task is string => typeof task === "string")
    : [];
}

export function runMatchesTool(
  run: PipelineRunRecord,
  moduleId: string,
  tool: ModuleTool | undefined,
): boolean {
  if (!toolSupportsCheckpointResume(tool)) return false;
  if (run.toolName && run.toolName === tool.name) return true;
  if (run.moduleId && run.moduleId === moduleId) return true;

  const pipelineTasks = tool?.runLifecycle?.pipelineTasks;
  if (pipelineTasks === "any") return true;
  if (!Array.isArray(pipelineTasks) || pipelineTasks.length === 0) return false;

  const tasks = new Set(runTasks(run));
  return pipelineTasks.some((task) => tasks.has(task));
}

export function selectResumeCandidates(
  runs: readonly PipelineRunRecord[],
  moduleId: string,
  tool: ModuleTool | undefined,
): PipelineRunRecord[] {
  return runs
    .filter((run) => isResumableRun(run) && runMatchesTool(run, moduleId, tool))
    .sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt));
}

export function latestCompletedRun(
  runs: readonly PipelineRunRecord[],
): PipelineRunRecord | undefined {
  return [...runs]
    .filter((run) => run.status === "complete")
    .sort((a, b) => {
      const aTime = Date.parse(a.completedAt ?? a.startedAt);
      const bTime = Date.parse(b.completedAt ?? b.startedAt);
      return bTime - aTime;
    })[0];
}

export function countCheckpointFindings(run: Pick<PipelineRunRecord, "findingsJson">): number {
  const parsed = safeJsonParse<unknown>(run.findingsJson ?? "", []);
  return Array.isArray(parsed) ? parsed.length : 0;
}

export function resumeStageLabel(status: PipelineRunStatus): string {
  switch (status) {
    case "scanning":
      return "scan";
    case "triaging":
      return "triage";
    case "verifying":
      return "verify";
    case "poc-harnessing":
      return "poc";
    case "dynamic-analyzing":
      return "dynamic";
    case "interrupted":
      return "checkpoint";
    case "complete":
      return "complete";
    case "error":
      return "error";
    case "aborted":
      return "aborted";
  }
}

function formatAge(iso: string, nowMs: number = Date.now()): string {
  const then = Date.parse(iso);
  if (!Number.isFinite(then)) return "unknown age";
  const minutes = Math.max(0, Math.floor((nowMs - then) / 60_000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(then).toISOString().slice(0, 10);
}

export function formatRunResumeSummary(run: PipelineRunRecord): string {
  const findingCount = countCheckpointFindings(run);
  const findings =
    findingCount > 0 ? `${findingCount} finding${findingCount === 1 ? "" : "s"}` : "checkpointed";
  const cost = run.totalCostUsd > 0 ? `$${run.totalCostUsd.toFixed(2)}` : "$0.00";
  return `resume available · ${resumeStageLabel(run.status)} · ${findings} · ${cost} · ${formatAge(run.updatedAt ?? run.startedAt)}`;
}

export function formatRunReplaySummary(run: PipelineRunRecord): string {
  const findingCount = countCheckpointFindings(run);
  const findings =
    findingCount > 0 ? `${findingCount} finding${findingCount === 1 ? "" : "s"}` : "no findings";
  const cost = run.totalCostUsd > 0 ? `$${run.totalCostUsd.toFixed(2)}` : "$0.00";
  return `completed · ${findings} · ${cost} · ${formatAge(run.completedAt ?? run.updatedAt ?? run.startedAt)}`;
}

export function formatResumeChooser(candidates: readonly PipelineRunRecord[]): string {
  const rows = candidates.slice(0, 8).map((run) => {
    const id = run.runId.slice(0, 12).padEnd(12);
    const stage = resumeStageLabel(run.status).padEnd(10);
    const findings = `${countCheckpointFindings(run)} findings`.padEnd(12);
    const cost = `$${run.totalCostUsd.toFixed(2)}`.padEnd(8);
    return `  ${id}  ${stage}  ${findings}  ${cost}  ${formatAge(run.updatedAt ?? run.startedAt)}`;
  });
  const suffix =
    candidates.length > 8 ? `\n  … ${candidates.length - 8} more (use /show runs)` : "";
  return (
    [
      "Multiple resumable runs match. Choose one:",
      "  RUN ID        STAGE       CHECKPOINT    COST      AGE",
      ...rows,
    ].join("\n") + suffix
  );
}

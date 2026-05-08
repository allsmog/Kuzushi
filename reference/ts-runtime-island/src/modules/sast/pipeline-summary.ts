import type { PipelineResult } from "../../cli/commands/scan-pipeline.js";

export interface PipelineSummaryInput {
  result: PipelineResult;
  repoName: string;
  label: string;
  postProcessMode: "full" | "scan-only";
  /**
   * M5: optional canonical finding count to override `result.stats.totalFindings`.
   * Pass the DB-derived count (e.g. `SELECT COUNT(*) FROM scan_findings WHERE
   * run_id = ?` resolved via the workspace handle) so the operator-visible
   * summary line agrees with the persisted DB. Without this, the summary
   * shows the in-memory orchestrator count which can drift from the DB
   * after dedup/upsert (carlini-threat-hunt's report stage was observed
   * showing 32 findings while the DB held 33).
   */
  canonicalFindingCount?: number;
}

const API_KEY_SENSITIVE_TASKS = new Set([
  "triage",
  "triage-escalation",
  "patch",
  "verify",
  "agentic-sast",
  "taint-iris",
  "carlini-threat-hunt",
  "threat-model-randori",
  "context-enricher",
  "app-model-build",
]);

export function summarizePipelineResult(input: PipelineSummaryInput): string {
  const { result, repoName, label, postProcessMode, canonicalFindingCount } = input;

  if (result.aborted) {
    return `${label} cancelled: ${repoName}`;
  }

  const findings = canonicalFindingCount ?? result.stats?.totalFindings ?? 0;
  const triaged = result.stats?.triaged ?? 0;
  const cost = result.stats?.totalCostUsd;
  const costSuffix = cost ? ` ($${cost.toFixed(2)})` : "";
  const failedTasks = result.stats?.failedTasks ?? [];
  const deadLetters = result.stats?.deadLetterCount ?? 0;
  const legacyIrisDegradation = result.stats?.legacyIrisDegradation;

  const findingsFragment =
    postProcessMode === "scan-only"
      ? `${findings} findings${costSuffix}`
      : `${findings} findings, ${triaged} triaged${costSuffix}`;

  if (
    result.status === "complete" &&
    failedTasks.length === 0 &&
    deadLetters === 0 &&
    legacyIrisDegradation?.type === "legacy-inconclusive"
  ) {
    return [
      `${label} inconclusive: ${repoName} — ${findingsFragment}`,
      `  ${legacyIrisDegradation.message}`,
    ].join("\n");
  }

  if (result.status === "complete" && failedTasks.length === 0 && deadLetters === 0) {
    return `${label} complete: ${repoName} — ${findingsFragment}`;
  }

  const lines: string[] = [];
  if (result.status === "complete") {
    lines.push(`${label} complete with warnings: ${repoName} — ${findingsFragment}`);
  } else {
    lines.push(
      `${label} finished with errors: ${repoName}${findings > 0 ? ` — ${findingsFragment}` : ""}`,
    );
  }

  if (failedTasks.length > 0) {
    const apiKeyCount = failedTasks.filter((t) => API_KEY_SENSITIVE_TASKS.has(t)).length;
    const otherTasks = failedTasks.filter((t) => !API_KEY_SENSITIVE_TASKS.has(t));
    if (apiKeyCount > 0) {
      lines.push(
        `  ${apiKeyCount} task${apiKeyCount === 1 ? "" : "s"} skipped — requires API key for AI analysis`,
      );
    }
    if (otherTasks.length > 0) {
      const shown = otherTasks.slice(0, 3).join(", ");
      const overflow = otherTasks.length > 3 ? ` (+${otherTasks.length - 3} more)` : "";
      lines.push(
        `  ${otherTasks.length} task${otherTasks.length === 1 ? "" : "s"} failed: ${shown}${overflow}`,
      );
    }
  }

  if (deadLetters > 0) {
    lines.push(`  ${deadLetters} event${deadLetters === 1 ? "" : "s"} dead-lettered`);
  }

  if (legacyIrisDegradation) {
    lines.push(`  ${legacyIrisDegradation.message}`);
  }

  if (result.error && result.status !== "complete") {
    lines.push(`  ${result.error}`);
  }

  lines.push(`  Run ID: ${result.runId}`);
  return lines.join("\n");
}

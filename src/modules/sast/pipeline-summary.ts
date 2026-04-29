import type { PipelineResult } from "../../cli/commands/scan-pipeline.js";

export interface PipelineSummaryInput {
  result: PipelineResult;
  repoName: string;
  label: string;
  postProcessMode: "full" | "scan-only";
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
  const { result, repoName, label, postProcessMode } = input;

  if (result.aborted) {
    return `${label} cancelled: ${repoName}`;
  }

  const findings = result.stats?.totalFindings ?? 0;
  const triaged = result.stats?.triaged ?? 0;
  const cost = result.stats?.totalCostUsd;
  const costSuffix = cost ? ` ($${cost.toFixed(2)})` : "";
  const failedTasks = result.stats?.failedTasks ?? [];
  const deadLetters = result.stats?.deadLetterCount ?? 0;

  const findingsFragment =
    postProcessMode === "scan-only"
      ? `${findings} findings${costSuffix}`
      : `${findings} findings, ${triaged} triaged${costSuffix}`;

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

  if (result.error && result.status !== "complete") {
    lines.push(`  ${result.error}`);
  }

  lines.push(`  Run ID: ${result.runId}`);
  return lines.join("\n");
}

import type Database from "better-sqlite3";
import type { PipelineStats } from "./bus/events.js";
import {
  getActionableFindings,
  getTotalCost,
  getTotalVerificationCost,
  getVerificationCounts,
  getVerdictCounts,
} from "./store.js";

interface RunMetaRow {
  startedAt?: string;
  configJson?: string;
}

export function generateMarkdownReport(
  db: Database.Database,
  repo: string,
  stats: Partial<PipelineStats>,
  runId: string,
): string {
  const verdictCounts = getVerdictCounts(db, repo);
  const verificationCounts = getVerificationCounts(db, repo);
  const triageCostUsd = getTotalCost(db, repo);
  const verifyCostUsd = getTotalVerificationCost(db, repo);
  const actionable = getActionableFindings(db, repo);

  const runMeta = db.prepare(`
    SELECT
      started_at as startedAt,
      config_json as configJson
    FROM pipeline_runs
    WHERE run_id = ?
    LIMIT 1
  `).get(runId) as RunMetaRow | undefined;

  const { model, scanners } = parseRunConfig(runMeta?.configJson);

  const lines: string[] = [];
  lines.push(`# Kuzushi Security Report - ${repo}`);
  lines.push("");
  lines.push(`Run ID: \`${runId}\``);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("| --- | ---: |");
  lines.push(`| Total findings | ${stats.totalFindings ?? verdictCounts.tp + verdictCounts.fp + verdictCounts.needs_review} |`);
  lines.push(`| Queued for triage | ${stats.queuedForTriage ?? 0} |`);
  lines.push(`| Skipped (already triaged) | ${stats.skippedAlreadyTriaged ?? 0} |`);
  lines.push(`| Skipped (low confidence) | ${stats.skippedLowConfidence ?? 0} |`);
  lines.push(`| True positives | ${verdictCounts.tp} |`);
  lines.push(`| Needs review | ${verdictCounts.needs_review} |`);
  lines.push(`| False positives | ${verdictCounts.fp} |`);
  lines.push(`| Exploitable | ${verificationCounts.exploitable} |`);
  lines.push(`| Not exploitable | ${verificationCounts.notExploitable} |`);
  lines.push(`| Triage cost (USD) | ${triageCostUsd.toFixed(4)} |`);
  lines.push(`| Verification cost (USD) | ${verifyCostUsd.toFixed(4)} |`);
  lines.push(`| Total cost (USD) | ${(triageCostUsd + verifyCostUsd).toFixed(4)} |`);

  lines.push("");
  lines.push("## Actionable Findings");
  lines.push("");

  if (actionable.length === 0) {
    lines.push("No actionable findings.");
  } else {
    for (const finding of actionable) {
      lines.push(`### ${finding.ruleId} (${finding.verdict.toUpperCase()})`);
      lines.push("");
      lines.push(`- File: \`${finding.filePath}:${finding.startLine}\``);
      lines.push(`- Scanner: \`${finding.scanner}\``);
      lines.push(`- Severity: \`${finding.severity}\``);
      lines.push(`- Confidence: ${(finding.confidence * 100).toFixed(0)}%`);
      lines.push("");
      lines.push("Triage rationale:");
      lines.push("");
      lines.push(finding.rationale || "No rationale provided.");
      lines.push("");

      if (finding.verifyExploitable === 1) {
        lines.push("Verification result: **EXPLOITABLE**");
      } else if (finding.verifyExploitable === 0) {
        lines.push("Verification result: **Not exploitable**");
      } else {
        lines.push("Verification result: **Not verified**");
      }
      lines.push("");

      if (finding.verifyPocPayload) {
        lines.push("PoC payload:");
        lines.push("");
        lines.push("```text");
        lines.push(finding.verifyPocPayload);
        lines.push("```");
        lines.push("");
      }

      if (finding.verifyAttackVector) {
        lines.push(`Attack vector: ${finding.verifyAttackVector}`);
        lines.push("");
      }

      const preconditions = parsePreconditions(finding.verifyPreconditions);
      if (preconditions.length > 0) {
        lines.push("Preconditions:");
        for (const item of preconditions) {
          lines.push(`- ${item}`);
        }
        lines.push("");
      }
    }
  }

  lines.push("## Metadata");
  lines.push("");
  lines.push(`- Scan started: ${runMeta?.startedAt ?? stats.startedAt ?? "unknown"}`);
  lines.push(`- Scan completed: ${stats.completedAt ?? "unknown"}`);
  lines.push(`- Model: ${model ?? "unknown"}`);
  lines.push(`- Scanners: ${scanners.length > 0 ? scanners.join(", ") : "unknown"}`);

  return `${lines.join("\n")}\n`;
}

function parsePreconditions(raw: string | null): string[] {
  if (!raw) {
    return [];
  }

  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed
      .map((item) => String(item).trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

function parseRunConfig(raw: string | undefined): { model?: string; scanners: string[] } {
  if (!raw) {
    return { model: undefined, scanners: [] };
  }

  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const model = typeof parsed["model"] === "string" ? parsed["model"] : undefined;
    const scanners = Array.isArray(parsed["scanners"])
      ? parsed["scanners"].map((item) => String(item).trim()).filter(Boolean)
      : [];

    return {
      model,
      scanners,
    };
  } catch {
    return { model: undefined, scanners: [] };
  }
}

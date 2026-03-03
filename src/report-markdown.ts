import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import type Database from "better-sqlite3";
import type { PipelineStats } from "./bus/events.js";
import {
  getActionableFindings,
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
  fingerprints?: string[],
): string {
  const allFindings = getActionableFindings(db, repo, { includeFalsePositives: true, fingerprints });

  const verdictCounts = { tp: 0, fp: 0, needs_review: 0 };
  let exploitable = 0;
  let notExploitable = 0;
  let pocGenerated = 0;
  let pocSkipped = 0;
  for (const f of allFindings) {
    if (f.verdict === "tp") verdictCounts.tp++;
    else if (f.verdict === "fp") verdictCounts.fp++;
    else verdictCounts.needs_review++;
    if (f.verifyExploitable === 1) exploitable++;
    else if (f.verifyExploitable === 0) notExploitable++;
    if (f.pocHarnessPath && !f.pocHarnessSkipped) pocGenerated++;
    if (f.pocHarnessSkipped === 1) pocSkipped++;
  }

  const verificationCounts = { exploitable, notExploitable };
  const pocHarnessCounts = { generated: pocGenerated, skipped: pocSkipped };
  const triageCostUsd = stats.totalCostUsd ?? 0;
  const verifyCostUsd = stats.verifyCostUsd ?? allFindings.reduce((sum, f) => sum + (f.verifyCostUsd ?? 0), 0);
  const pocHarnessCostUsd = stats.pocHarnessCostUsd ?? allFindings.reduce((sum, f) => sum + (f.pocHarnessCostUsd ?? 0), 0);
  const actionable = allFindings.filter((f) => f.verdict !== "fp");

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
  lines.push(`| Triage errors | ${stats.triageErrors ?? 0} |`);
  lines.push(`| Exploitable | ${verificationCounts.exploitable} |`);
  lines.push(`| Not exploitable | ${verificationCounts.notExploitable} |`);
  lines.push(`| Verification errors | ${stats.verifyErrors ?? 0} |`);
  lines.push(`| PoC harnesses generated | ${pocHarnessCounts.generated} |`);
  lines.push(`| PoC harnesses skipped | ${pocHarnessCounts.skipped} |`);
  lines.push(`| PoC harness errors | ${stats.pocHarnessErrors ?? 0} |`);
  lines.push(`| Triage cost (USD) | ${triageCostUsd.toFixed(4)} |`);
  lines.push(`| Verification cost (USD) | ${verifyCostUsd.toFixed(4)} |`);
  lines.push(`| PoC harness cost (USD) | ${pocHarnessCostUsd.toFixed(4)} |`);
  lines.push(`| Total cost (USD) | ${(triageCostUsd + verifyCostUsd + pocHarnessCostUsd).toFixed(4)} |`);

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

      if (finding.pocHarnessPath) {
        lines.push(`PoC harness path: \`${finding.pocHarnessPath}\``);
      } else if (finding.pocHarnessSkipped === 1) {
        lines.push(`PoC harness: **Skipped** (${finding.pocHarnessSkipReason ?? "no reason provided"})`);
      } else {
        lines.push("PoC harness: **Not generated**");
      }
      lines.push("");
      if (finding.pocHarnessParsed === 0 && finding.pocHarnessParseError) {
        lines.push(`PoC harness parse check: **Failed** (${finding.pocHarnessParseError})`);
        lines.push("");
      }
    }
  }

  lines.push("## PoC Harnesses");
  lines.push("");
  const findingsWithHarness = actionable.filter((finding) => Boolean(finding.pocHarnessPath));
  if (findingsWithHarness.length === 0) {
    lines.push("No PoC harnesses generated.");
  } else {
    for (const finding of findingsWithHarness) {
      const scriptPath = finding.pocHarnessPath as string;
      lines.push(`### ${finding.ruleId} (${finding.fingerprint.slice(0, 12)}...)`);
      lines.push("");
      lines.push(`- Path: \`${scriptPath}\``);
      lines.push(`- Parsed: ${finding.pocHarnessParsed === 1 ? "yes" : "no"}`);
      lines.push("");

      if (!existsSync(scriptPath)) {
        lines.push("_Script file not found on disk._");
        lines.push("");
        continue;
      }

      const script = readFileSync(scriptPath, "utf-8");
      const language = languageFromPath(scriptPath, finding.pocHarnessLanguage);
      lines.push(`\`\`\`${language}`);
      lines.push(script);
      lines.push("```");
      lines.push("");
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

function languageFromPath(filePath: string, fallback: string | null): string {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".ts") return "ts";
  if (ext === ".js" || ext === ".mjs" || ext === ".cjs") return "js";
  if (ext === ".py") return "python";
  if (ext === ".sh") return "sh";
  if (fallback && fallback.trim().length > 0) {
    return fallback.trim().toLowerCase();
  }
  return "text";
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

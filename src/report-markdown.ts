import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import type Database from "better-sqlite3";
import type { PipelineStats } from "./bus/events.js";
import { formatTaintPathForDisplay, summarizeTaintPath } from "./findings/taint-path.js";
import type { RunMetrics } from "./scoring/run-metrics.js";
import {
  getActionableFindings,
} from "./store.js";
import { loadThreatModelDocument, renderThreatModelContext } from "./threat-model-renderer.js";

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
  repoRoot?: string,
): string {
  const allFindings = getActionableFindings(db, repo, { includeFalsePositives: true, fingerprints });

  const verdictCounts = { tp: 0, fp: 0, needs_review: 0, by_design: 0 };
  let exploitable = 0;
  let notExploitable = 0;
  let pocGenerated = 0;
  let pocSkipped = 0;
  for (const f of allFindings) {
    if (f.verdict === "tp") verdictCounts.tp++;
    else if (f.verdict === "fp") verdictCounts.fp++;
    else if (f.verdict === "by_design") verdictCounts.by_design++;
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

  const { model, tasks } = parseRunConfig(runMeta?.configJson);

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

  // Threat model context
  if (repoRoot) {
    const threatModel = loadThreatModelDocument(repoRoot, runId);
    if (threatModel) {
      lines.push("## Threat Model Context");
      lines.push("");
      lines.push(renderThreatModelContext(threatModel));
      lines.push("");
    }
  }

  lines.push("## Actionable Findings");
  lines.push("");

  if (actionable.length === 0) {
    lines.push("No actionable findings.");
  } else {
    for (const finding of actionable) {
      lines.push(`### ${finding.ruleId} (${finding.verdict.toUpperCase()})`);
      lines.push("");
      lines.push(`- File: \`${finding.filePath}:${finding.startLine}\``);
      lines.push(`- Scanner: \`${finding.taskId}\``);
      lines.push(`- Severity: \`${finding.severity}\``);
      lines.push(`- Confidence: ${(finding.confidence * 100).toFixed(0)}%`);
      if (finding.proofState) {
        lines.push(`- Proof state: \`${formatProofStateLabel(finding.proofState)}\``);
      }
      if (finding.engineProvenance && finding.engineProvenance.length > 0) {
        lines.push(`- Engine provenance: ${formatEngineProvenance(finding.engineProvenance)}`);
      }
      if (finding.taintPath && finding.taintPath.length > 0) {
        lines.push(`- Taint path summary: \`${summarizeTaintPath(finding.taintPath) ?? ""}\``);
      }
      lines.push("");
      lines.push("Triage rationale:");
      lines.push("");
      lines.push(finding.rationale || "No rationale provided.");
      lines.push("");

      const taintPathLines = formatTaintPathForDisplay(finding.taintPath);
      if (taintPathLines.length > 0) {
        lines.push("Structured taint path:");
        lines.push("");
        for (const line of taintPathLines) {
          lines.push(`- ${line}`);
        }
        lines.push("");
      }

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
        lines.push(escapeFenceContent(finding.verifyPocPayload));
        lines.push("```");
        lines.push("");
      }

      if (finding.verifyAttackVector) {
        lines.push(`Attack vector: ${finding.verifyAttackVector}`);
        lines.push("");
      }

      const preconditions = finding.verifyPreconditions;
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

      if (finding.pocRunVerdict) {
        lines.push(`PoC execution: **${finding.pocRunVerdict}**${formatPocDuration(finding.pocRunDurationMs)}`);
        lines.push("");
      }

      if (finding.pocHarnessParsed === 0 && finding.pocHarnessParseError) {
        lines.push(`PoC harness parse check: **Failed** (${finding.pocHarnessParseError})`);
        lines.push("");
      }

      if (finding.codeCitations && finding.codeCitations.length > 0) {
        lines.push("Evidence:");
        lines.push("");
        for (const citation of finding.codeCitations) {
          lines.push(`#### \`${citation.filePath}:${citation.startLine}-${citation.endLine}\``);
          lines.push("");
          lines.push(citation.description);
          if (citation.snippet) {
            lines.push("");
            lines.push("```");
            lines.push(escapeFenceContent(citation.snippet));
            lines.push("```");
          }
          lines.push("");
        }
      }

      if (finding.attackPath) {
        lines.push("Attack-path analysis:");
        lines.push("");
        if (finding.attackPath.chain.length > 0) {
          lines.push(finding.attackPath.chain.join(" --> "));
          lines.push("");
        }
        if (finding.attackPath.narrative) {
          lines.push(finding.attackPath.narrative);
          lines.push("");
        }
        if (finding.attackPath.likelihoodReasoning) {
          lines.push(`**Likelihood**: ${finding.attackPath.likelihoodReasoning}`);
          lines.push("");
        }
        if (finding.attackPath.impactReasoning) {
          lines.push(`**Impact**: ${finding.attackPath.impactReasoning}`);
          lines.push("");
        }
      }

      if (finding.assumptions && finding.assumptions.length > 0) {
        lines.push("Assumptions:");
        for (const a of finding.assumptions) lines.push(`- ${a}`);
        lines.push("");
      }
      if (finding.controls && finding.controls.length > 0) {
        lines.push("Controls:");
        for (const c of finding.controls) {
          const loc = c.filePath ? ` (\`${c.filePath}\`)` : "";
          lines.push(`- **${c.name}**${loc}: ${c.description}`);
        }
        lines.push("");
      }
      if (finding.blindspots && finding.blindspots.length > 0) {
        lines.push("Blindspots:");
        for (const b of finding.blindspots) lines.push(`- ${b}`);
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
      const language = sanitizeLanguageId(languageFromPath(scriptPath, finding.pocHarnessLanguage));
      lines.push(`\`\`\`${language}`);
      lines.push(escapeFenceContent(script));
      lines.push("```");
      lines.push("");
    }
  }

  const runMetrics = stats.runMetrics;
  if (runMetrics) {
    appendMetricsSection(lines, runMetrics);
  }

  lines.push("## Metadata");
  lines.push("");
  lines.push(`- Scan started: ${runMeta?.startedAt ?? stats.startedAt ?? "unknown"}`);
  lines.push(`- Scan completed: ${stats.completedAt ?? "unknown"}`);
  lines.push(`- Model: ${model ?? "unknown"}`);
  lines.push(`- Scanners: ${tasks.length > 0 ? tasks.join(", ") : "unknown"}`);

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

/** Escape sequences of 3+ backticks inside fenced code blocks to prevent fence injection. */
function escapeFenceContent(s: string): string {
  return s.replace(/`{3,}/g, (m) => m.split("").join("\u200B"));
}

/** Restrict language identifier to safe characters only. */
function sanitizeLanguageId(lang: string): string {
  return lang.replace(/[^a-z0-9+#.\-]/gi, "").slice(0, 20) || "text";
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
    // Graceful degradation: preconditions JSON from the DB may be malformed.
    // Return empty list so the markdown report renders without this section.
    return [];
  }
}

function parseRunConfig(raw: string | undefined): { model?: string; tasks: string[] } {
  if (!raw) {
    return { model: undefined, tasks: [] };
  }

  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const model = typeof parsed["model"] === "string" ? parsed["model"] : undefined;
    const tasks = Array.isArray(parsed["tasks"])
      ? parsed["tasks"].map((item) => String(item).trim()).filter(Boolean)
      : [];

    return {
      model,
      tasks,
    };
  } catch {
    // Graceful degradation: config JSON from the DB may be corrupted or
    // written by a different schema version. Return safe defaults so markdown
    // generation still succeeds with partial metadata.
    return { model: undefined, tasks: [] };
  }
}

function formatDurationMs(ms: number): string {
  if (ms < 1000) {
    return `${ms}ms`;
  }
  const seconds = ms / 1000;
  if (seconds < 60) {
    return `${seconds.toFixed(1)}s`;
  }
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${remainingSeconds.toFixed(0)}s`;
}

function appendMetricsSection(lines: string[], metrics: RunMetrics): void {
  lines.push("## Run Metrics");
  lines.push("");

  // Verdict breakdown table
  lines.push("### Verdict Breakdown");
  lines.push("");
  lines.push("| Verdict | Count | Rate |");
  lines.push("| --- | ---: | ---: |");
  const verdictTotal = Object.values(metrics.verdictCounts).reduce((s, n) => s + n, 0);
  for (const [verdict, count] of Object.entries(metrics.verdictCounts)) {
    const pct = verdictTotal > 0 ? ((count / verdictTotal) * 100).toFixed(1) : "0.0";
    lines.push(`| ${verdict} | ${count} | ${pct}% |`);
  }
  lines.push(`| **TP Rate** | | **${(metrics.tpRate * 100).toFixed(1)}%** |`);
  lines.push(`| **FP Rate** | | **${(metrics.fpRate * 100).toFixed(1)}%** |`);
  lines.push("");

  // Severity distribution
  const sevEntries = Object.entries(metrics.severityCounts);
  if (sevEntries.length > 0) {
    lines.push("### Severity Distribution");
    lines.push("");
    lines.push("| Severity | Count |");
    lines.push("| --- | ---: |");
    for (const [severity, count] of sevEntries) {
      lines.push(`| ${severity} | ${count} |`);
    }
    lines.push("");
  }

  // Task yield
  const yieldEntries = Object.entries(metrics.taskYield);
  if (yieldEntries.length > 0) {
    lines.push("### Task Yield");
    lines.push("");
    lines.push("| Task | Findings |");
    lines.push("| --- | ---: |");
    for (const [taskId, count] of yieldEntries) {
      lines.push(`| ${taskId} | ${count} |`);
    }
    lines.push("");
  }

  // Confidence & exploitability
  lines.push("### Quality Metrics");
  lines.push("");
  lines.push(`- Average Confidence: ${(metrics.averageConfidence * 100).toFixed(1)}%`);
  if (metrics.exploitabilityRate != null) {
    lines.push(`- Exploitability Rate: ${(metrics.exploitabilityRate * 100).toFixed(1)}%`);
  }
  lines.push(`- Findings With Taint Path: ${metrics.structuredEvidence.findingsWithTaintPath}`);
  const proofEntries = Object.entries(metrics.structuredEvidence.proofStateCounts);
  if (proofEntries.length > 0) {
    lines.push(`- Proof States: ${proofEntries.map(([state, count]) => `${state}=${count}`).join(", ")}`);
  }
  const engineEntries = Object.entries(metrics.structuredEvidence.engineKindCounts);
  if (engineEntries.length > 0) {
    lines.push(`- Engine Provenance: ${engineEntries.map(([kind, count]) => `${kind}=${count}`).join(", ")}`);
  }
  lines.push("");

  // Duration breakdown
  lines.push("### Duration Breakdown");
  lines.push("");
  lines.push("| Stage | Duration |");
  lines.push("| --- | ---: |");
  lines.push(`| Scan | ${formatDurationMs(metrics.durationBreakdown.scan)} |`);
  lines.push(`| Triage | ${formatDurationMs(metrics.durationBreakdown.triage)} |`);
  if (metrics.durationBreakdown.verify != null) {
    lines.push(`| Verify | ${formatDurationMs(metrics.durationBreakdown.verify)} |`);
  }
  if (metrics.durationBreakdown.pocHarness != null) {
    lines.push(`| PoC Harness | ${formatDurationMs(metrics.durationBreakdown.pocHarness)} |`);
  }
  lines.push(`| **Total** | **${formatDurationMs(metrics.durationBreakdown.total)}** |`);
  lines.push("");

  // Cost breakdown
  lines.push("### Cost Breakdown");
  lines.push("");
  lines.push("| Category | Cost (USD) |");
  lines.push("| --- | ---: |");
  lines.push(`| Triage | $${metrics.costBreakdown.triage.toFixed(4)} |`);
  lines.push(`| Verify | $${metrics.costBreakdown.verify.toFixed(4)} |`);
  lines.push(`| PoC Harness | $${metrics.costBreakdown.pocHarness.toFixed(4)} |`);
  lines.push(`| Variant Analysis | $${metrics.costBreakdown.variantAnalysis.toFixed(4)} |`);
  lines.push(`| **Total** | **$${metrics.costBreakdown.total.toFixed(4)}** |`);
  lines.push("");
}

function formatProofStateLabel(proofState: string): string {
  return proofState.replace(/_/g, " ");
}

function formatEngineProvenance(
  engineProvenance: Array<{ kind: string; detail: string }>,
): string {
  return engineProvenance
    .map((entry) => `\`${entry.kind}\` (${entry.detail})`)
    .join(", ");
}

function formatPocDuration(durationMs: number | null | undefined): string {
  if (typeof durationMs !== "number" || !Number.isFinite(durationMs)) {
    return "";
  }
  return ` (${formatDurationMs(durationMs)})`;
}

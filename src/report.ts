import path from "node:path";
import type Database from "better-sqlite3";
import chalk from "chalk";
import type { PipelineStats } from "./bus/events.js";
import { formatTaintPathForDisplay, summarizeTaintPath } from "./findings/taint-path.js";
import type { QualityGateResult } from "./quality-gate.js";
import type { TaskId } from "./scanners/types.js";
import type { RunMetrics } from "./scoring/run-metrics.js";
import { getActionableFindings } from "./store.js";
import type { ExploitChain, TriageResult, Verdict } from "./types.js";

/** Print quality gate results to terminal. */
export function printQualityGateResult(result: QualityGateResult): void {
  console.log("");
  if (result.passed) {
    console.log(`  ${chalk.green.bold("Quality Gates: PASSED")}`);
  } else {
    console.log(`  ${chalk.red.bold("Quality Gates: FAILED")}`);
    for (const violation of result.violations) {
      console.log(`    ${chalk.red("x")} ${chalk.bold(violation.rule)}: ${violation.message}`);
      if (violation.fingerprints && violation.fingerprints.length > 0) {
        const shown = violation.fingerprints.slice(0, 5);
        for (const fp of shown) {
          console.log(`      ${chalk.dim(fp.slice(0, 16))}...`);
        }
        if (violation.fingerprints.length > 5) {
          console.log(`      ${chalk.dim(`... and ${violation.fingerprints.length - 5} more`)}`);
        }
      }
    }
  }
  console.log(chalk.bold("─".repeat(60)));
}

/** Color a verdict string. */
function colorVerdict(verdict: Verdict): string {
  switch (verdict) {
    case "tp":
      return chalk.red.bold("TRUE POSITIVE");
    case "fp":
      return chalk.green("false positive");
    case "needs_review":
      return chalk.yellow("needs review");
    case "by_design":
      return chalk.blue("BY DESIGN");
  }
}

/** Print a progress line for a single triage result. */
export function printTriageProgress(
  result: TriageResult,
  index: number,
  total: number,
  attempts?: number,
): void {
  const verdict = colorVerdict(result.verdict);
  const conf = chalk.dim(`(${(result.confidence * 100).toFixed(0)}%)`);
  const cost =
    result.triageCostUsd && result.triageCostUsd > 0
      ? chalk.dim(`$${result.triageCostUsd.toFixed(4)}`)
      : "";
  const retry = attempts && attempts > 1 ? chalk.dim(`(retry #${attempts})`) : "";
  console.log(
    `  [${index}/${total}] ${verdict} ${conf}${cost ? ` ${cost}` : ""}${retry ? ` ${retry}` : ""} ${chalk.dim(result.fingerprint.slice(0, 12))}...`,
  );
}

export interface PrintSummaryOptions {
  stats?: Partial<PipelineStats>;
  runId?: string;
  repoRoot?: string;
  auditLog?: boolean;
  fingerprints?: string[];
  exploitChains?: ExploitChain[];
}

/** Print the final scan summary to terminal. */
export function printSummary(
  db: Database.Database,
  repo: string,
  options: PrintSummaryOptions = {},
): void {
  const fp = options.fingerprints;
  const allFindings = getActionableFindings(db, repo, {
    includeFalsePositives: true,
    fingerprints: fp,
  });

  const counts: Record<Verdict, number> = { tp: 0, fp: 0, needs_review: 0, by_design: 0 };
  for (const f of allFindings) {
    counts[f.verdict]++;
  }

  const triageCostUsd = options.stats?.totalCostUsd ?? 0;
  const verificationCostUsd =
    options.stats?.verifyCostUsd ?? allFindings.reduce((sum, f) => sum + (f.verifyCostUsd ?? 0), 0);
  const pocHarnessCostUsd =
    options.stats?.pocHarnessCostUsd ??
    allFindings.reduce((sum, f) => sum + (f.pocHarnessCostUsd ?? 0), 0);

  let exploitable = 0;
  let notExploitable = 0;
  let pocGenerated = 0;
  let pocSkipped = 0;
  for (const f of allFindings) {
    if (f.verifyExploitable === 1) exploitable++;
    else if (f.verifyExploitable === 0) notExploitable++;
    if (f.pocHarnessPath && !f.pocHarnessSkipped) pocGenerated++;
    if (f.pocHarnessSkipped === 1) pocSkipped++;
  }

  const verificationCounts = { exploitable, notExploitable };
  const pocHarnessCounts = { generated: pocGenerated, skipped: pocSkipped };
  const hasVerificationStats =
    verificationCounts.exploitable + verificationCounts.notExploitable > 0;
  const hasVerificationSpend = verificationCostUsd > 0;
  const hasVerificationErrors = (options.stats?.verifyErrors ?? 0) > 0;
  const hasVerificationData = hasVerificationStats || hasVerificationSpend || hasVerificationErrors;
  const hasPocHarnessData =
    pocHarnessCounts.generated > 0 ||
    pocHarnessCounts.skipped > 0 ||
    (options.stats?.pocHarnessErrors ?? 0) > 0 ||
    pocHarnessCostUsd > 0;
  const total = counts.tp + counts.fp + counts.needs_review;
  const actionable = allFindings.filter((f) => f.verdict !== "fp");

  console.log("");
  console.log(chalk.bold("─".repeat(60)));
  console.log(chalk.bold("  Kuzushi Scan Results"));
  console.log(chalk.bold("─".repeat(60)));
  console.log("");
  const failedTasks = options.stats?.failedTasks;
  if (failedTasks && failedTasks.length > 0) {
    console.log(
      `  ${chalk.red("Scanners failed:")}  ${failedTasks.join(", ")} ${chalk.dim("(results may be incomplete)")}`,
    );
    console.log("");
  }
  const extractionDeg = options.stats?.extractionDegradation;
  if (extractionDeg && extractionDeg.status !== "ok") {
    const colorFn = extractionDeg.status === "failed" ? chalk.red : chalk.yellow;
    console.log(
      `  ${colorFn("Extraction status:")}  ${extractionDeg.status} [${extractionDeg.reasons.join(", ")}]`,
    );
    console.log("");
  }
  const stitchDeg = options.stats?.stitchDegradation;
  if (stitchDeg) {
    console.log(`  ${chalk.yellow("Stitch status:")}     degraded [${stitchDeg.reason}]`);
    console.log("");
  }
  if (options.stats?.tiPriorDegraded) {
    console.log(`  ${chalk.yellow("TI Prior status:")}   degraded`);
    console.log("");
  }
  console.log(`  ${chalk.dim("Total triaged:")}    ${total}`);
  console.log(`  ${chalk.red.bold("True positives:")}   ${counts.tp}`);
  console.log(`  ${chalk.green("False positives:")}  ${counts.fp}`);
  console.log(`  ${chalk.yellow("Needs review:")}     ${counts.needs_review}`);
  if ((options.stats?.triageErrors ?? 0) > 0) {
    console.log(`  ${chalk.red("Triage errors:")}     ${options.stats?.triageErrors}`);
  }
  if ((options.stats?.skippedLowConfidence ?? 0) > 0) {
    console.log(
      `  ${chalk.dim("Skipped (low confidence):")} ${options.stats?.skippedLowConfidence}`,
    );
  }
  if ((options.stats?.skippedByFpFilter ?? 0) > 0) {
    console.log(`  ${chalk.dim("Skipped (hard exclusions):")} ${options.stats?.skippedByFpFilter}`);
  }
  if ((options.stats?.softSuppressedFindings ?? 0) > 0) {
    console.log(
      `  ${chalk.dim("Soft-suppressed findings:")} ${options.stats?.softSuppressedFindings}`,
    );
  }
  if ((options.stats?.skippedByLlmRescore ?? 0) > 0) {
    console.log(`  ${chalk.dim("Skipped (LLM rescore):")} ${options.stats?.skippedByLlmRescore}`);
  }
  if ((options.stats?.corroboratedClusters ?? 0) > 0) {
    console.log(`  ${chalk.dim("Corroborated clusters:")} ${options.stats?.corroboratedClusters}`);
  }
  if (
    (options.stats?.verifyGateAutoAccepted ?? 0) > 0 ||
    (options.stats?.verifyGateSkipped ?? 0) > 0
  ) {
    console.log(
      `  ${chalk.dim("Gate auto-accepted:")}   ${options.stats?.verifyGateAutoAccepted ?? 0}`,
    );
    console.log(
      `  ${chalk.dim("Gate skipped:")}          ${options.stats?.verifyGateSkipped ?? 0}`,
    );
  }
  if (hasVerificationData) {
    const verifyErrors = options.stats?.verifyErrors ?? 0;
    console.log("");
    if (hasVerificationStats) {
      console.log(`  ${chalk.red.bold("Exploitable:")}      ${verificationCounts.exploitable}`);
      console.log(`  ${chalk.green("Not exploitable:")}  ${verificationCounts.notExploitable}`);
    } else {
      console.log(`  ${chalk.yellow("Verification:")}    errors only`);
    }
    if (verifyErrors > 0) {
      console.log(`  ${chalk.red("Verification errors:")} ${verifyErrors}`);
    }
  }
  if (hasPocHarnessData) {
    console.log("");
    console.log(`  ${chalk.cyan("PoC harnesses generated:")} ${pocHarnessCounts.generated}`);
    console.log(`  ${chalk.yellow("PoC harnesses skipped:")}   ${pocHarnessCounts.skipped}`);
    console.log(
      `  ${chalk.red("PoC harness errors:")}     ${options.stats?.pocHarnessErrors ?? 0}`,
    );
    if (options.repoRoot) {
      const pocDir = path.join(options.repoRoot, ".kuzushi", "poc");
      console.log(`  ${chalk.dim("PoC output dir:")} ${pocDir}/`);
    }
  }

  if ((options.stats?.variantFindings ?? 0) > 0) {
    console.log("");
    console.log(`  ${chalk.cyan("Variant findings:")}  ${options.stats?.variantFindings}`);
  }

  const dynConfirmed = options.stats?.dynamicConfirmed ?? 0;
  const dynInteresting = options.stats?.dynamicInteresting ?? 0;
  const dynRejected = options.stats?.dynamicRejected ?? 0;
  const dynErrors = options.stats?.dynamicErrors ?? 0;
  if (dynConfirmed + dynInteresting + dynRejected + dynErrors > 0) {
    console.log("");
    console.log(chalk.bold("  Dynamic Analysis:"));
    console.log(`    ${chalk.red.bold("Confirmed:")}   ${dynConfirmed}`);
    console.log(`    ${chalk.yellow("Interesting:")} ${dynInteresting}`);
    console.log(`    ${chalk.green("Rejected:")}    ${dynRejected}`);
    if (dynErrors > 0) {
      console.log(`    ${chalk.red("Errors:")}      ${dynErrors}`);
    }
    if (options.stats?.dynamicCostUsd) {
      console.log(`    ${chalk.dim("Cost:")}        $${options.stats.dynamicCostUsd.toFixed(4)}`);
    }
  }

  const cachedFiles = options.stats?.incrementalCachedFiles ?? 0;
  const rescannedFiles = options.stats?.incrementalRescannedFiles ?? 0;
  const depExpanded = options.stats?.incrementalDepExpandedFiles ?? 0;
  if (cachedFiles > 0 || rescannedFiles > 0) {
    console.log("");
    console.log(
      `  ${chalk.dim("Incremental:")}     ${chalk.green(`${cachedFiles} cached`)}, ${rescannedFiles} rescanned${depExpanded > 0 ? `, ${depExpanded} dependency-expanded` : ""}`,
    );
  }

  const patchGenerated = options.stats?.patchGenerated ?? 0;
  const patchVerified = options.stats?.patchVerified ?? 0;
  const patchFailed = options.stats?.patchFailed ?? 0;
  const patchErrors = options.stats?.patchErrors ?? 0;
  if (patchGenerated + patchVerified + patchFailed + patchErrors > 0) {
    console.log("");
    console.log(chalk.bold("  Patch Synthesis:"));
    console.log(`    ${chalk.cyan("Generated:")}  ${patchGenerated}`);
    console.log(
      `    ${chalk.green("Verified:")}   ${patchVerified} (finding eliminated after patch)`,
    );
    if (patchFailed > 0) {
      console.log(`    ${chalk.red("Failed:")}     ${patchFailed}`);
    }
    if (patchErrors > 0) {
      console.log(`    ${chalk.red("Errors:")}     ${patchErrors}`);
    }
    if (options.stats?.patchCostUsd) {
      console.log(`    ${chalk.dim("Cost:")}       $${options.stats.patchCostUsd.toFixed(4)}`);
    }
  }

  const chains = options.exploitChains;
  if (chains && chains.length > 0) {
    console.log("");
    console.log(chalk.bold("  Exploitation Chains:"));
    console.log("");
    for (const chain of chains) {
      const sevColor =
        chain.overallSeverity === "CRITICAL"
          ? chalk.red.bold
          : chain.overallSeverity === "HIGH"
            ? chalk.red
            : chalk.yellow;
      console.log(`  ${sevColor(chain.overallSeverity)} ${chalk.bold(chain.name)}`);
      for (const step of chain.steps) {
        console.log(
          `    ${chalk.dim(`${step.role}:`)} ${step.description} ${chalk.dim(`[${step.findingFingerprint.slice(0, 8)}]`)}`,
        );
      }
      if (chain.preconditions.length > 0) {
        console.log(`    ${chalk.dim("Preconditions:")} ${chain.preconditions.join(", ")}`);
      }
      console.log(`    ${chalk.dim("Impact:")} ${chain.impactDescription}`);
      console.log("");
    }
  }

  if (actionable.length > 0) {
    console.log("");
    console.log(chalk.bold("  Actionable Findings:"));
    console.log("");

    for (const f of actionable) {
      const verdict = colorVerdict(f.verdict);
      const location = chalk.cyan(`${f.filePath}:${f.startLine}`);
      const conf = chalk.dim(`${(f.confidence * 100).toFixed(0)}%`);
      const severity = f.severity === "ERROR" ? chalk.red(f.severity) : chalk.yellow(f.severity);
      const scanner = chalk.dim(`[${f.taskId}]`);
      const verificationBadge =
        f.verifyExploitable === 1
          ? chalk.bgRed.white.bold(" EXPLOITABLE ")
          : f.verifyExploitable === 0
            ? chalk.bgGreen.black(" NOT EXPLOITABLE ")
            : "";

      console.log(
        `  ${verdict} ${conf}  ${severity} ${scanner}${verificationBadge ? ` ${verificationBadge}` : ""}`,
      );
      console.log(`    ${location}`);
      console.log(`    ${chalk.dim(f.ruleId)}`);
      if (f.taskId.startsWith("threat-model-")) {
        const strideMatch = f.ruleId.match(/^threat-model\/([^/]+)/);
        if (strideMatch) {
          console.log(`    ${chalk.blue("STRIDE:")} ${strideMatch[1]}`);
        }
      }
      console.log(`    ${f.rationale.slice(0, 120)}${f.rationale.length > 120 ? "..." : ""}`);
      if (f.verifyExploitable === 1 && f.verifyPocPayload) {
        const payload =
          f.verifyPocPayload.length > 80
            ? `${f.verifyPocPayload.slice(0, 77)}...`
            : f.verifyPocPayload;
        console.log(`    ${chalk.magenta("PoC:")} ${payload}`);
      }
      if (f.verifyAttackVector) {
        console.log(`    ${chalk.cyan("Vector:")} ${f.verifyAttackVector}`);
      }
      if (f.proofState) {
        console.log(`    ${chalk.magenta("Proof State:")} ${formatProofStateLabel(f.proofState)}`);
      }
      if (f.engineProvenance && f.engineProvenance.length > 0) {
        console.log(
          `    ${chalk.dim("Engine Provenance:")} ${formatEngineProvenance(f.engineProvenance)}`,
        );
      }
      const taintPathSummary = summarizeTaintPath(f.taintPath);
      if (taintPathSummary) {
        console.log(`    ${chalk.dim("Taint Path:")} ${taintPathSummary}`);
        for (const line of formatTaintPathForDisplay(f.taintPath, 3)) {
          console.log(`      ${chalk.dim(line)}`);
        }
      }
      if (f.corroboratingSignals.length > 0) {
        const tasks = [...new Set(f.corroboratingSignals.map((signal) => signal.taskId))];
        console.log(
          `    ${chalk.dim("Corroborated by:")} ${tasks.join(", ")} (+${f.corroboratingSignals.length})`,
        );
      }
      if (f.suppressionReasons.length > 0) {
        console.log(
          `    ${chalk.dim("Suppression notes:")} ${f.suppressionReasons.map((reason) => reason.id).join(", ")}`,
        );
      }
      if (f.pocHarnessPath) {
        console.log(`    ${chalk.blue("PoC Harness:")} ${f.pocHarnessPath}`);
      } else if (f.pocHarnessSkipped === 1) {
        console.log(
          `    ${chalk.yellow("PoC Harness:")} skipped (${f.pocHarnessSkipReason ?? "no reason provided"})`,
        );
      }
      if (f.pocHarnessParsed === 0 && f.pocHarnessParseError) {
        console.log(`    ${chalk.red("PoC Parse Error:")} ${f.pocHarnessParseError}`);
      }
      const pocRunVerdict = f.pocRunVerdict;
      const pocRunDurationMs = f.pocRunDurationMs;
      if (typeof pocRunVerdict === "string" && pocRunVerdict) {
        const verdictColor =
          pocRunVerdict === "PASS"
            ? chalk.green.bold
            : pocRunVerdict === "FAIL"
              ? chalk.red.bold
              : pocRunVerdict === "TIMEOUT"
                ? chalk.yellow.bold
                : chalk.red;
        const durationStr =
          typeof pocRunDurationMs === "number"
            ? chalk.dim(` (${(pocRunDurationMs / 1000).toFixed(1)}s)`)
            : "";
        console.log(`    ${verdictColor(`PoC Execution: ${pocRunVerdict}`)}${durationStr}`);
      }
      console.log("");
    }
  } else if (total > 0) {
    console.log("");
    console.log(chalk.green.bold("  All findings triaged as false positives. Code looks clean."));
  }

  console.log("");
  console.log(`  ${chalk.dim("Total triage cost:")} $${triageCostUsd.toFixed(4)}`);
  if (hasVerificationData) {
    console.log(`  ${chalk.dim("Total verification cost:")} $${verificationCostUsd.toFixed(4)}`);
  }
  if (hasPocHarnessData) {
    console.log(`  ${chalk.dim("Total PoC harness cost:")} $${pocHarnessCostUsd.toFixed(4)}`);
  }
  if ((options.stats?.variantAnalysisCostUsd ?? 0) > 0) {
    console.log(
      `  ${chalk.dim("Total variant analysis cost:")} $${options.stats!.variantAnalysisCostUsd!.toFixed(4)}`,
    );
  }
  if (options.stats?.budgetExceeded) {
    console.log("");
    console.log(
      `  ${chalk.yellow.bold("Budget exceeded:")} pipeline stopped early to stay within cost limit`,
    );
  }
  if (options.auditLog && options.repoRoot && options.runId) {
    const runDir = path.join(options.repoRoot, ".kuzushi", "runs", options.runId);
    console.log(`  ${chalk.dim("Audit log:")} ${runDir}/`);
  }

  const runMetrics = options.stats?.runMetrics;
  if (runMetrics) {
    printMetricsSummary(runMetrics);
  }

  console.log(chalk.bold("─".repeat(60)));
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

function printMetricsSummary(metrics: RunMetrics): void {
  console.log("");
  console.log(chalk.bold("  Run Metrics"));
  console.log("");

  // Verdict rates
  const verdictTotal = Object.values(metrics.verdictCounts).reduce((s, n) => s + n, 0);
  if (verdictTotal > 0) {
    for (const [verdict, count] of Object.entries(metrics.verdictCounts)) {
      const pct = ((count / verdictTotal) * 100).toFixed(1);
      console.log(`  ${chalk.dim(`${verdict}:`)} ${count} (${pct}%)`);
    }
    console.log(`  ${chalk.dim("TP Rate:")} ${(metrics.tpRate * 100).toFixed(1)}%`);
    console.log(`  ${chalk.dim("FP Rate:")} ${(metrics.fpRate * 100).toFixed(1)}%`);
    console.log("");
  }

  // Severity distribution
  const sevEntries = Object.entries(metrics.severityCounts);
  if (sevEntries.length > 0) {
    console.log(
      `  ${chalk.dim("Severity:")} ${sevEntries.map(([s, c]) => `${s}=${c}`).join(", ")}`,
    );
  }

  // Task yield
  const yieldEntries = Object.entries(metrics.taskYield);
  if (yieldEntries.length > 0) {
    console.log(
      `  ${chalk.dim("Task yield:")} ${yieldEntries.map(([s, c]) => `${s}=${c}`).join(", ")}`,
    );
  }

  // Average confidence
  if (metrics.averageConfidence > 0) {
    console.log(
      `  ${chalk.dim("Avg confidence:")} ${(metrics.averageConfidence * 100).toFixed(1)}%`,
    );
  }

  // Exploitability rate
  if (metrics.exploitabilityRate != null) {
    console.log(
      `  ${chalk.dim("Exploitability rate:")} ${(metrics.exploitabilityRate * 100).toFixed(1)}%`,
    );
  }
  console.log(
    `  ${chalk.dim("Structured evidence:")} taint-path=${metrics.structuredEvidence.findingsWithTaintPath}`,
  );
  const proofEntries = Object.entries(metrics.structuredEvidence.proofStateCounts);
  if (proofEntries.length > 0) {
    console.log(
      `  ${chalk.dim("Proof states:")} ${proofEntries.map(([state, count]) => `${state}=${count}`).join(", ")}`,
    );
  }
  const engineEntries = Object.entries(metrics.structuredEvidence.engineKindCounts);
  if (engineEntries.length > 0) {
    console.log(
      `  ${chalk.dim("Engine provenance:")} ${engineEntries.map(([kind, count]) => `${kind}=${count}`).join(", ")}`,
    );
  }

  // Duration breakdown
  console.log("");
  console.log(
    `  ${chalk.dim("Duration:")} scan=${formatDurationMs(metrics.durationBreakdown.scan)} triage=${formatDurationMs(metrics.durationBreakdown.triage)}${
      metrics.durationBreakdown.verify != null
        ? ` verify=${formatDurationMs(metrics.durationBreakdown.verify)}`
        : ""
    }${
      metrics.durationBreakdown.pocHarness != null
        ? ` poc=${formatDurationMs(metrics.durationBreakdown.pocHarness)}`
        : ""
    } total=${formatDurationMs(metrics.durationBreakdown.total)}`,
  );

  // Cost breakdown
  console.log(
    `  ${chalk.dim("Cost:")} triage=$${metrics.costBreakdown.triage.toFixed(4)} verify=$${metrics.costBreakdown.verify.toFixed(4)} poc=$${metrics.costBreakdown.pocHarness.toFixed(4)} variant=$${metrics.costBreakdown.variantAnalysis.toFixed(4)} total=$${metrics.costBreakdown.total.toFixed(4)}`,
  );
}

function formatProofStateLabel(proofState: string): string {
  return proofState.replace(/_/g, " ");
}

function formatEngineProvenance(engineProvenance: Array<{ kind: string; detail: string }>): string {
  return engineProvenance.map((entry) => `${entry.kind}:${entry.detail}`).join(", ");
}

/** Print a short line when starting a scan. */
export function printScanStart(
  repoName: string,
  findingCount: number,
  total: number,
  tasks: TaskId[],
): void {
  console.log("");
  console.log(chalk.bold(`  Kuzushi v0.1 — scanning ${repoName}`));
  console.log(`  Scanners: ${tasks.join(", ")}`);
  console.log(`  ${total} findings, ${findingCount} selected for AI triage`);
  console.log("");
}

/** Print when resuming with skipped findings. */
export function printResumeInfo(skipped: number, remaining: number): void {
  console.log(chalk.dim(`  Skipping ${skipped} already-triaged findings, ${remaining} remaining`));
}

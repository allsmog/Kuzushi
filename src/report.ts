import chalk from "chalk";
import path from "node:path";
import type { TriageResult, Verdict } from "./types.js";
import type { ScannerId } from "./scanners/types.js";
import type Database from "better-sqlite3";
import type { PipelineStats } from "./bus/events.js";
import {
  getActionableFindings,
  getPocHarnessCounts,
  getTotalCost,
  getTotalPocHarnessCost,
  getTotalVerificationCost,
  getVerificationCounts,
  getVerdictCounts,
} from "./store.js";

/** Color a verdict string. */
function colorVerdict(verdict: Verdict): string {
  switch (verdict) {
    case "tp":
      return chalk.red.bold("TRUE POSITIVE");
    case "fp":
      return chalk.green("false positive");
    case "needs_review":
      return chalk.yellow("needs review");
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
  const cost = result.triageCostUsd && result.triageCostUsd > 0
    ? chalk.dim(`$${result.triageCostUsd.toFixed(4)}`)
    : "";
  const retry = attempts && attempts > 1
    ? chalk.dim(`(retry #${attempts})`)
    : "";
  console.log(
    `  [${index}/${total}] ${verdict} ${conf}${cost ? ` ${cost}` : ""}${retry ? ` ${retry}` : ""} ${chalk.dim(result.fingerprint.slice(0, 12))}...`,
  );
}

export interface PrintSummaryOptions {
  stats?: Partial<PipelineStats>;
  runId?: string;
  repoRoot?: string;
  auditLog?: boolean;
}

/** Print the final scan summary to terminal. */
export function printSummary(
  db: Database.Database,
  repo: string,
  options: PrintSummaryOptions = {},
): void {
  const counts = getVerdictCounts(db, repo);
  const totalCostUsd = getTotalCost(db, repo);
  const verificationCostUsd = getTotalVerificationCost(db, repo);
  const pocHarnessCostUsd = getTotalPocHarnessCost(db, repo);
  const verificationCounts = getVerificationCounts(db, repo);
  const pocHarnessCounts = getPocHarnessCounts(db, repo);
  const hasVerificationStats = verificationCounts.exploitable + verificationCounts.notExploitable > 0;
  const hasVerificationSpend = verificationCostUsd > 0;
  const hasVerificationData = hasVerificationStats || hasVerificationSpend;
  const hasPocHarnessData = (
    pocHarnessCounts.generated > 0
    || pocHarnessCounts.skipped > 0
    || (options.stats?.pocHarnessErrors ?? 0) > 0
    || pocHarnessCostUsd > 0
  );
  const total = counts.tp + counts.fp + counts.needs_review;
  const actionable = getActionableFindings(db, repo);

  console.log("");
  console.log(chalk.bold("─".repeat(60)));
  console.log(chalk.bold("  Kuzushi Scan Results"));
  console.log(chalk.bold("─".repeat(60)));
  console.log("");
  console.log(`  ${chalk.dim("Total triaged:")}    ${total}`);
  console.log(`  ${chalk.red.bold("True positives:")}   ${counts.tp}`);
  console.log(`  ${chalk.green("False positives:")}  ${counts.fp}`);
  console.log(`  ${chalk.yellow("Needs review:")}     ${counts.needs_review}`);
  if ((options.stats?.skippedLowConfidence ?? 0) > 0) {
    console.log(`  ${chalk.dim("Skipped (low confidence):")} ${options.stats?.skippedLowConfidence}`);
  }
  if (hasVerificationData) {
    console.log("");
    if (hasVerificationStats) {
      console.log(`  ${chalk.red.bold("Exploitable:")}      ${verificationCounts.exploitable}`);
      console.log(`  ${chalk.green("Not exploitable:")}  ${verificationCounts.notExploitable}`);
    } else {
      console.log(`  ${chalk.yellow("Verification:")}    errors only`);
    }
  }
  if (hasPocHarnessData) {
    console.log("");
    console.log(`  ${chalk.cyan("PoC harnesses generated:")} ${pocHarnessCounts.generated}`);
    console.log(`  ${chalk.yellow("PoC harnesses skipped:")}   ${pocHarnessCounts.skipped}`);
    console.log(`  ${chalk.red("PoC harness errors:")}     ${options.stats?.pocHarnessErrors ?? 0}`);
    if (options.repoRoot) {
      const pocDir = path.join(options.repoRoot, ".kuzushi", "poc");
      console.log(`  ${chalk.dim("PoC output dir:")} ${pocDir}/`);
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
      const scanner = chalk.dim(`[${f.scanner}]`);
      const verificationBadge = f.verifyExploitable === 1
        ? chalk.bgRed.white.bold(" EXPLOITABLE ")
        : f.verifyExploitable === 0
          ? chalk.bgGreen.black(" NOT EXPLOITABLE ")
          : "";

      console.log(`  ${verdict} ${conf}  ${severity} ${scanner}${verificationBadge ? ` ${verificationBadge}` : ""}`);
      console.log(`    ${location}`);
      console.log(`    ${chalk.dim(f.ruleId)}`);
      console.log(`    ${f.rationale.slice(0, 120)}${f.rationale.length > 120 ? "..." : ""}`);
      if (f.verifyExploitable === 1 && f.verifyPocPayload) {
        const payload = f.verifyPocPayload.length > 80
          ? `${f.verifyPocPayload.slice(0, 77)}...`
          : f.verifyPocPayload;
        console.log(`    ${chalk.magenta("PoC:")} ${payload}`);
      }
      if (f.verifyAttackVector) {
        console.log(`    ${chalk.cyan("Vector:")} ${f.verifyAttackVector}`);
      }
      if (f.pocHarnessPath) {
        console.log(`    ${chalk.blue("PoC Harness:")} ${f.pocHarnessPath}`);
      } else if (f.pocHarnessSkipped === 1) {
        console.log(`    ${chalk.yellow("PoC Harness:")} skipped (${f.pocHarnessSkipReason ?? "no reason provided"})`);
      }
      if (f.pocHarnessParsed === 0 && f.pocHarnessParseError) {
        console.log(`    ${chalk.red("PoC Parse Error:")} ${f.pocHarnessParseError}`);
      }
      console.log("");
    }
  } else if (total > 0) {
    console.log("");
    console.log(chalk.green.bold("  All findings triaged as false positives. Code looks clean."));
  }

  console.log("");
  console.log(`  ${chalk.dim("Total triage cost:")} $${totalCostUsd.toFixed(4)}`);
  if (hasVerificationData) {
    console.log(`  ${chalk.dim("Total verification cost:")} $${verificationCostUsd.toFixed(4)}`);
  }
  if (hasPocHarnessData) {
    console.log(`  ${chalk.dim("Total PoC harness cost:")} $${pocHarnessCostUsd.toFixed(4)}`);
  }
  if (options.auditLog && options.repoRoot && options.runId) {
    const runDir = path.join(options.repoRoot, ".kuzushi", "runs", options.runId);
    console.log(`  ${chalk.dim("Audit log:")} ${runDir}/`);
  }

  console.log(chalk.bold("─".repeat(60)));
}

/** Print a short line when starting a scan. */
export function printScanStart(
  repoName: string,
  findingCount: number,
  total: number,
  scanners: ScannerId[],
): void {
  console.log("");
  console.log(chalk.bold(`  Kuzushi v0.1 — scanning ${repoName}`));
  console.log(`  Scanners: ${scanners.join(", ")}`);
  console.log(`  ${total} findings, ${findingCount} selected for AI triage`);
  console.log("");
}

/** Print when resuming with skipped findings. */
export function printResumeInfo(skipped: number, remaining: number): void {
  console.log(
    chalk.dim(`  Skipping ${skipped} already-triaged findings, ${remaining} remaining`),
  );
}

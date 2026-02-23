import chalk from "chalk";
import type { TriageResult, Verdict } from "./types.js";
import type Database from "better-sqlite3";
import { getVerdictCounts, getActionableFindings } from "./store.js";

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
): void {
  const pct = Math.round((index / total) * 100);
  const verdict = colorVerdict(result.verdict);
  const conf = chalk.dim(`(${(result.confidence * 100).toFixed(0)}%)`);
  console.log(
    `  [${index}/${total}] ${verdict} ${conf} ${chalk.dim(result.fingerprint.slice(0, 12))}...`,
  );
}

/** Print the final scan summary to terminal. */
export function printSummary(db: Database.Database, repo: string): void {
  const counts = getVerdictCounts(db, repo);
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

  if (actionable.length > 0) {
    console.log("");
    console.log(chalk.bold("  Actionable Findings:"));
    console.log("");

    for (const f of actionable) {
      const verdict = colorVerdict(f.verdict);
      const location = chalk.cyan(`${f.filePath}:${f.startLine}`);
      const conf = chalk.dim(`${(f.confidence * 100).toFixed(0)}%`);
      const severity = f.severity === "ERROR" ? chalk.red(f.severity) : chalk.yellow(f.severity);

      console.log(`  ${verdict} ${conf}  ${severity}`);
      console.log(`    ${location}`);
      console.log(`    ${chalk.dim(f.ruleId)}`);
      console.log(`    ${f.rationale.slice(0, 120)}${f.rationale.length > 120 ? "..." : ""}`);
      console.log("");
    }
  } else if (total > 0) {
    console.log("");
    console.log(chalk.green.bold("  All findings triaged as false positives. Code looks clean."));
  }

  console.log(chalk.bold("─".repeat(60)));
}

/** Print a short line when starting a scan. */
export function printScanStart(repoName: string, findingCount: number, total: number): void {
  console.log("");
  console.log(chalk.bold(`  Kuzushi v0.1 — scanning ${repoName}`));
  console.log(`  ${total} Semgrep findings, ${findingCount} selected for AI triage`);
  console.log("");
}

/** Print when resuming with skipped findings. */
export function printResumeInfo(skipped: number, remaining: number): void {
  console.log(
    chalk.dim(`  Skipping ${skipped} already-triaged findings, ${remaining} remaining`),
  );
}

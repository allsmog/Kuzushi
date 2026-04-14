/**
 * Plain-text fallback renderer for non-TTY output (CI, piped).
 *
 * Subscribes to UIStore changes and outputs formatted console.log text
 * with Unicode icons but no live-updating (static output only).
 */
import chalk from "chalk";
import { icons } from "./icons.js";
import {
  colorVerdict,
  formatCost,
  formatDuration,
  progressBar,
  miniBarChart,
  badge,
  boxHeader,
  boxFooter,
  boxDivider,
  treeLines,
} from "./format.js";
import type { UIStore, Phase, ResultLine, SummaryData } from "./state.js";

/**
 * Register a plain-text renderer that subscribes to store changes
 * and outputs to console.log.
 *
 * @returns Unsubscribe function
 */
export function registerPlainTextRenderer(store: UIStore): () => void {
  let lastPhase: Phase = "idle";
  let lastResultCount = 0;
  let bannerPrinted = false;
  let startBannerPrinted = false;

  const unsubscribe = store.subscribe(() => {
    const state = store.getState();

    // Print banner once
    if (state.bannerShown && !bannerPrinted) {
      bannerPrinted = true;
      // In plain text mode, the original banner.ts printBanner() is called separately
    }

    // Print start banner once
    if (state.startBannerShown && !startBannerPrinted) {
      startBannerPrinted = true;
      console.log("");
      console.log(chalk.bold(`  ${icons.complete} Kuzushi — scanning ${state.repoName}`));
      console.log(`  Scanners: ${state.tasks.join(", ")}`);
      console.log(`  ${state.totalFindings} findings, ${state.selectedForTriage} selected for AI triage`);
      console.log("");

      if (state.skippedAlreadyTriaged > 0) {
        console.log(chalk.dim(`  Skipping ${state.skippedAlreadyTriaged} already-triaged findings, ${state.selectedForTriage} remaining`));
      }
    }

    // Print stage transitions
    if (state.phase !== lastPhase) {
      if (state.phase === "triaging" && state.selectedForTriage > 0) {
        console.log(`  ${icons.lightning} Triaging ${state.selectedForTriage} findings via ${state.model}...\n`);
      } else if (state.phase === "verifying" && state.progress.total > 0) {
        console.log(`  ${icons.shield} Verifying ${state.progress.total} findings via ${state.model}...\n`);
      } else if (state.phase === "poc" && state.progress.total > 0) {
        console.log(`  ${icons.gear} Generating ${state.progress.total} PoC harnesses via ${state.model}...\n`);
      }
      lastPhase = state.phase;
    }

    // Print new results
    const newResults = state.results.slice(lastResultCount);
    for (const result of newResults) {
      printResultLine(result);
    }
    lastResultCount = state.results.length;

    // Print summary
    if (state.phase === "summary" && state.summary) {
      printPlainSummary(state.summary);
    }
  });

  return unsubscribe;
}

function printResultLine(result: ResultLine): void {
  const prefix = `  [${result.index}/${result.total}]`;
  const fingerprint = chalk.dim(`${result.fingerprint.slice(0, 12)}...`);
  const retry = result.attempts && result.attempts > 1 ? chalk.dim(` (retry #${result.attempts})`) : "";

  if (result.kind === "error") {
    const stage = result.errorStage?.toUpperCase() ?? "TRIAGE";
    console.log(`${prefix} ${chalk.red(`${icons.error} ${stage} ERROR`)}${retry} ${fingerprint}`);
    if (result.errorMessage) {
      console.log(`    ${result.errorMessage.slice(0, 160)}`);
    }
    return;
  }

  if (result.kind === "triage" && result.verdict) {
    const verdict = colorVerdict(result.verdict);
    const conf = chalk.dim(`(${((result.confidence ?? 0) * 100).toFixed(0)}%)`);
    const cost = result.costUsd && result.costUsd > 0 ? ` ${chalk.dim(formatCost(result.costUsd))}` : "";
    console.log(`${prefix} ${verdict} ${conf}${cost}${retry} ${fingerprint}`);
    return;
  }

  if (result.kind === "verify") {
    const statusIcon = result.exploitable ? chalk.red(icons.error) : chalk.green(icons.success);
    const statusLabel = result.exploitable ? "EXPLOITABLE" : "not exploitable";
    const cost = result.costUsd && result.costUsd > 0 ? ` ${chalk.dim(formatCost(result.costUsd))}` : "";
    console.log(`${prefix} ${statusIcon} ${statusLabel}${cost}${retry} ${fingerprint}`);
    return;
  }

  if (result.kind === "poc") {
    const statusIcon = result.skipped ? chalk.yellow(icons.pending) : chalk.cyan(icons.gear);
    const statusLabel = result.skipped ? "SKIPPED" : "GENERATED";
    const parsed = result.skipped ? "" : result.parsed ? " parsed" : " parse-error";
    const cost = result.costUsd && result.costUsd > 0 ? ` ${chalk.dim(formatCost(result.costUsd))}` : "";
    console.log(`${prefix} ${statusIcon} ${statusLabel}${parsed}${cost}${retry} ${fingerprint}`);
  }
}

function printPlainSummary(data: SummaryData): void {
  // Delegate to the existing console.log approach with enhanced formatting
  const { verdictCounts: counts } = data;
  const total = counts.tp + counts.fp + counts.needs_review;

  console.log("");
  console.log(boxHeader(`${icons.complete} Scan Results`, 60));
  console.log("");

  if (data.failedTasks.length > 0) {
    console.log(`  ${chalk.red("Scanners failed:")}  ${data.failedTasks.join(", ")} ${chalk.dim("(results may be incomplete)")}`);
    console.log("");
  }

  console.log(`  ${chalk.dim("Total triaged:")}    ${total}`);
  console.log(`  ${chalk.red.bold(`${icons.error} True positives:`)}   ${counts.tp}`);
  console.log(`  ${chalk.green(`${icons.success} False positives:`)}  ${counts.fp}`);
  console.log(`  ${chalk.yellow(`${icons.warning} Needs review:`)}     ${counts.needs_review}`);

  if (total > 0) {
    console.log("");
    for (const line of miniBarChart([
      { label: "tp", value: counts.tp, color: chalk.red },
      { label: "fp", value: counts.fp, color: chalk.green },
      { label: "needs_review", value: counts.needs_review, color: chalk.yellow },
    ])) {
      console.log(`  ${line}`);
    }
  }

  console.log("");
  console.log(`  ${chalk.dim("Triage cost:")} ${formatCost(data.triageCostUsd)}`);
  if (data.verificationCostUsd > 0) {
    console.log(`  ${chalk.dim("Verification cost:")} ${formatCost(data.verificationCostUsd)}`);
  }
  console.log(boxFooter(60));
}

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
  miniBarChart,
  boxHeader,
  boxFooter,
  terminalCardWidth,
} from "./format.js";
import type { UIStore, Phase, ResultLine, SummaryData, AgentActivityLine } from "./state.js";

/**
 * Register a plain-text renderer that subscribes to store changes
 * and outputs to console.log.
 *
 * @returns Unsubscribe function
 */
export function registerPlainTextRenderer(store: UIStore): () => void {
  let lastPhase: Phase = "idle";
  let lastResultCount = 0;
  let lastNoticeCount = 0;
  let bannerPrinted = false;
  let startBannerPrinted = false;
  const taskState = new Map<string, { status: string; findingCount: number; detail?: string }>();
  const scanActivityPrinted = new Map<string, number>();

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

    const scanStage = state.stages.find((stage) => stage.id === "scan");
    if (scanStage) {
      for (const task of scanStage.subTasks) {
        const previous = taskState.get(task.id);
        const current = {
          status: task.status,
          findingCount: task.findingCount ?? 0,
          detail: task.detail,
        };
        if (!previous || previous.status !== current.status || previous.findingCount !== current.findingCount || previous.detail !== current.detail) {
          printScanTaskLine(task.label, task.status, current.findingCount, task.detail, task.elapsedMs, task.lastError, task.retryCount);
          taskState.set(task.id, current);
        }

        // Print new scan activity lines (curated tool calls)
        const lines = task.activityLines ?? [];
        const prevCount = scanActivityPrinted.get(task.id) ?? 0;
        if (lines.length > prevCount) {
          for (const line of lines.slice(prevCount)) {
            printScanActivityLine(task.id, line);
          }
          scanActivityPrinted.set(task.id, lines.length);
        }
      }
    }

    // Print new results
    const newResults = state.results.slice(lastResultCount);
    for (const result of newResults) {
      printResultLine(result);
    }
    lastResultCount = state.results.length;

    const newNotices = state.notices.slice(lastNoticeCount);
    for (const notice of newNotices) {
      printNotice(notice.level, notice.message, notice.detail);
    }
    lastNoticeCount = state.notices.length;

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

function printScanTaskLine(
  taskId: string,
  status: string,
  findingCount: number,
  detail?: string,
  elapsedMs?: number,
  lastError?: string,
  retryCount?: number,
): void {
  const findings = findingCount > 0 ? ` ${chalk.dim(`(${findingCount} finding${findingCount === 1 ? "" : "s"})`)}` : "";
  const suffix = detail ? ` ${chalk.dim(detail)}` : "";
  const elapsed = elapsedMs != null ? ` ${chalk.dim(formatDuration(elapsedMs))}` : "";
  const retryTag = retryCount && retryCount > 0 ? chalk.yellow(` (retry #${retryCount})`) : "";

  if (status === "done") {
    console.log(`  ${chalk.dim(icons.complete)} ${taskId}${findings}${elapsed}${suffix}`);
    return;
  }
  if (status === "error") {
    const errorDetail = lastError ? ` ${chalk.red(lastError.slice(0, 80))}` : suffix;
    console.log(`  ${chalk.red(icons.error)} ${taskId}${errorDetail}${retryTag}  ${chalk.dim("continuing with remaining tasks")}`);
    return;
  }
  if (status === "active") {
    console.log(`  ${chalk.yellow(icons.active)} ${taskId}${findings}${suffix}${retryTag}`);
  }
}

function printScanActivityLine(taskId: string, line: AgentActivityLine): void {
  if (line.kind === "tool-start") {
    const detail = line.detail ?? line.toolName ?? "tool";
    console.log(`    ${icons.arrow} [${taskId}] ${detail}`);
  } else if (line.kind === "tool-complete" && line.detail) {
    console.log(`    ${chalk.green(icons.success)} [${taskId}] ${line.detail.slice(0, 120)}`);
  }
}

function printNotice(level: "info" | "warning" | "error" | "success", message: string, detail?: string): void {
  const icon = level === "success"
    ? chalk.green(icons.success)
    : level === "warning"
      ? chalk.yellow(icons.warning)
      : level === "error"
        ? chalk.red(icons.error)
        : chalk.blue(icons.info);
  const body = level === "error"
    ? chalk.red(message)
    : level === "warning"
      ? chalk.yellow(message)
      : message;
  console.log(`  ${icon} ${body}${detail ? ` ${chalk.dim(detail)}` : ""}`);
}

function printPlainSummary(data: SummaryData): void {
  // Delegate to the existing console.log approach with enhanced formatting
  const { verdictCounts: counts } = data;
  const total = counts.tp + counts.fp + counts.needs_review;
  const width = terminalCardWidth(96, 60);

  console.log("");
  console.log(boxHeader(`${icons.complete} Scan Results`, width));
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
  console.log(boxFooter(width));
}

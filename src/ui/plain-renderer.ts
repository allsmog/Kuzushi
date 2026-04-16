/**
 * Plain-text fallback renderer for non-TTY output (CI, piped).
 *
 * Subscribes to UIStore changes and outputs formatted console.log text
 * with Unicode icons but no live-updating (static output only).
 */
import chalk from "chalk";
import {
  colorVerdict,
  formatCost,
  formatDuration,
  miniBarChart,
  terminalCardWidth,
} from "./format.js";
import { icons } from "./icons.js";
import type { AgentActivityLine, Phase, ResultLine, SummaryData, UIStore } from "./state.js";

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

      if (state.skippedAlreadyTriaged > 0) {
      }
    }

    // Print stage transitions
    if (state.phase !== lastPhase) {
      if (state.phase === "triaging" && state.selectedForTriage > 0) {
      } else if (state.phase === "verifying" && state.progress.total > 0) {
      } else if (state.phase === "poc" && state.progress.total > 0) {
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
        if (
          !previous ||
          previous.status !== current.status ||
          previous.findingCount !== current.findingCount ||
          previous.detail !== current.detail
        ) {
          printScanTaskLine(
            task.label,
            task.status,
            current.findingCount,
            task.detail,
            task.elapsedMs,
            task.lastError,
            task.retryCount,
          );
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
  const _prefix = `  [${result.index}/${result.total}]`;
  const _fingerprint = chalk.dim(`${result.fingerprint.slice(0, 12)}...`);
  const _retry =
    result.attempts && result.attempts > 1 ? chalk.dim(` (retry #${result.attempts})`) : "";

  if (result.kind === "error") {
    const _stage = result.errorStage?.toUpperCase() ?? "TRIAGE";
    if (result.errorMessage) {
    }
    return;
  }

  if (result.kind === "triage" && result.verdict) {
    const _verdict = colorVerdict(result.verdict);
    const _conf = chalk.dim(`(${((result.confidence ?? 0) * 100).toFixed(0)}%)`);
    const _cost =
      result.costUsd && result.costUsd > 0 ? ` ${chalk.dim(formatCost(result.costUsd))}` : "";
    return;
  }

  if (result.kind === "verify") {
    const _statusIcon = result.exploitable ? chalk.red(icons.error) : chalk.green(icons.success);
    const _statusLabel = result.exploitable ? "EXPLOITABLE" : "not exploitable";
    const _cost =
      result.costUsd && result.costUsd > 0 ? ` ${chalk.dim(formatCost(result.costUsd))}` : "";
    return;
  }

  if (result.kind === "poc") {
    const _statusIcon = result.skipped ? chalk.yellow(icons.pending) : chalk.cyan(icons.gear);
    const _statusLabel = result.skipped ? "SKIPPED" : "GENERATED";
    const _parsed = result.skipped ? "" : result.parsed ? " parsed" : " parse-error";
    const _cost =
      result.costUsd && result.costUsd > 0 ? ` ${chalk.dim(formatCost(result.costUsd))}` : "";
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
  const _findings =
    findingCount > 0
      ? ` ${chalk.dim(`(${findingCount} finding${findingCount === 1 ? "" : "s"})`)}`
      : "";
  const suffix = detail ? ` ${chalk.dim(detail)}` : "";
  const _elapsed = elapsedMs != null ? ` ${chalk.dim(formatDuration(elapsedMs))}` : "";
  const _retryTag = retryCount && retryCount > 0 ? chalk.yellow(` (retry #${retryCount})`) : "";

  if (status === "done") {
    return;
  }
  if (status === "error") {
    const _errorDetail = lastError ? ` ${chalk.red(lastError.slice(0, 80))}` : suffix;
    return;
  }
  if (status === "active") {
  }
}

function printScanActivityLine(taskId: string, line: AgentActivityLine): void {
  if (line.kind === "tool-start") {
    const _detail = line.detail ?? line.toolName ?? "tool";
  } else if (line.kind === "tool-complete" && line.detail) {
  }
}

function printNotice(
  level: "info" | "warning" | "error" | "success",
  message: string,
  detail?: string,
): void {
  const _icon =
    level === "success"
      ? chalk.green(icons.success)
      : level === "warning"
        ? chalk.yellow(icons.warning)
        : level === "error"
          ? chalk.red(icons.error)
          : chalk.blue(icons.info);
  const _body =
    level === "error" ? chalk.red(message) : level === "warning" ? chalk.yellow(message) : message;
}

function printPlainSummary(data: SummaryData): void {
  // Delegate to the existing console.log approach with enhanced formatting
  const { verdictCounts: counts } = data;
  const total = counts.tp + counts.fp + counts.needs_review;
  const _width = terminalCardWidth(96, 60);

  if (data.failedTasks.length > 0) {
  }

  if (total > 0) {
    for (const _line of miniBarChart([
      { label: "tp", value: counts.tp, color: chalk.red },
      { label: "fp", value: counts.fp, color: chalk.green },
      { label: "needs_review", value: counts.needs_review, color: chalk.yellow },
    ])) {
    }
  }
  if (data.verificationCostUsd > 0) {
  }
}

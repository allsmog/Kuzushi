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
import type {
  AgentActivityLine,
  Phase,
  ResultLine,
  ShellPlan,
  ShellState,
  SummaryData,
  UIStore,
} from "./state.js";

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
  let summaryPrinted = false;
  let lastQualityGate: unknown;
  // Phase D.5: shell-view + pendingPlan + threatModel + diffSince diff
  // trackers so the non-TTY path prints *something* when those state
  // transitions fire. The TUI carries the layout; the plain renderer
  // just logs the transition + headline counts so piped output stays
  // readable.
  let lastShellView: string | null = null;
  let lastPlanSource: string | null = null;
  let lastThreatModelPath: string | null = null;
  let lastDiffSinceRef: string | null = null;
  const taskState = new Map<string, { status: string; findingCount: number; detail?: string }>();
  const completedStages = new Set<string>();
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
        console.log(
          chalk.dim(
            `  Skipping ${state.skippedAlreadyTriaged} already-triaged findings, ${state.selectedForTriage} remaining`,
          ),
        );
      }
    }

    // Print stage transitions
    if (state.phase !== lastPhase) {
      if (state.phase === "triaging" && state.selectedForTriage > 0) {
        console.log(chalk.bold(`  Triaging ${state.selectedForTriage} findings...`));
      } else if (state.phase === "verifying" && state.progress.total > 0) {
        console.log(chalk.bold(`  Verifying ${state.progress.total} findings...`));
      } else if (state.phase === "poc" && state.progress.total > 0) {
        console.log(
          chalk.bold(`  Generating PoC harnesses for ${state.progress.total} findings...`),
        );
      }
      lastPhase = state.phase;
    }

    // Print stage completions once
    for (const stage of state.stages) {
      if (stage.status === "done" && !completedStages.has(stage.id)) {
        completedStages.add(stage.id);
        const elapsed =
          stage.elapsedMs != null ? ` ${chalk.dim(formatDuration(stage.elapsedMs))}` : "";
        console.log(`  ${chalk.green(icons.success)} ${stage.label}${elapsed}`);
      }
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

    // Print summary once when it first becomes available
    if (state.phase === "summary" && state.summary && !summaryPrinted) {
      summaryPrinted = true;
      printPlainSummary(state.summary);
    }

    // Print quality gate result once
    if (state.qualityGate && state.qualityGate !== lastQualityGate) {
      lastQualityGate = state.qualityGate;
      printQualityGate(state.qualityGate);
    }

    // Phase D.5 — shell-view + pendingPlan + threatModel + diffSince
    // transitions. Each emits one terse line so piped output is still
    // useful; the full layouts live in the Ink components.
    const shell = state.shell;
    if (shell) {
      const viewKey = `${shell.shellView}:${shell.focusedModule ?? ""}:${shell.openFindingId ?? ""}`;
      if (viewKey !== lastShellView) {
        lastShellView = viewKey;
        printShellView(shell);
      }

      const planSource = shell.pendingPlan?.source ?? null;
      if (planSource !== lastPlanSource) {
        lastPlanSource = planSource;
        if (shell.pendingPlan) printPendingPlan(shell.pendingPlan);
        else console.log(chalk.dim("  [plan] discarded"));
      }

      const tmPath = shell.threatModelSource?.path ?? null;
      if (tmPath && tmPath !== lastThreatModelPath) {
        lastThreatModelPath = tmPath;
        const threats = shell.threatModel?.threats.length ?? 0;
        const elements = shell.threatModel?.dfd.elements.length ?? 0;
        console.log(
          chalk.dim(`  [threats] loaded ${tmPath} · ${elements} elements · ${threats} threats`),
        );
      }

      const diffRef = shell.diffSince?.ref ?? null;
      if (diffRef !== lastDiffSinceRef) {
        lastDiffSinceRef = diffRef;
        if (shell.diffSince) {
          const n = shell.diffSince.changedFiles.length;
          const suffix = shell.diffSince.error ? ` · error: ${shell.diffSince.error}` : "";
          console.log(chalk.dim(`  [since ${shell.diffSince.ref}] ${n} changed file(s)${suffix}`));
        }
      }
    }
  });

  return unsubscribe;
}

function printResultLine(result: ResultLine): void {
  const prefix = `  [${result.index}/${result.total}]`;
  const fingerprint = chalk.dim(`${result.fingerprint.slice(0, 12)}...`);
  const retry =
    result.attempts && result.attempts > 1 ? chalk.dim(` (retry #${result.attempts})`) : "";

  if (result.kind === "error") {
    const stage = result.errorStage?.toUpperCase() ?? "TRIAGE";
    const msg = result.errorMessage ? `: ${result.errorMessage.slice(0, 120)}` : "";
    console.log(`${prefix} ${chalk.red(`${stage} ERROR`)}${msg} ${fingerprint}${retry}`);
    return;
  }

  if (result.kind === "triage" && result.verdict) {
    const verdict = colorVerdict(result.verdict);
    const conf = chalk.dim(`(${((result.confidence ?? 0) * 100).toFixed(0)}%)`);
    const cost =
      result.costUsd && result.costUsd > 0 ? ` ${chalk.dim(formatCost(result.costUsd))}` : "";
    console.log(`${prefix} ${verdict} ${conf}${cost} ${fingerprint}${retry}`);
    return;
  }

  if (result.kind === "verify") {
    const statusIcon = result.exploitable ? chalk.red(icons.error) : chalk.green(icons.success);
    const statusLabel = result.exploitable
      ? chalk.red.bold("EXPLOITABLE")
      : chalk.green("not exploitable");
    const cost =
      result.costUsd && result.costUsd > 0 ? ` ${chalk.dim(formatCost(result.costUsd))}` : "";
    console.log(`${prefix} ${statusIcon} ${statusLabel}${cost} ${fingerprint}${retry}`);
    return;
  }

  if (result.kind === "poc") {
    const statusIcon = result.skipped ? chalk.yellow(icons.pending) : chalk.cyan(icons.gear);
    const statusLabel = result.skipped ? chalk.yellow("SKIPPED") : chalk.cyan("GENERATED");
    const parsed = result.skipped ? "" : result.parsed ? " parsed" : " parse-error";
    const cost =
      result.costUsd && result.costUsd > 0 ? ` ${chalk.dim(formatCost(result.costUsd))}` : "";
    console.log(`${prefix} ${statusIcon} ${statusLabel}${parsed}${cost} ${fingerprint}${retry}`);
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
  const findings =
    findingCount > 0
      ? ` ${chalk.dim(`(${findingCount} finding${findingCount === 1 ? "" : "s"})`)}`
      : "";
  const suffix = detail ? ` ${chalk.dim(detail)}` : "";
  const elapsed = elapsedMs != null ? ` ${chalk.dim(formatDuration(elapsedMs))}` : "";
  const retryTag = retryCount && retryCount > 0 ? chalk.yellow(` (retry #${retryCount})`) : "";

  if (status === "done") {
    console.log(`  ${chalk.green(icons.success)} ${taskId}${findings}${elapsed}${retryTag}`);
    return;
  }
  if (status === "error") {
    const errorDetail = lastError ? ` ${chalk.red(lastError.slice(0, 80))}` : suffix;
    console.log(`  ${chalk.red(icons.error)} ${taskId}${errorDetail}${elapsed}${retryTag}`);
    return;
  }
  // active / pending — do not spam console every tick; only emit on terminal statuses.
}

function printScanActivityLine(taskId: string, line: AgentActivityLine): void {
  if (line.kind === "tool-complete" && line.detail) {
    console.log(`    ${chalk.dim(`[${taskId}]`)} ${chalk.dim(line.detail)}`);
  } else if (line.kind === "finding-preview" && line.detail) {
    console.log(`    ${chalk.dim(`[${taskId}]`)} ${line.detail}`);
  } else if (line.kind === "reasoning" && line.detail) {
    console.log(`    ${chalk.dim(`[${taskId}]`)} ${chalk.italic(line.detail)}`);
  }
}

function printNotice(
  level: "info" | "warning" | "error" | "success",
  message: string,
  detail?: string,
): void {
  const icon =
    level === "success"
      ? chalk.green(icons.success)
      : level === "warning"
        ? chalk.yellow(icons.warning)
        : level === "error"
          ? chalk.red(icons.error)
          : chalk.blue(icons.info);
  const body =
    level === "error" ? chalk.red(message) : level === "warning" ? chalk.yellow(message) : message;
  const detailSuffix = detail ? ` ${chalk.dim(detail)}` : "";
  console.log(`  ${icon} ${body}${detailSuffix}`);
}

function printQualityGate(result: {
  passed: boolean;
  violations?: Array<{ rule: string; message: string }>;
}): void {
  console.log("");
  if (result.passed) {
    console.log(`  ${chalk.green.bold("Quality Gates: PASSED")}`);
    return;
  }
  console.log(`  ${chalk.red.bold("Quality Gates: FAILED")}`);
  for (const violation of result.violations ?? []) {
    console.log(`    ${chalk.red("x")} ${chalk.bold(violation.rule)}: ${violation.message}`);
  }
}

function printPlainSummary(data: SummaryData): void {
  const { verdictCounts: counts } = data;
  const total = counts.tp + counts.fp + counts.needs_review;
  const width = terminalCardWidth(96, 60);

  console.log("");
  console.log(chalk.bold("─".repeat(width)));
  console.log(chalk.bold("  Kuzushi Scan Results"));
  console.log(chalk.bold("─".repeat(width)));

  if (data.failedTasks.length > 0) {
    console.log(
      `  ${chalk.red("Scanners failed:")} ${data.failedTasks.join(", ")} ${chalk.dim("(results may be incomplete)")}`,
    );
  }

  console.log(`  ${chalk.dim("Total triaged:")}    ${total}`);
  console.log(`  ${chalk.red.bold("True positives:")}   ${counts.tp}`);
  console.log(`  ${chalk.green("False positives:")}  ${counts.fp}`);
  console.log(`  ${chalk.yellow("Needs review:")}     ${counts.needs_review}`);

  if (total > 0) {
    for (const line of miniBarChart([
      { label: "tp", value: counts.tp, color: chalk.red },
      { label: "fp", value: counts.fp, color: chalk.green },
      { label: "needs_review", value: counts.needs_review, color: chalk.yellow },
    ])) {
      console.log(`  ${line}`);
    }
  }

  if (data.exploitable > 0 || data.notExploitable > 0) {
    console.log(`  ${chalk.red.bold("Exploitable:")}     ${data.exploitable}`);
    console.log(`  ${chalk.green("Not exploitable:")} ${data.notExploitable}`);
  }

  console.log(`  ${chalk.dim("Triage cost:")}     ${formatCost(data.triageCostUsd)}`);
  if (data.verificationCostUsd > 0) {
    console.log(`  ${chalk.dim("Verification cost:")} ${formatCost(data.verificationCostUsd)}`);
  }
  if (data.pocHarnessCostUsd > 0) {
    console.log(`  ${chalk.dim("PoC harness cost:")} ${formatCost(data.pocHarnessCostUsd)}`);
  }
  console.log(chalk.bold("─".repeat(width)));
}

// ---------------------------------------------------------------------------
// Phase D.5 helpers — shell-view + planner + threats + diff-since
// ---------------------------------------------------------------------------

function printShellView(shell: ShellState): void {
  const mod = shell.focusedModule ? ` (${shell.focusedModule})` : "";
  switch (shell.shellView) {
    case "catalog": {
      const n = shell.moduleCatalog?.length ?? 0;
      console.log(chalk.dim(`  [shell] catalog · ${n} modules`));
      return;
    }
    case "module":
      console.log(chalk.dim(`  [shell] module home${mod}`));
      return;
    case "tune":
      console.log(chalk.dim(`  [shell] tune${mod}`));
      return;
    case "findings":
      console.log(chalk.dim(`  [shell] findings list${mod}`));
      return;
    case "finding":
      if (shell.openFindingId) {
        console.log(chalk.dim(`  [shell] finding ${shell.openFindingId}${mod}`));
      } else {
        console.log(chalk.dim(`  [shell] finding${mod}`));
      }
      return;
    case "threat-dfd":
    case "threat-stride":
    case "threat-stories":
    case "threat-scope":
    case "threat-summary": {
      const suffix = shell.shellView.replace(/^threat-/, "");
      const threats = shell.threatModel?.threats.length ?? 0;
      const elements = shell.threatModel?.dfd.elements.length ?? 0;
      console.log(chalk.dim(`  [threats] ${suffix} · ${elements} elements · ${threats} threats`));
      return;
    }
    case "diff-since": {
      const ref = shell.diffSince?.ref ?? "?";
      const n = shell.diffSince?.changedFiles.length ?? 0;
      console.log(chalk.dim(`  [since ${ref}] ${n} changed file(s)`));
      return;
    }
  }
}

function printPendingPlan(plan: ShellPlan): void {
  const changes = plan.changes.length;
  const unsupported = plan.unsupported.length;
  const parts = [`${changes} change${changes === 1 ? "" : "s"} proposed`];
  if (unsupported > 0) parts.push(`${unsupported} unsupported`);
  parts.push(`$${plan.planCostUsd.toFixed(4)} plan cost`);
  console.log(chalk.dim(`  [plan] ${plan.source} · ${parts.join(" · ")} · y/n to apply`));
  if (changes > 0) {
    for (const c of plan.changes.slice(0, 3)) {
      const current = c.current == null ? "(default)" : JSON.stringify(c.current);
      const proposed = JSON.stringify(c.proposed);
      console.log(chalk.dim(`    ${c.option}: ${current} → ${proposed}`));
    }
    if (changes > 3) console.log(chalk.dim(`    (+${changes - 3} more)`));
  }
}

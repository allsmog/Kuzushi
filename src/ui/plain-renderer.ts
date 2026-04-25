/**
 * Plain-text fallback renderer for non-TTY output (CI, piped, NO_COLOR,
 * KUZUSHI_PLAIN=1, screen readers).
 *
 * Subscribes to UIStore changes and emits line-oriented text. Every
 * `ShellView` has a render path; every overlay (`pendingPlan`,
 * `costCapHalted`, `throttle`) emits a one-line advisory so piped
 * output stays grep-able and self-descriptive.
 *
 * Accessibility:
 *   - No box-drawing, no ANSI art, no dim-color.
 *   - Severity labels go through `severityToken(sev, { NO_COLOR: "1" })`
 *     so they render as `■ CRIT | ▲ HIGH | ◆ MED  | ● LOW  | ○ INFO`
 *     (plain chars, no color).
 *   - Headings are structural (`# TITLE`) with labels before values
 *     (`severity: HIGH`) so screen readers narrate the document order.
 *   - Every "No X" path routes through `describeEmptyState()` so the
 *     copy stays in sync with the Ink `<EmptyState>` component.
 *
 * The renderer is pure / side-effect-free except for writing to stdout.
 * Tests inject `{ write: (line) => ... }` to capture output.
 */
import chalk from "chalk";
import { describeEmptyState, type EmptyStateContext, type EmptyStateKind } from "./error-format.js";
import {
  colorVerdict,
  formatCost,
  formatDuration,
  miniBarChart,
  terminalCardWidth,
} from "./format.js";
import { icons } from "./icons.js";
import { normalizeSeverity, severityToken } from "./severity.js";
import {
  formatShellHistoryEntryPlain,
  shellHistoryPlainKey,
  shellHistoryPlainSignature,
} from "./shell-log-events.js";
import type {
  ActionableFinding,
  AgentActivityLine,
  Phase,
  ResultLine,
  ShellPlan,
  ShellState,
  SummaryData,
  UIState,
  UIStore,
} from "./state.js";
import { formatStoryEventPlain, shouldPersistStoryEvent } from "./task-story.js";

export interface PlainRendererOptions {
  /**
   * Line sink — default is `console.log`. Tests pass a capture closure.
   * A single line may contain `\n`, in which case it's emitted as-is
   * (the sink is responsible for breaking it up if needed).
   */
  write?: (line: string) => void;
}

/**
 * Register a plain-text renderer that subscribes to store changes
 * and emits lines via the supplied `write` sink (defaults to `console.log`).
 *
 * @returns Unsubscribe function
 */
export function registerPlainTextRenderer(
  store: UIStore,
  options: PlainRendererOptions = {},
): () => void {
  const write = options.write ?? ((line: string) => console.log(line));
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
  let lastShellHistoryLength = 0;
  let printedShellHistory = new Map<string, string>();
  // Workstream 5 — overlay trackers. Each overlay emits once per edge
  // transition (false → true) to avoid duplicate prompts on every
  // subscriber tick while the overlay stays active.
  let costCapHaltPrinted = false;
  let lastThrottleKey: string | null = null;
  const taskState = new Map<string, { status: string; findingCount: number; detail?: string }>();
  const completedStages = new Set<string>();
  const scanActivityPrinted = new Map<string, number>();

  const emit = (line: string): void => write(line);

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
        emit(
          chalk.dim(
            `  Skipping ${state.skippedAlreadyTriaged} already-triaged findings, ${state.selectedForTriage} remaining`,
          ),
        );
      }
    }

    // Print stage transitions
    if (state.phase !== lastPhase) {
      if (state.phase === "triaging" && state.selectedForTriage > 0) {
        emit(chalk.bold(`  Triaging ${state.selectedForTriage} findings...`));
      } else if (state.phase === "verifying" && state.progress.total > 0) {
        emit(chalk.bold(`  Verifying ${state.progress.total} findings...`));
      } else if (state.phase === "poc" && state.progress.total > 0) {
        emit(chalk.bold(`  Generating PoC harnesses for ${state.progress.total} findings...`));
      }
      lastPhase = state.phase;
    }

    // Print stage completions once
    for (const stage of state.stages) {
      if (stage.status === "done" && !completedStages.has(stage.id)) {
        completedStages.add(stage.id);
        const elapsed =
          stage.elapsedMs != null ? ` ${chalk.dim(formatDuration(stage.elapsedMs))}` : "";
        emit(`  ${chalk.green(icons.success)} ${stage.label}${elapsed}`);
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
            emit,
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
            printScanActivityLine(emit, task.id, line);
          }
          scanActivityPrinted.set(task.id, lines.length);
        }
      }
    }

    // Print new results
    const newResults = state.results.slice(lastResultCount);
    for (const result of newResults) {
      printResultLine(emit, result);
    }
    lastResultCount = state.results.length;

    const newNotices = state.notices.slice(lastNoticeCount);
    for (const notice of newNotices) {
      printNotice(emit, notice.level, notice.message, notice.detail);
    }
    lastNoticeCount = state.notices.length;

    // Print summary once when it first becomes available
    if (state.phase === "summary" && state.summary && !summaryPrinted) {
      summaryPrinted = true;
      printPlainSummary(emit, state.summary);
    }

    // Print quality gate result once
    if (state.qualityGate && state.qualityGate !== lastQualityGate) {
      lastQualityGate = state.qualityGate;
      printQualityGate(emit, state.qualityGate);
    }

    // Workstream 5 — rate-limit banner. One line per change of concurrency
    // or reason so tail -f stays readable. Clears (`[throttled] cleared`)
    // when `throttle` goes back to null.
    const throttleKey = state.throttle
      ? `${state.throttle.concurrency}:${state.throttle.reason}`
      : null;
    if (throttleKey !== lastThrottleKey) {
      lastThrottleKey = throttleKey;
      if (state.throttle) {
        const reason = state.throttle.reason ? ` · ${state.throttle.reason}` : "";
        emit(`[!] [throttled] concurrency=${state.throttle.concurrency}${reason}`);
      } else {
        emit(`[throttled] cleared`);
      }
    }

    // Workstream 5 — cost-cap halt overlay. Print the budget card + the
    // `continue (c) or abort (a)?` prompt once per halt. Reset on clear so
    // a second halt later in the run prints again.
    if (state.costCapHalted && !costCapHaltPrinted) {
      costCapHaltPrinted = true;
      printCostCapHalt(emit, state);
    } else if (!state.costCapHalted && costCapHaltPrinted) {
      costCapHaltPrinted = false;
    }

    // Phase D.5 — shell-view + pendingPlan + threatModel + diffSince
    // transitions. Each emits one terse line so piped output is still
    // useful; the full layouts live in the Ink components.
    const shell = state.shell;
    if (shell) {
      if (shell.history.length < lastShellHistoryLength) {
        printedShellHistory = new Map();
      }
      lastShellHistoryLength = shell.history.length;
      shell.history.forEach((entry, index) => {
        const key = shellHistoryPlainKey(entry, index);
        const signature = shellHistoryPlainSignature(entry);
        if (printedShellHistory.get(key) === signature) return;
        printedShellHistory.set(key, signature);
        for (const line of formatShellHistoryEntryPlain(entry)) emit(line);
      });

      const viewKey = `${shell.shellView}:${shell.focusedModule ?? ""}:${shell.openFindingId ?? ""}`;
      if (viewKey !== lastShellView) {
        lastShellView = viewKey;
        printShellView(emit, shell, state);
      }

      const planSource = shell.pendingPlan?.source ?? null;
      if (planSource !== lastPlanSource) {
        lastPlanSource = planSource;
        if (shell.pendingPlan) printPendingPlan(emit, shell.pendingPlan);
        else emit(chalk.dim("  [plan] discarded"));
      }

      const tmPath = shell.threatModelSource?.path ?? null;
      if (tmPath && tmPath !== lastThreatModelPath) {
        lastThreatModelPath = tmPath;
        const threats = shell.threatModel?.threats.length ?? 0;
        const elements = shell.threatModel?.dfd.elements.length ?? 0;
        emit(chalk.dim(`  [threats] loaded ${tmPath} · ${elements} elements · ${threats} threats`));
      }

      const diffRef = shell.diffSince?.ref ?? null;
      if (diffRef !== lastDiffSinceRef) {
        lastDiffSinceRef = diffRef;
        if (shell.diffSince) {
          const n = shell.diffSince.changedFiles.length;
          const suffix = shell.diffSince.error ? ` · error: ${shell.diffSince.error}` : "";
          emit(chalk.dim(`  [since ${shell.diffSince.ref}] ${n} changed file(s)${suffix}`));
        }
      }
    }
  });

  return unsubscribe;
}

type Emit = (line: string) => void;

function printResultLine(emit: Emit, result: ResultLine): void {
  const prefix = `  [${result.index}/${result.total}]`;
  const fingerprint = chalk.dim(`${result.fingerprint.slice(0, 12)}...`);
  const retry =
    result.attempts && result.attempts > 1 ? chalk.dim(` (retry #${result.attempts})`) : "";

  if (result.kind === "error") {
    const stage = result.errorStage?.toUpperCase() ?? "TRIAGE";
    const msg = result.errorMessage ? `: ${result.errorMessage.slice(0, 120)}` : "";
    emit(`${prefix} ${chalk.red(`${stage} ERROR`)}${msg} ${fingerprint}${retry}`);
    return;
  }

  if (result.kind === "triage" && result.verdict) {
    const verdict = colorVerdict(result.verdict);
    const conf = chalk.dim(`(${((result.confidence ?? 0) * 100).toFixed(0)}%)`);
    const cost =
      result.costUsd && result.costUsd > 0 ? ` ${chalk.dim(formatCost(result.costUsd))}` : "";
    emit(`${prefix} ${verdict} ${conf}${cost} ${fingerprint}${retry}`);
    return;
  }

  if (result.kind === "verify") {
    const statusIcon = result.exploitable ? chalk.red(icons.error) : chalk.green(icons.success);
    const statusLabel = result.exploitable
      ? chalk.red.bold("EXPLOITABLE")
      : chalk.green("not exploitable");
    const cost =
      result.costUsd && result.costUsd > 0 ? ` ${chalk.dim(formatCost(result.costUsd))}` : "";
    emit(`${prefix} ${statusIcon} ${statusLabel}${cost} ${fingerprint}${retry}`);
    return;
  }

  if (result.kind === "poc") {
    const statusIcon = result.skipped ? chalk.yellow(icons.pending) : chalk.cyan(icons.gear);
    const statusLabel = result.skipped ? chalk.yellow("SKIPPED") : chalk.cyan("GENERATED");
    const parsed = result.skipped ? "" : result.parsed ? " parsed" : " parse-error";
    const cost =
      result.costUsd && result.costUsd > 0 ? ` ${chalk.dim(formatCost(result.costUsd))}` : "";
    emit(`${prefix} ${statusIcon} ${statusLabel}${parsed}${cost} ${fingerprint}${retry}`);
  }
}

function printScanTaskLine(
  emit: Emit,
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
    emit(`  ${chalk.green(icons.success)} ${taskId}${findings}${elapsed}${retryTag}`);
    return;
  }
  if (status === "error") {
    const errorDetail = lastError ? ` ${chalk.red(lastError.slice(0, 80))}` : suffix;
    emit(`  ${chalk.red(icons.error)} ${taskId}${errorDetail}${elapsed}${retryTag}`);
    return;
  }
  // active / pending — do not spam console every tick; only emit on terminal statuses.
}

function printScanActivityLine(emit: Emit, taskId: string, line: AgentActivityLine): void {
  if (line.kind === "tool-complete" && line.detail) {
    emit(`    ${chalk.dim(`[${taskId}]`)} ${chalk.dim(line.detail)}`);
  } else if (line.kind === "finding-preview" && line.detail) {
    emit(`    ${chalk.dim(`[${taskId}]`)} ${line.detail}`);
  } else if (line.kind === "reasoning" && line.detail) {
    emit(`    ${chalk.dim(`[${taskId}]`)} ${chalk.italic(line.detail)}`);
  }
}

function printNotice(
  emit: Emit,
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
  emit(`  ${icon} ${body}${detailSuffix}`);
}

function printQualityGate(
  emit: Emit,
  result: {
    passed: boolean;
    violations?: Array<{ rule: string; message: string }>;
  },
): void {
  emit("");
  if (result.passed) {
    emit(`  ${chalk.green.bold("Quality Gates: PASSED")}`);
    return;
  }
  emit(`  ${chalk.red.bold("Quality Gates: FAILED")}`);
  for (const violation of result.violations ?? []) {
    emit(`    ${chalk.red("x")} ${chalk.bold(violation.rule)}: ${violation.message}`);
  }
}

function printPlainSummary(emit: Emit, data: SummaryData): void {
  const { verdictCounts: counts } = data;
  const total = counts.tp + counts.fp + counts.needs_review;
  const width = terminalCardWidth(96, 60);

  emit("");
  emit(chalk.bold("─".repeat(width)));
  emit(chalk.bold("  Kuzushi Scan Results"));
  emit(chalk.bold("─".repeat(width)));

  if (data.failedTasks.length > 0) {
    emit(
      `  ${chalk.red("Scanners failed:")} ${data.failedTasks.join(", ")} ${chalk.dim("(results may be incomplete)")}`,
    );
  }

  emit(`  ${chalk.dim("Total triaged:")}    ${total}`);
  emit(`  ${chalk.red.bold("True positives:")}   ${counts.tp}`);
  emit(`  ${chalk.green("False positives:")}  ${counts.fp}`);
  emit(`  ${chalk.yellow("Needs review:")}     ${counts.needs_review}`);

  if (total > 0) {
    for (const line of miniBarChart([
      { label: "tp", value: counts.tp, color: chalk.red },
      { label: "fp", value: counts.fp, color: chalk.green },
      { label: "needs_review", value: counts.needs_review, color: chalk.yellow },
    ])) {
      emit(`  ${line}`);
    }
  }

  if (data.exploitable > 0 || data.notExploitable > 0) {
    emit(`  ${chalk.red.bold("Exploitable:")}     ${data.exploitable}`);
    emit(`  ${chalk.green("Not exploitable:")} ${data.notExploitable}`);
  }

  emit(`  ${chalk.dim("Triage cost:")}     ${formatCost(data.triageCostUsd)}`);
  if (data.verificationCostUsd > 0) {
    emit(`  ${chalk.dim("Verification cost:")} ${formatCost(data.verificationCostUsd)}`);
  }
  if (data.pocHarnessCostUsd > 0) {
    emit(`  ${chalk.dim("PoC harness cost:")} ${formatCost(data.pocHarnessCostUsd)}`);
  }
  emit(chalk.bold("─".repeat(width)));
}

// ---------------------------------------------------------------------------
// Phase D.5 + Workstream 5 helpers — shell-view + planner + threats +
// diff-since + overlays. Each helper takes the `emit` sink as its first
// argument so tests can inject a capture closure without stubbing console.
// ---------------------------------------------------------------------------

/**
 * Dispatch the per-view plain render. Headings are structural (`# TITLE`)
 * and the body uses labels-before-values so screen readers narrate the
 * view in reading order. Every empty-data path routes through
 * `describeEmptyState()`.
 */
function printShellView(emit: Emit, shell: ShellState, state: UIState): void {
  switch (shell.shellView) {
    case "catalog":
      printCatalogView(emit, shell);
      return;
    case "module":
      printModuleView(emit, shell);
      return;
    case "tune":
      printTuneView(emit, shell);
      return;
    case "findings":
      printFindingsView(emit, shell, state);
      return;
    case "finding":
      printFindingView(emit, shell, state);
      return;
    case "threats":
      printThreatView(emit, shell, state.agentActivity);
      return;
    case "context-build":
      printContextBuildView(emit, shell);
      return;
    case "task-story":
      printTaskStoryView(emit, shell);
      return;
    case "module-run":
      printModuleRunView(emit, shell);
      return;
    case "actor-detail":
      printActorDetailView(emit, shell, state);
      return;
    case "prompts-editor":
      printPromptsEditorView(emit, shell);
      return;
  }
}

function printModuleRunView(emit: Emit, shell: ShellState): void {
  const run = shell.moduleRun;
  if (!run) {
    emit(`  [run] ${shell.focusedModule ?? "module"} · idle`);
    emit("# RUN");
    emit("  (no active run)");
    return;
  }
  const elapsed = formatDuration(Math.max(0, Date.now() - run.startedAtMs));
  const stepsDone = run.steps.filter((s) => s.status === "done").length;
  const stepsTotal = run.steps.length;
  emit(
    `  [run] ${run.moduleId}:${run.toolName ?? "run"} · ${elapsed} · ${stepsDone}/${stepsTotal}`,
  );
  emit(`# RUN ${run.moduleId}`);
  emit(`  status: ${run.status}`);
  for (const step of run.steps) {
    const glyph =
      step.status === "done"
        ? "✓"
        : step.status === "running"
          ? "→"
          : step.status === "error"
            ? "✗"
            : "○";
    emit(`  ${glyph} ${step.title}`);
  }
}

function printActorDetailView(emit: Emit, shell: ShellState, state: UIState): void {
  const fp = shell.focusedActor ?? "";
  const lines = fp ? (state.agentActivity?.get(fp) ?? []) : [];
  emit(`  [actor] ${fp || "(none)"} · ${lines.length} events`);
  emit("# ACTOR TRANSCRIPT");
  if (!fp) {
    emit("  (no actor focused)");
    return;
  }
  for (const line of lines) {
    const head =
      line.kind === "tool-start" || line.kind === "tool-progress"
        ? "● "
        : line.kind === "tool-complete"
          ? "⎿ "
          : line.kind === "reasoning"
            ? "✻ "
            : line.kind === "finding-preview"
              ? "★ "
              : "• ";
    const detail = line.detail ?? line.toolName ?? line.kind;
    emit(`  ${head}${detail}`);
  }
}

function printPromptsEditorView(emit: Emit, shell: ShellState): void {
  const moduleId = shell.focusedModule ?? "module";
  const audit = shell.promptsEditor?.audit ?? [];
  const localEdits = audit.filter((r) => r.effective.source === "file").length;
  emit(`  [prompts] ${moduleId} · ${localEdits} override${localEdits === 1 ? "" : "s"}`);
  emit("# PROMPTS");
  if (audit.length === 0) {
    emit("  (no prompt keys)");
    return;
  }
  for (const row of audit) {
    emit(`  ${row.verb}  source=${row.effective.source}  ${row.effective.filePath ?? ""}`);
  }
}

function printTaskStoryView(emit: Emit, shell: ShellState): void {
  const story = shell.taskStory;
  const jobs = story?.backgroundJobs ?? [];
  const activeJobs = jobs.filter((job) => job.status === "running");
  emit(
    chalk.dim(
      `  [shell] task story · ${story?.events.length ?? 0} events${
        activeJobs.length > 0 ? ` · ${activeJobs.length} background` : ""
      }`,
    ),
  );
  emit("# TASK STORY");
  if (!story || story.events.length === 0) {
    emit("  (no task story yet)");
    return;
  }
  if (jobs.length > 0) {
    emit("## Background");
    for (const job of jobs.slice(0, 6)) {
      emit(`  job ${job.id}: ${job.status} · ${job.label}`);
    }
  }
  emit("## Live");
  for (const event of story.events) {
    if (!shouldPersistStoryEvent(event)) continue;
    emit(`  ${formatStoryEventPlain(event)}`);
  }
}

function printContextBuildView(emit: Emit, shell: ShellState): void {
  const cb = shell.contextBuild;
  if (!cb) {
    emit("# CONTEXT BUILD");
    emit("  (no build in progress — run /context build)");
    return;
  }
  const phaseOrder: ReadonlyArray<"manifests" | "walk" | "path-signals" | "grep" | "assemble"> = [
    "manifests",
    "walk",
    "path-signals",
    "grep",
    "assemble",
  ];
  const runningIdx = phaseOrder.findIndex((p) => cb.phases[p].status === "running");
  const activePhase =
    runningIdx >= 0
      ? phaseOrder[runningIdx]
      : phaseOrder.find((p) => cb.phases[p].status === "pending");
  const progressIdx = runningIdx >= 0 ? runningIdx + 1 : phaseOrder.length;
  emit(chalk.dim(`  [shell] context:build · ${cb.status}`));
  emit(`# CONTEXT BUILD · run ${cb.runId}`);
  emit(`  status: ${cb.status} (phase ${progressIdx}/${phaseOrder.length})`);
  if (activePhase) emit(`  active: ${activePhase}`);
  if (cb.walk) {
    emit(`  walk: ${cb.walk.entries} entries · ${cb.walk.sourceFiles} source files`);
  }
  if (cb.grep) {
    emit(`  grep: ${cb.grep.filesDone}/${cb.grep.filesTotal} files · ${cb.grep.workers} workers`);
  }
  if (cb.scanContextPath) emit(`  wrote: ${cb.scanContextPath}`);
  if (cb.errorMessage) emit(`  error: ${cb.errorMessage}`);
}

function printCatalogView(emit: Emit, shell: ShellState): void {
  const cards = shell.moduleCatalog ?? [];
  const count = cards.length;
  emit(chalk.dim(`  [shell] catalog · ${count} modules`));
  emit("# CATALOG");
  if (count === 0) {
    printEmpty(emit, "module-no-tools", { moduleId: "(no modules loaded)" });
    return;
  }
  // Group by category so the structural order matches the Ink layout.
  const groups = new Map<string, Array<{ id: string; desc: string; lastRun: string }>>();
  for (const card of cards) {
    const key = card.external ? "external" : String(card.category ?? "other");
    const list = groups.get(key) ?? [];
    list.push({
      id: card.id,
      desc: card.description ?? "",
      lastRun: card.lastRunSummary ?? "never run",
    });
    groups.set(key, list);
  }
  const order = ["offense", "intel", "governance", "defense", "other", "external"];
  for (const key of order) {
    const list = groups.get(key);
    if (!list || list.length === 0) continue;
    emit(`## ${key.toUpperCase()}`);
    for (const row of list) {
      emit(`- ${row.id} — ${clipLine(row.desc, 60)} (${row.lastRun})`);
    }
  }
  emit("hint: /use <id> to focus · /findings to list · /help for more");
}

function printModuleView(emit: Emit, shell: ShellState): void {
  const mod = shell.focusedModule ? ` (${shell.focusedModule})` : "";
  emit(chalk.dim(`  [shell] module home${mod}`));
  if (!shell.focusedModule) {
    emit("# MODULE");
    printEmpty(emit, "module-none-focused");
    return;
  }
  const card = (shell.moduleCatalog ?? []).find((c) => c.id === shell.focusedModule);
  emit(`# MODULE  ${shell.focusedModule}`);
  if (card?.description) emit(`description: ${card.description}`);
  const tools = card?.toolSummaries ?? [];
  if (tools.length === 0) {
    printEmpty(emit, "module-no-tools", { moduleId: shell.focusedModule });
    return;
  }
  emit("## tools");
  for (const t of tools) {
    const headless = t.headless ? " [headless]" : "";
    emit(`- ${t.verb}${headless}: ${t.description}`);
  }
  emit("hint: run <verb> to invoke · /tune to adjust · /back to return");
}

function printTuneView(emit: Emit, shell: ShellState): void {
  const mod = shell.focusedModule ? ` (${shell.focusedModule})` : "";
  emit(chalk.dim(`  [shell] tune${mod}`));
  emit(`# TUNE  ${shell.focusedModule ?? "(no module)"}`);
  const snap = shell.tuneSnapshot;
  if (!snap) {
    emit("preset: (default)");
    emit("hint: /config to open the expert editor");
    return;
  }
  emit(`preset: ${snap.preset ?? "standard"}`);
  emit(`tasks: ${(snap.tasks ?? []).join(", ") || "(none)"}`);
  emit(`verify: ${snap.verify ? "on" : "off"}`);
  emit(`autoPatch: ${snap.autoPatch ? "on" : "off"}`);
  emit(`triageConcurrency: ${snap.triageConcurrency}`);
  emit(`model: ${snap.model}`);
  if (snap.houseRules) {
    emit("## house rules");
    // Emit as a single multi-line block; screen readers follow line breaks.
    for (const line of snap.houseRules.split("\n").slice(0, 20)) emit(line);
    if (snap.houseRulesPath) emit(chalk.dim(`(loaded from ${snap.houseRulesPath})`));
  }
  emit("hint: /config to open the expert editor · /back to return");
}

function printFindingsView(emit: Emit, shell: ShellState, state: UIState): void {
  const mod = shell.focusedModule ? ` (${shell.focusedModule})` : "";
  emit(chalk.dim(`  [shell] findings list${mod}`));
  emit("# FINDINGS");

  const summary = state.summary;
  const findings: ReadonlyArray<ActionableFinding> = summary?.actionableFindings ?? [];
  if (findings.length === 0) {
    const kind: EmptyStateKind =
      state.phase === "summary" || state.phase === "done"
        ? "findings-zero-after-scan"
        : "findings-never-scanned";
    printEmpty(emit, kind);
    return;
  }

  // Sort by severity rank (critical first) so the plain listing matches
  // the Ink UnifiedFindings ordering.
  const sorted = [...findings].sort((a, b) => severityPlainRank(a) - severityPlainRank(b));
  const counts = tallyFindings(sorted);
  emit(
    `counts: ${counts.crit} critical · ${counts.high} high · ${counts.med} medium · ${counts.low} low · ${findings.length} total`,
  );
  // List up to 50 rows. On larger lists we append a truncation note so
  // piped output stays bounded; operators who want the full dump pipe
  // through the CI stream or an export.
  const MAX_ROWS = 50;
  const shown = sorted.slice(0, MAX_ROWS);
  for (let i = 0; i < shown.length; i += 1) {
    const f = shown[i];
    const sev = normalizeSeverity(f.displaySeverity ?? f.severity);
    const token = severityToken(sev, { NO_COLOR: "1" });
    const alias = `F-${String(i + 1).padStart(4, "0")}`;
    const title = f.title ?? f.ruleId ?? "(untitled)";
    emit(`- ${alias}  ${token}  ${clipLine(title, 60)}  [${f.taskId ?? "sast"}]`);
    emit(`          ${f.filePath}:${f.startLine}`);
  }
  if (sorted.length > MAX_ROWS) {
    emit(`...and ${sorted.length - MAX_ROWS} more (use /open F-NNNN or export)`);
  }
  emit("hint: /open F-NNNN to drill in · c clear filter · /back to return");
}

function printFindingView(emit: Emit, shell: ShellState, state: UIState): void {
  const mod = shell.focusedModule ? ` (${shell.focusedModule})` : "";
  const id = shell.openFindingId ?? "";
  emit(chalk.dim(`  [shell] finding ${id || "(none)"}${mod}`));
  emit(`# FINDING  ${id || "(none)"}`);

  const summary = state.summary;
  const findings = summary?.actionableFindings ?? [];
  // Resolve alias F-NNNN by severity-sorted index, else by fingerprint prefix.
  const match = resolveFindingByAlias(id, findings);
  if (!match) {
    printEmpty(emit, "findings-filter-empty", { filterCount: 0 });
    emit(`no finding matches "${id}" — try /findings to list, /open F-NNNN to drill in`);
    return;
  }
  const sev = normalizeSeverity(match.displaySeverity ?? match.severity);
  emit(`severity: ${severityToken(sev, { NO_COLOR: "1" })}`);
  emit(`title: ${match.title ?? match.ruleId ?? "(untitled)"}`);
  emit(`where: ${match.filePath}:${match.startLine}`);
  emit(`found by: ${match.taskId ?? "sast"}${match.ruleId ? ` · ${match.ruleId}` : ""}`);
  emit(`fingerprint: ${match.fingerprint.slice(0, 16)}`);
  emit(`verdict: ${(match.verdict ?? "—").toUpperCase()}`);
  if (match.rationale) {
    emit("rationale:");
    for (const line of match.rationale.split("\n").slice(0, 10)) emit(`  ${line}`);
  }
  if (match.verifyExploitable === 1) emit("verification: exploit harness passed");
  if (match.verifyPocPayload) {
    emit(`PoC: ${clipLine(match.verifyPocPayload, 120)}`);
  }
  if (match.attackPath?.chain?.length) {
    emit(`taint: ${match.attackPath.chain.join(" -> ")}`);
  }
  emit("hint: q back · /back returns to findings · /trace <runId> shows run evidence");
}

function printThreatView(
  emit: Emit,
  shell: ShellState,
  agentActivity: Map<string, AgentActivityLine[]>,
): void {
  const suffix = shell.threatTab ?? "summary";
  const tm = shell.threatModel;
  const threats = tm?.threats.length ?? 0;
  const elements = tm?.dfd.elements.length ?? 0;
  emit(chalk.dim(`  [threats] ${suffix} · ${elements} elements · ${threats} threats`));
  emit(`# THREATS  ${suffix.toUpperCase()}`);
  if (!tm) {
    printEmpty(emit, "threat-model-missing", { threatView: suffix });
    return;
  }
  switch (suffix) {
    case "dfd": {
      emit(`elements: ${elements}`);
      emit(`trust boundaries: ${tm.dfd.trustBoundaries?.length ?? 0}`);
      const zones = new Map<string, number>();
      for (const el of tm.dfd.elements ?? []) {
        const key = el.trustZone || "(unzoned)";
        zones.set(key, (zones.get(key) ?? 0) + 1);
      }
      if (zones.size > 0) {
        emit("## trust zones");
        for (const [zone, n] of zones) emit(`- ${zone}: ${n} element(s)`);
      }
      break;
    }
    case "stride": {
      emit(`total threats: ${threats}`);
      const by = tm.summary?.byCategory ?? {};
      emit("## by category");
      for (const cat of Object.keys(by)) emit(`- ${cat}: ${by[cat as keyof typeof by]}`);
      break;
    }
    case "stories": {
      const stories = tm.narrative?.attackerStories ?? [];
      emit(`total stories: ${stories.length}`);
      for (const story of stories.slice(0, 10)) {
        const linked = story.threatIds?.length ?? 0;
        emit(`- ${story.title} (${linked} linked threat${linked === 1 ? "" : "s"})`);
      }
      if (stories.length > 10) emit(`...and ${stories.length - 10} more`);
      break;
    }
    case "scope": {
      const buckets = tm.narrative?.criticalityBuckets;
      if (buckets) {
        emit("## criticality calibration");
        for (const tier of ["critical", "high", "medium", "low"] as const) {
          const items = buckets[tier] ?? [];
          emit(`- ${tier}: ${items.length} example(s)`);
          for (const item of items.slice(0, 5)) emit(`  · ${clipLine(item, 120)}`);
          if (items.length > 5) emit(`  · (+${items.length - 5} more)`);
        }
      } else {
        emit("## criticality calibration");
        emit("- (no narrative criticality buckets)");
      }

      const outOfScope = tm.narrative?.outOfScope ?? [];
      emit(`out-of-scope items: ${outOfScope.length}`);
      for (const item of outOfScope.slice(0, 8)) emit(`- ${clipLine(item, 120)}`);
      if (outOfScope.length > 8) emit(`...and ${outOfScope.length - 8} more`);

      const annotationCount = Object.keys(tm.userAnnotations ?? {}).length;
      const confirmedCount = tm.confirmedMitigations?.length ?? 0;
      const dismissedCount = tm.dismissedThreats?.length ?? 0;
      const editTotal = annotationCount + confirmedCount + dismissedCount;
      emit(`operator edits: ${editTotal} total`);
      emit(`- annotations: ${annotationCount}`);
      emit(`- confirmed mitigations: ${confirmedCount}`);
      emit(`- dismissed threats: ${dismissedCount}`);
      break;
    }
    case "summary": {
      emit(`total: ${tm.summary?.total ?? threats}`);
      if (tm.summary?.byCategory) {
        emit("## by category");
        for (const [k, v] of Object.entries(tm.summary.byCategory)) {
          emit(`- ${k}: ${v}`);
        }
      }
      break;
    }
  }
  const actionLines = collectRecentAgentActions(agentActivity, 6);
  if (actionLines.length > 0) {
    emit("## agent actions");
    for (const line of actionLines) emit(`- ${line}`);
  }
  emit("hint: 1..5 to cycle threat views · /threats edit to author · /back to return");
}

function collectRecentAgentActions(
  activity: Map<string, AgentActivityLine[]>,
  maxLines: number,
): string[] {
  const flattened: AgentActivityLine[] = [];
  for (const lines of activity.values()) flattened.push(...lines);
  const ordered = flattened.sort((a, b) => b.index - a.index);
  const out: string[] = [];
  for (const line of ordered) {
    const label = line.toolName ?? line.kind;
    const detail = line.detail?.trim();
    out.push(detail ? `${label}: ${clipLine(detail, 100)}` : label);
    if (out.length >= maxLines) break;
  }
  return out;
}

function printDiffSinceView(emit: Emit, shell: ShellState): void {
  const ref = shell.diffSince?.ref ?? "?";
  const n = shell.diffSince?.changedFiles.length ?? 0;
  emit(chalk.dim(`  [since ${ref}] ${n} changed file(s)`));
  emit(`# DIFF SINCE  ${ref}`);
  if (!shell.diffSince) {
    printEmpty(emit, "diff-since-idle");
    return;
  }
  if (shell.diffSince.error) emit(`error: ${shell.diffSince.error}`);
  emit(`changed files: ${n}`);
  for (const p of shell.diffSince.changedFiles.slice(0, 40)) emit(`- ${p}`);
  if (n > 40) emit(`...and ${n - 40} more`);
  emit("hint: /findings to list scoped findings · /back to return");
}

function printEmpty(emit: Emit, kind: EmptyStateKind, ctx?: EmptyStateContext): void {
  const copy = describeEmptyState(kind, ctx);
  emit(copy.title);
  emit(copy.reason);
  emit(copy.action);
}

function printPendingPlan(emit: Emit, plan: ShellPlan): void {
  const changes = plan.changes.length;
  const unsupported = plan.unsupported.length;
  const parts = [`${changes} change${changes === 1 ? "" : "s"} proposed`];
  if (unsupported > 0) parts.push(`${unsupported} unsupported`);
  parts.push(`$${plan.planCostUsd.toFixed(4)} plan cost`);
  emit(chalk.dim(`  [plan] ${plan.source} · ${parts.join(" · ")} · y/n to apply`));
  if (changes > 0) {
    for (const c of plan.changes.slice(0, 3)) {
      const current = c.current == null ? "(default)" : JSON.stringify(c.current);
      const proposed = JSON.stringify(c.proposed);
      emit(chalk.dim(`    ${c.option}: ${current} → ${proposed}`));
    }
    if (changes > 3) emit(chalk.dim(`    (+${changes - 3} more)`));
  }
  // Workstream 5 — the Ink PlanCard shows a `y / n / Esc` hint row; the
  // plain renderer prints an explicit prompt so non-TTY operators see
  // exactly which key to type. `apply? [y/n] ` matches README conventions.
  emit("apply? [y/n] ");
}

/**
 * Cost-cap halt overlay. Mirrors the Ink `<CostCapHalt>` card: spent /
 * cap + over amount, pause reason, and the continue/abort prompt. No
 * box-drawing — just structural headings.
 */
function printCostCapHalt(emit: Emit, state: UIState): void {
  const spent = state.runningCostUsd ?? 0;
  const cap = state.costCapBudgetUsd;
  const over = cap != null ? Math.max(0, spent - cap) : 0;
  emit("[!] BUDGET EXCEEDED");
  if (cap != null) {
    emit(`spent: $${spent.toFixed(2)} of $${cap.toFixed(2)} cap (+$${over.toFixed(2)} over)`);
  } else {
    emit(`spent: $${spent.toFixed(2)} (no cap set)`);
  }
  emit("pipeline paused — continuing incurs further charges");
  emit("continue (c) or abort (a)? ");
}

/**
 * severityPlainRank — sort helper mirroring FindingsView's order.
 */
function severityPlainRank(f: ActionableFinding): number {
  const sev = normalizeSeverity(f.displaySeverity ?? f.severity);
  switch (sev) {
    case "critical":
      return 0;
    case "high":
      return 1;
    case "medium":
      return 2;
    case "low":
      return 3;
    default:
      return 4;
  }
}

function tallyFindings(findings: ReadonlyArray<ActionableFinding>): {
  crit: number;
  high: number;
  med: number;
  low: number;
} {
  const out = { crit: 0, high: 0, med: 0, low: 0 };
  for (const f of findings) {
    const sev = normalizeSeverity(f.displaySeverity ?? f.severity);
    if (sev === "critical") out.crit += 1;
    else if (sev === "high") out.high += 1;
    else if (sev === "medium") out.med += 1;
    else out.low += 1;
  }
  return out;
}

function resolveFindingByAlias(
  id: string,
  findings: ReadonlyArray<ActionableFinding>,
): ActionableFinding | undefined {
  if (!id) return undefined;
  // F-NNNN alias = 1-based index into severity-sorted list.
  const aliasMatch = /^F-(\d{1,6})$/i.exec(id);
  if (aliasMatch) {
    const n = Number.parseInt(aliasMatch[1], 10);
    const sorted = [...findings].sort((a, b) => severityPlainRank(a) - severityPlainRank(b));
    return sorted[n - 1];
  }
  return findings.find((f) => f.fingerprint.startsWith(id));
}

function clipLine(text: string, max: number): string {
  if (!text) return "";
  const single = text.replace(/\s+/g, " ").trim();
  if (single.length <= max) return single;
  return `${single.slice(0, max - 1)}…`;
}

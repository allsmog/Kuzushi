import chalk from "chalk";
import type { MessageBus } from "../types.js";
import type {
  BudgetCheckEvent,
  PipelineCompleteEvent,
  PipelineStartEvent,
  PocHarnessAgentActivityEvent,
  PocHarnessCompleteEvent,
  PocHarnessErrorEvent,
  PocHarnessResultEvent,
  ReportCompleteEvent,
  ScanCompleteEvent,
  ScanFindingEvent,
  ScanScannerCompleteEvent,
  StageCompleteEvent,
  TaskCompleteEvent,
  TaskStartEvent,
  TriageAgentActivityEvent,
  TriageErrorEvent,
  TriageResultEvent,
  VerificationAgentActivityEvent,
  VerificationCompleteEvent,
  VerificationErrorEvent,
  VerificationResultEvent,
  PocHarnessStartEvent,
  TriageStartEvent,
  VerificationStartEvent,
  DynamicAnalysisAgentActivityEvent,
  DynamicAnalysisCompleteEvent,
  DynamicAnalysisErrorEvent,
  DynamicAnalysisResultEvent,
  DynamicAnalysisStartEvent,
  PipelineErrorEvent,
} from "../events.js";

// ── Internal state ───────────────────────────────────────────────────────────

interface ProgressState {
  repoName: string;
  startTime: number;

  // Current phase tracking
  currentPhase: string;
  phaseDone: number;
  phaseTotal: number;

  // Scan tracking
  scanFindings: number;
  scannersComplete: number;
  scannersTotal: number;

  // Triage verdicts
  triageTp: number;
  triageNeedsReview: number;
  triageFp: number;
  triageErrors: number;
  triageTotal: number;
  triageDone: number;

  // Verification
  verifyExploitable: number;
  verifyNotExploitable: number;
  verifyErrors: number;
  verifyTotal: number;
  verifyDone: number;

  // PoC harness
  pocGenerated: number;
  pocSkipped: number;
  pocErrors: number;
  pocTotal: number;
  pocDone: number;

  // Dynamic analysis
  dynamicConfirmed: number;
  dynamicInteresting: number;
  dynamicRejected: number;
  dynamicErrors: number;
  dynamicTotal: number;
  dynamicDone: number;

  // Cost
  totalCostUsd: number;

  // Agent activity — latest tool/reasoning summary
  latestActivity: string;
  latestActivityModel: string;

  // Stage tracking
  stagesComplete: number;

  // How many lines we last rendered (for rewriting)
  lastRenderedLines: number;

  // Whether the pipeline is done
  finished: boolean;
}

// ── Public API ───────────────────────────────────────────────────────────────

export interface ProgressWorkerResult {
  /** Whether the progress worker is actively rendering a live panel */
  isActive: boolean;
}

/**
 * Register a progress worker that renders a compact, rewriting status panel
 * to stderr. If stderr is not a TTY (piped output, CI, etc.) or verbose mode
 * is on, the worker becomes a no-op and report-worker handles output.
 */
export function registerProgressWorker(
  bus: MessageBus,
  options?: { verbose?: boolean },
): ProgressWorkerResult {
  const isTTY = process.stderr.isTTY === true;
  const verbose = options?.verbose === true;

  if (!isTTY || verbose) {
    return { isActive: false };
  }

  const state: ProgressState = createInitialState();
  let renderTimer: ReturnType<typeof setInterval> | null = null;

  // ── Event subscriptions ──────────────────────────────────────────────────

  bus.subscribe<PipelineStartEvent>("pipeline:start", (event) => {
    state.repoName = event.payload.context.repoName;
    state.startTime = Date.now();
    state.currentPhase = "Scanning";
    startRendering();
  });

  bus.subscribe<ScanFindingEvent>("scan:finding", () => {
    state.scanFindings++;
  });

  bus.subscribe<ScanScannerCompleteEvent>("scan:scanner-complete", (event) => {
    state.scannersComplete++;
    if (state.scannersTotal === 0) {
      // We'll learn the total from scan:start or pipeline config
      state.scannersTotal = state.scannersComplete;
    }
  });

  bus.subscribe<ScanCompleteEvent>("scan:complete", (event) => {
    state.scanFindings = event.payload.totalFindings;
  });

  bus.subscribe<TaskStartEvent>("task:start", (event) => {
    if (state.currentPhase === "Scanning" || state.currentPhase === "Initializing") {
      state.currentPhase = "Scanning";
    }
  });

  bus.subscribe<TaskCompleteEvent>("task:complete", (event) => {
    if (event.payload.costUsd) {
      state.totalCostUsd += event.payload.costUsd;
    }
  });

  bus.subscribe<StageCompleteEvent>("stage:complete", () => {
    state.stagesComplete++;
  });

  // ── Triage ───────────────────────────────────────────────────────────────

  bus.subscribe<TriageStartEvent>("triage:start", (event) => {
    state.currentPhase = "Triage";
    state.triageTotal = event.payload.findingCount;
    state.phaseTotal = event.payload.findingCount;
    state.phaseDone = 0;
    state.latestActivityModel = event.payload.model;
  });

  bus.subscribe<TriageResultEvent>("triage:result", (event) => {
    const verdict = event.payload.result.verdict;
    if (verdict === "tp") state.triageTp++;
    else if (verdict === "needs_review") state.triageNeedsReview++;
    else if (verdict === "fp") state.triageFp++;

    state.triageDone++;
    state.phaseDone = state.triageDone;

    if (event.payload.costUsd) {
      state.totalCostUsd += event.payload.costUsd;
    }
  });

  bus.subscribe<TriageErrorEvent>("triage:error", (event) => {
    state.triageErrors++;
    state.triageDone++;
    state.phaseDone = state.triageDone;

    if (event.payload.costUsd) {
      state.totalCostUsd += event.payload.costUsd;
    }
  });

  bus.subscribe<TriageAgentActivityEvent>("triage:agent-activity", (event) => {
    state.latestActivity = formatAgentActivity(event.payload);
  });

  // ── Verification ─────────────────────────────────────────────────────────

  bus.subscribe<VerificationStartEvent>("verification:start", (event) => {
    state.currentPhase = "Verification";
    state.verifyTotal = event.payload.findingCount;
    state.phaseTotal = event.payload.findingCount;
    state.phaseDone = 0;
    state.latestActivityModel = event.payload.model;
  });

  bus.subscribe<VerificationResultEvent>("verification:result", (event) => {
    if (event.payload.result.exploitable) {
      state.verifyExploitable++;
    } else {
      state.verifyNotExploitable++;
    }
    state.verifyDone++;
    state.phaseDone = state.verifyDone;

    if (event.payload.costUsd) {
      state.totalCostUsd += event.payload.costUsd;
    }
  });

  bus.subscribe<VerificationErrorEvent>("verification:error", (event) => {
    state.verifyErrors++;
    state.verifyDone++;
    state.phaseDone = state.verifyDone;

    if (event.payload.costUsd) {
      state.totalCostUsd += event.payload.costUsd;
    }
  });

  bus.subscribe<VerificationAgentActivityEvent>("verification:agent-activity", (event) => {
    state.latestActivity = formatAgentActivity(event.payload);
  });

  bus.subscribe<VerificationCompleteEvent>("verification:complete", (event) => {
    if (event.payload.totalCostUsd) {
      // Cost is tracked incrementally; don't double-count
    }
  });

  // ── PoC Harness ──────────────────────────────────────────────────────────

  bus.subscribe<PocHarnessStartEvent>("poc-harness:start", (event) => {
    state.currentPhase = "PoC Harness";
    state.pocTotal = event.payload.findingCount;
    state.phaseTotal = event.payload.findingCount;
    state.phaseDone = 0;
    state.latestActivityModel = event.payload.model;
  });

  bus.subscribe<PocHarnessResultEvent>("poc-harness:result", (event) => {
    if (event.payload.result.skipped) {
      state.pocSkipped++;
    } else {
      state.pocGenerated++;
    }
    state.pocDone++;
    state.phaseDone = state.pocDone;

    if (event.payload.costUsd) {
      state.totalCostUsd += event.payload.costUsd;
    }
  });

  bus.subscribe<PocHarnessErrorEvent>("poc-harness:error", (event) => {
    state.pocErrors++;
    state.pocDone++;
    state.phaseDone = state.pocDone;

    if (event.payload.costUsd) {
      state.totalCostUsd += event.payload.costUsd;
    }
  });

  bus.subscribe<PocHarnessAgentActivityEvent>("poc-harness:agent-activity", (event) => {
    state.latestActivity = formatAgentActivity(event.payload);
  });

  bus.subscribe<PocHarnessCompleteEvent>("poc-harness:complete", () => {
    // Phase completed
  });

  // ── Dynamic Analysis ─────────────────────────────────────────────────────

  bus.subscribe<DynamicAnalysisStartEvent>("dynamic:start", (event) => {
    state.currentPhase = "Dynamic Analysis";
    state.dynamicTotal = event.payload.findingCount;
    state.phaseTotal = event.payload.findingCount;
    state.phaseDone = 0;
    state.latestActivityModel = event.payload.model;
  });

  bus.subscribe<DynamicAnalysisResultEvent>("dynamic:result", (event) => {
    const status = event.payload.result.status;
    if (status === "confirmed") state.dynamicConfirmed++;
    else if (status === "interesting") state.dynamicInteresting++;
    else if (status === "rejected") state.dynamicRejected++;

    state.dynamicDone++;
    state.phaseDone = state.dynamicDone;

    if (event.payload.costUsd) {
      state.totalCostUsd += event.payload.costUsd;
    }
  });

  bus.subscribe<DynamicAnalysisErrorEvent>("dynamic:error", (event) => {
    state.dynamicErrors++;
    state.dynamicDone++;
    state.phaseDone = state.dynamicDone;

    if (event.payload.costUsd) {
      state.totalCostUsd += event.payload.costUsd;
    }
  });

  bus.subscribe<DynamicAnalysisAgentActivityEvent>("dynamic:agent-activity", (event) => {
    state.latestActivity = formatAgentActivity(event.payload);
  });

  bus.subscribe<DynamicAnalysisCompleteEvent>("dynamic:complete", () => {
    // Phase completed
  });

  // ── Budget ───────────────────────────────────────────────────────────────

  bus.subscribe<BudgetCheckEvent>("budget:check", (event) => {
    state.totalCostUsd = event.payload.currentSpend;
  });

  // ── Pipeline end ─────────────────────────────────────────────────────────

  bus.subscribe<PipelineCompleteEvent>("pipeline:complete", () => {
    state.finished = true;
    stopRendering();
    clearPanel();
  });

  bus.subscribe<ReportCompleteEvent>("report:complete", () => {
    state.finished = true;
    stopRendering();
    clearPanel();
  });

  bus.subscribe<PipelineErrorEvent>("pipeline:error", (event) => {
    if (event.payload.fatal) {
      state.finished = true;
      stopRendering();
      clearPanel();
    }
  });

  // ── Render loop ──────────────────────────────────────────────────────────

  function startRendering(): void {
    if (renderTimer) return;
    render(); // immediate first frame
    renderTimer = setInterval(render, 500);
  }

  function stopRendering(): void {
    if (renderTimer) {
      clearInterval(renderTimer);
      renderTimer = null;
    }
  }

  function clearPanel(): void {
    if (state.lastRenderedLines > 0) {
      // Move up and clear each line
      const up = `\x1B[${state.lastRenderedLines}A`;
      const clear = Array.from({ length: state.lastRenderedLines }, () => "\x1B[2K").join("\n");
      process.stderr.write(up + clear + `\x1B[${state.lastRenderedLines}A`);
      state.lastRenderedLines = 0;
    }
  }

  function render(): void {
    if (state.finished) return;

    const lines = buildPanel(state);

    // Clear previous render
    if (state.lastRenderedLines > 0) {
      process.stderr.write(`\x1B[${state.lastRenderedLines}A`);
    }

    // Write new lines, clearing each line before writing
    for (const line of lines) {
      process.stderr.write(`\x1B[2K${line}\n`);
    }

    state.lastRenderedLines = lines.length;
  }

  return { isActive: true };
}

// ── Panel builder ────────────────────────────────────────────────────────────

function buildPanel(state: ProgressState): string[] {
  const lines: string[] = [];

  // ── Header line ──────────────────────────────────────────────────────────
  const elapsed = formatElapsed(Date.now() - state.startTime);
  const repoLabel = state.repoName || "repo";
  lines.push(
    `  ${chalk.bold("Kuzushi")} ${chalk.dim("--")} scanning ${chalk.cyan(repoLabel)}` +
    `${" ".repeat(Math.max(1, 4))}${chalk.dim(`[${elapsed}]`)}`,
  );

  lines.push(""); // blank separator

  // ── Stage + progress bar ─────────────────────────────────────────────────
  const phaseLabel = chalk.bold(state.currentPhase);
  const costLabel = state.totalCostUsd > 0
    ? chalk.dim(`$${state.totalCostUsd.toFixed(4)}`)
    : "";

  if (state.phaseTotal > 0) {
    const bar = buildProgressBar(state.phaseDone, state.phaseTotal, 20);
    const counter = `${state.phaseDone}/${state.phaseTotal}`;
    lines.push(`  Stage: ${phaseLabel}  ${bar}  ${counter}    ${costLabel}`);
  } else if (state.currentPhase === "Scanning") {
    const scanLabel = state.scanFindings > 0
      ? `${state.scanFindings} findings found`
      : "scanning...";
    lines.push(`  Stage: ${phaseLabel}  ${chalk.dim(scanLabel)}    ${costLabel}`);
  } else {
    lines.push(`  Stage: ${phaseLabel}    ${costLabel}`);
  }

  // ── Activity line ────────────────────────────────────────────────────────
  if (state.latestActivity) {
    const model = state.latestActivityModel
      ? chalk.dim(state.latestActivityModel)
      : "";
    const activity = truncate(state.latestActivity, 60);
    lines.push(`    ${model}${model ? "  " : ""}${chalk.dim(activity)}`);
  } else {
    lines.push(""); // placeholder
  }

  lines.push(""); // blank separator

  // ── Verdict counters ─────────────────────────────────────────────────────
  const verdictParts: string[] = [];

  // Triage verdicts
  if (state.triageDone > 0) {
    if (state.triageTp > 0) verdictParts.push(chalk.red(`${state.triageTp} TP`));
    if (state.triageNeedsReview > 0) verdictParts.push(chalk.yellow(`${state.triageNeedsReview} needs_review`));
    if (state.triageFp > 0) verdictParts.push(chalk.green(`${state.triageFp} FP`));
    if (state.triageErrors > 0) verdictParts.push(chalk.red.dim(`${state.triageErrors} err`));
  }

  // Verification counters
  if (state.verifyDone > 0) {
    const vParts: string[] = [];
    if (state.verifyExploitable > 0) vParts.push(chalk.red(`${state.verifyExploitable} exploitable`));
    if (state.verifyNotExploitable > 0) vParts.push(chalk.dim(`${state.verifyNotExploitable} safe`));
    if (state.verifyErrors > 0) vParts.push(chalk.red.dim(`${state.verifyErrors} err`));
    if (vParts.length > 0) {
      verdictParts.push(chalk.dim("| verify:") + " " + vParts.join("  "));
    }
  }

  // PoC counters
  if (state.pocDone > 0) {
    const pParts: string[] = [];
    if (state.pocGenerated > 0) pParts.push(chalk.cyan(`${state.pocGenerated} generated`));
    if (state.pocSkipped > 0) pParts.push(chalk.dim(`${state.pocSkipped} skipped`));
    if (state.pocErrors > 0) pParts.push(chalk.red.dim(`${state.pocErrors} err`));
    if (pParts.length > 0) {
      verdictParts.push(chalk.dim("| poc:") + " " + pParts.join("  "));
    }
  }

  // Dynamic analysis counters
  if (state.dynamicDone > 0) {
    const dParts: string[] = [];
    if (state.dynamicConfirmed > 0) dParts.push(chalk.red(`${state.dynamicConfirmed} confirmed`));
    if (state.dynamicInteresting > 0) dParts.push(chalk.yellow(`${state.dynamicInteresting} interesting`));
    if (state.dynamicRejected > 0) dParts.push(chalk.dim(`${state.dynamicRejected} rejected`));
    if (state.dynamicErrors > 0) dParts.push(chalk.red.dim(`${state.dynamicErrors} err`));
    if (dParts.length > 0) {
      verdictParts.push(chalk.dim("| dyn:") + " " + dParts.join("  "));
    }
  }

  if (verdictParts.length > 0) {
    lines.push(`  Verdicts: ${verdictParts.join("  ")}`);
  } else {
    lines.push(""); // placeholder
  }

  return lines;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function createInitialState(): ProgressState {
  return {
    repoName: "",
    startTime: Date.now(),
    currentPhase: "Initializing",
    phaseDone: 0,
    phaseTotal: 0,
    scanFindings: 0,
    scannersComplete: 0,
    scannersTotal: 0,
    triageTp: 0,
    triageNeedsReview: 0,
    triageFp: 0,
    triageErrors: 0,
    triageTotal: 0,
    triageDone: 0,
    verifyExploitable: 0,
    verifyNotExploitable: 0,
    verifyErrors: 0,
    verifyTotal: 0,
    verifyDone: 0,
    pocGenerated: 0,
    pocSkipped: 0,
    pocErrors: 0,
    pocTotal: 0,
    pocDone: 0,
    dynamicConfirmed: 0,
    dynamicInteresting: 0,
    dynamicRejected: 0,
    dynamicErrors: 0,
    dynamicTotal: 0,
    dynamicDone: 0,
    totalCostUsd: 0,
    latestActivity: "",
    latestActivityModel: "",
    stagesComplete: 0,
    lastRenderedLines: 0,
    finished: false,
  };
}

function buildProgressBar(done: number, total: number, width: number): string {
  if (total <= 0) return chalk.dim("[" + " ".repeat(width) + "]");

  const fraction = Math.min(done / total, 1);
  const filled = Math.round(fraction * width);
  const empty = width - filled;

  const bar =
    chalk.green("=".repeat(Math.max(0, filled - 1))) +
    (filled > 0 ? chalk.green.bold(">") : "") +
    chalk.dim(" ".repeat(empty));

  return `[${bar}]`;
}

function formatElapsed(ms: number): string {
  const totalSeconds = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;

  if (minutes > 0) {
    return `${minutes}m ${seconds.toString().padStart(2, "0")}s`;
  }
  return `${seconds}s`;
}

interface AgentActivityPayload {
  kind: "tool-start" | "tool-progress" | "tool-complete" | "reasoning";
  toolName?: string;
  toolInput?: Record<string, unknown>;
  summary?: string;
}

function formatAgentActivity(payload: AgentActivityPayload): string {
  if (payload.kind === "tool-start") {
    return formatToolUse(payload.toolName, payload.toolInput);
  }
  if (payload.kind === "tool-progress") {
    const toolName = payload.toolName ?? "tool";
    return `... ${toolName}`;
  }
  if (payload.kind === "tool-complete" && payload.summary) {
    return payload.summary;
  }
  if (payload.summary) {
    return payload.summary;
  }
  return "";
}

function formatToolUse(
  toolName: string | undefined,
  toolInput: Record<string, unknown> | undefined,
): string {
  const name = toolName ?? "Tool";

  if (!toolInput) return name;

  const filePath = asString(toolInput["file_path"]) ?? asString(toolInput["path"]);
  const pattern = asString(toolInput["pattern"]);
  const glob = asString(toolInput["glob"]);

  if (name === "Read" && filePath) return `Reading ${filePath}`;
  if (name === "Grep" && pattern) return `Grepping "${pattern}"`;
  if (name === "Glob" && glob) return `Globbing "${glob}"`;
  if (filePath) return `${name} ${filePath}`;

  return name;
}

function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return text.slice(0, max - 3) + "...";
}

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

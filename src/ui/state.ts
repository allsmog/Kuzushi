/**
 * Observable UI state store.
 *
 * The report-worker writes state updates via `store.update()`.
 * The Ink app subscribes via `store.subscribe()` and re-renders reactively.
 */

import type { ThreatModelDocument } from "../agents/tasks/threat-modeling/types.js";
import type { QualityGateResult } from "../quality-gate.js";
import type { RunMetrics } from "../scoring/run-metrics.js";
import type {
  AttackPathAnalysis,
  CodeCitation,
  ExploitChain,
  OperatorScanContext,
  SecurityControl,
  Verdict,
} from "../types.js";
import type { ConfigConfirmData } from "./components/ConfigConfirm.js";
import type { CredentialChoice } from "./components/CredentialPrompt.js";
import type { WizardResult } from "./components/SetupWizard.js";

export type Phase = "idle" | "scanning" | "triaging" | "verifying" | "poc" | "summary" | "done";
export type UIMode = "preflight" | "running" | "summary" | "review" | "done" | "shell";

export type StageStatus = "pending" | "active" | "done" | "error";
export type NoticeLevel = "info" | "warning" | "error" | "success";

export interface UINotice {
  id: string;
  level: NoticeLevel;
  message: string;
  detail?: string;
  source?: string;
  createdAt: number;
}

export type PreflightState =
  | {
      kind: "wizard";
      repoName: string;
      repoRoot: string;
      onComplete: (result: WizardResult) => void;
      onCancel: () => void;
    }
  | {
      kind: "confirm";
      repoName: string;
      repoRoot: string;
      config: ConfigConfirmData;
      onProceed: () => void;
      onEdit: () => void;
      onQuit: () => void;
    }
  | {
      kind: "credentials";
      onComplete: (choice: CredentialChoice) => void;
      onCancel: () => void;
    }
  | {
      kind: "context-intake";
      repoName: string;
      repoRoot: string;
      initialContext: OperatorScanContext;
      onComplete: (context: OperatorScanContext) => void;
      onSkip: () => void;
      onCancel: () => void;
    }
  | {
      kind: "threat-editor";
      repoName: string;
      repoRoot: string;
      threatModel: ThreatModelDocument;
      onComplete: (updated: ThreatModelDocument) => void;
      onSkip: () => void;
      onCancel: () => void;
    };

export interface ReviewSession {
  findings: ActionableFinding[];
  onVerdict: (fingerprint: string, verdict: Verdict) => void;
  onQuit: () => void;
}

export interface SubTask {
  id: string;
  label: string;
  status: StageStatus;
  detail?: string;
  elapsedMs?: number;
  startedAt?: number;
  findingCount?: number;
  lastFinding?: string;
  /** Whether this is a primary detector or a support/setup task. */
  role?: "primary" | "support";
  /** Live agent activity lines (last 4 kept). */
  activityLines?: AgentActivityLine[];
  /** Timestamp of last visible activity event — used for heartbeat logic. */
  lastEventAt?: number;
  /** Number of retries attempted so far. */
  retryCount?: number;
  /** Last error message (sticky for display). */
  lastError?: string;
}

export interface PipelineStage {
  id: string;
  label: string;
  status: StageStatus;
  detail?: string;
  elapsedMs?: number;
  startedAt?: number;
  /** Sub-tasks branching off this stage (e.g. individual scanners, findings). */
  subTasks: SubTask[];
}

export interface ResultLine {
  kind: "triage" | "verify" | "poc" | "error";
  verdict?: Verdict;
  confidence?: number;
  costUsd?: number;
  fingerprint: string;
  index: number;
  total: number;
  attempts?: number;
  // Verify-specific
  exploitable?: boolean;
  // PoC-specific
  skipped?: boolean;
  parsed?: boolean;
  // Error-specific
  errorMessage?: string;
  errorStage?: string;
}

export interface AgentActivityLine {
  kind:
    | "tool-start"
    | "tool-progress"
    | "tool-complete"
    | "summary"
    | "reasoning"
    | "finding-preview";
  toolName?: string;
  detail?: string;
  elapsedSeconds?: number;
  index: number;
  total: number;
}

export interface SummaryData {
  repoName: string;
  verdictCounts: Record<Verdict, number>;
  totalTriaged: number;
  triageCostUsd: number;
  verificationCostUsd: number;
  pocHarnessCostUsd: number;
  variantAnalysisCostUsd: number;
  exploitable: number;
  notExploitable: number;
  pocGenerated: number;
  pocSkipped: number;
  triageErrors: number;
  verifyErrors: number;
  pocHarnessErrors: number;
  skippedLowConfidence: number;
  skippedByFpFilter: number;
  softSuppressedFindings: number;
  skippedByLlmRescore: number;
  corroboratedClusters: number;
  verifyGateAutoAccepted: number;
  verifyGateSkipped: number;
  variantFindings: number;
  dynamicConfirmed: number;
  dynamicInteresting: number;
  dynamicRejected: number;
  dynamicErrors: number;
  dynamicCostUsd: number;
  incrementalCachedFiles: number;
  incrementalRescannedFiles: number;
  incrementalDepExpandedFiles: number;
  patchGenerated: number;
  patchVerified: number;
  patchFailed: number;
  patchErrors: number;
  patchCostUsd: number;
  budgetExceeded: boolean;
  failedTasks: string[];
  extractionDegradation?: { status: string; reasons: string[] };
  stitchDegradation?: { type: string; reason: string; message: string };
  tiPriorDegraded: boolean;
  runMetrics?: RunMetrics;
  auditLogDir?: string;
  pocOutputDir?: string;
  threatModelSummary?: string;
  exploitChains: ExploitChain[];
  actionableFindings: ActionableFinding[];
}

export interface ActionableFinding {
  verdict: Verdict;
  confidence: number;
  severity: string;
  taskId: string;
  filePath: string;
  startLine: number;
  ruleId: string;
  rationale: string;
  fingerprint: string;
  verifyExploitable?: number;
  verifyPocPayload?: string;
  verifyAttackVector?: string;
  proofState?: string;
  engineProvenance?: Array<{ kind: string; detail: string }>;
  taintPath?: unknown;
  corroboratingSignals: Array<{
    taskId: string;
    fingerprint?: string;
    ruleId?: string;
    filePath?: string;
    startLine?: number;
    cwe?: string[];
    score?: number;
  }>;
  suppressionReasons: Array<{ id: string }>;
  pocHarnessPath?: string;
  pocHarnessSkipped?: number;
  pocHarnessSkipReason?: string;
  pocHarnessParsed?: number;
  pocHarnessParseError?: string;
  pocRunVerdict?: string;
  pocRunDurationMs?: number;
  codeCitations?: CodeCitation[];
  attackPath?: AttackPathAnalysis;
  assumptions?: string[];
  controls?: SecurityControl[];
  blindspots?: string[];
  sourceThreatIds?: string[];
  verificationSteps?: string[];
  blame?: { sha: string; author: string; date: string; summary: string };
  introducedIn?: string;
}

export interface UIState {
  mode: UIMode;
  phase: Phase;
  repoName: string;
  tasks: string[];
  totalFindings: number;
  selectedForTriage: number;
  skippedAlreadyTriaged: number;
  model: string;
  progress: { current: number; total: number };
  /** Running cost total — updated on every result. */
  runningCostUsd: number;
  /** Rate limit / throttle info — shown when active. */
  throttle?: { concurrency: number; reason: string } | null;
  /** Timestamp when pipeline started (for elapsed timer). */
  pipelineStartedAt?: number;
  /** Resolved config for the pre-scan banner. */
  configBanner?: {
    model: string;
    tasks: string[];
    severity?: string[];
    concurrency?: number;
    backend?: string;
    budget?: number;
    scanMode?: string;
  } | null;
  results: ResultLine[];
  agentActivity: Map<string, AgentActivityLine[]>;
  summary: SummaryData | null;
  qualityGate: QualityGateResult | null;
  notices: UINotice[];
  warnings: string[];
  bannerShown: boolean;
  compactBannerShown?: boolean;
  startBannerShown: boolean;
  /** Resume diff data — shown when resuming a previous run. */
  resumeDiff?: import("./components/ResumeDiff.js").ResumeDiffData | null;
  /** REPL state — controls live scan behavior via slash commands. */
  replState?: {
    skippedFingerprints: Set<string>;
    suppressedRules: Set<string>;
    focusPath: string | null;
    paused: boolean;
  };
  /** Pipeline stage indicator — tracks all stages for the ○/●/◆ display. */
  stages: PipelineStage[];
  preflight: PreflightState | null;
  review: ReviewSession | null;
  /** Shell mode state — interactive copilot. */
  shell?: ShellState | null;
}

export interface ShellHistoryEntry {
  type: "input" | "output" | "error";
  text: string;
  timestamp: number;
  prompt?: string;
}

/**
 * Generated application context for a target repository.
 * Platform-level state — readable by all modules, not owned by any single one.
 * Task outputs stored as `unknown` to avoid coupling state.ts to heavy task types.
 * Formatting/display functions do runtime shape checks.
 */
export interface ContextSnapshot {
  /** Which target this context was generated for. */
  target: string;
  /** When this context was generated (epoch ms). */
  timestamp: number;
  /** Discovery mode used during generation. */
  discovery: "auto" | "flat" | "modules";
  /** Which optional steps were enabled when generated. */
  options: { enrichment: boolean; threatModel: boolean; scenarios: boolean };

  // --- Single-project context (discovery=flat, or auto with single project) ---
  /** RepoContext from context-gatherer (languages, frameworks, auth, entry points). */
  repoContext?: unknown;
  /** FileIndex from context-gatherer (file tree, security pattern matches). */
  fileIndex?: unknown;
  /** Enrichment object from context-enricher (custom middleware, sanitizers, trust boundaries). */
  enrichedContext?: unknown;
  /** ApplicationModel from app-model-build (routes, outbound clients, data stores, jobs). */
  appModel?: unknown;
  /** ThreatModelDocument from threat-model-randori (DFD, STRIDE threats, summary). */
  threatModel?: unknown;
  /** ThreatScenario[] from threat-scenario-build. */
  scenarios?: unknown[];

  // --- Monorepo context (discovery=modules) ---
  /** Per-module contexts, keyed by relative path (e.g. "api/", "auth-service/"). */
  modules?: Record<string, Omit<ContextSnapshot, "modules" | "discovery" | "options">>;
}

export interface ShellState {
  /** Loaded module IDs. */
  modules: string[];
  /** Available tool names. */
  tools: string[];
  /** Currently focused module (for shorthand commands). */
  focusedModule: string | null;
  /** Active target. */
  target: string | null;
  /** Workspace ID. */
  workspace: string | null;
  /** Conversation history (rendered in the scroll region). */
  history: ShellHistoryEntry[];
  /** Submitted commands, capped and persisted for prompt recall. */
  commandHistory: string[];
  /** Per-tool stored options from /set, keyed by fully-qualified tool name. */
  moduleOptions: Record<string, Record<string, unknown>>;
  /** Last selected or successfully executed tool. */
  lastUsedTool?: string;
  /** Generated context for the current target. Platform-level — readable by all modules. */
  contextSnapshot?: ContextSnapshot | null;
  /** Transient assistant text streamed before the turn finalizes. */
  pendingAssistantText?: string;
  /** Whether the agent is currently processing a query. */
  processing: boolean;
  /** Currently executing tool (shown as inline activity). */
  currentTool?: { name: string; elapsedSeconds: number };
  /** Callback to handle user input from the Ink component. */
  onInput?: (input: string) => void;
  /** Callback to exit the shell. */
  onExit?: () => void;
  /** Callback to abort the active shell action. */
  onAbort?: () => void;
}

type Listener = () => void;

export class UIStore {
  private state: UIState;
  private listeners = new Set<Listener>();
  private preflightReturnMode: UIMode = "running";
  private reviewReturnMode: UIMode = "summary";

  constructor() {
    this.state = {
      mode: "preflight",
      phase: "idle",
      repoName: "",
      tasks: [],
      totalFindings: 0,
      selectedForTriage: 0,
      skippedAlreadyTriaged: 0,
      model: "",
      progress: { current: 0, total: 0 },
      runningCostUsd: 0,
      results: [],
      agentActivity: new Map(),
      summary: null,
      qualityGate: null,
      notices: [],
      warnings: [],
      bannerShown: false,
      compactBannerShown: false,
      startBannerShown: false,
      stages: [],
      preflight: null,
      review: null,
    };
  }

  getState(): UIState {
    return this.state;
  }

  update(partial: Partial<UIState>): void {
    this.state = { ...this.state, ...partial };
    this.notify();
  }

  setMode(mode: UIMode): void {
    this.state = { ...this.state, mode };
    this.notify();
  }

  setPreflight(preflight: PreflightState | null, returnMode?: UIMode): void {
    if (preflight) {
      this.preflightReturnMode = returnMode ?? this.state.mode;
    }
    this.state = {
      ...this.state,
      preflight,
      mode: preflight
        ? "preflight"
        : this.state.mode === "preflight"
          ? this.preflightReturnMode
          : this.state.mode,
    };
    this.notify();
  }

  setReview(review: ReviewSession | null, returnMode?: UIMode): void {
    if (review) {
      this.reviewReturnMode = returnMode ?? this.state.mode;
    }
    this.state = {
      ...this.state,
      review,
      mode: review
        ? "review"
        : this.state.mode === "review"
          ? this.reviewReturnMode
          : this.state.mode,
    };
    this.notify();
  }

  addResult(result: ResultLine): void {
    this.state = {
      ...this.state,
      results: [...this.state.results, result],
      progress: { current: result.index, total: result.total },
      runningCostUsd: this.state.runningCostUsd + (result.costUsd ?? 0),
    };
    this.notify();
  }

  addNotice(
    notice: Omit<UINotice, "id" | "createdAt"> & { id?: string; createdAt?: number },
  ): void {
    const createdAt = notice.createdAt ?? Date.now();
    const id = notice.id ?? `${createdAt}-${Math.random().toString(36).slice(2, 8)}`;
    const duplicate = this.state.notices.find(
      (entry) =>
        entry.level === notice.level &&
        entry.message === notice.message &&
        entry.detail === notice.detail,
    );
    if (duplicate) {
      return;
    }

    this.state = {
      ...this.state,
      notices: [...this.state.notices, { ...notice, id, createdAt }].slice(-8),
    };
    this.notify();
  }

  clearNotices(): void {
    if (this.state.notices.length === 0) {
      return;
    }
    this.state = { ...this.state, notices: [] };
    this.notify();
  }

  addAgentActivity(fingerprint: string, line: AgentActivityLine): void {
    const newMap = new Map(this.state.agentActivity);
    const lines = newMap.get(fingerprint) ?? [];
    const previous = lines[lines.length - 1];
    if (
      previous &&
      previous.kind === line.kind &&
      previous.toolName === line.toolName &&
      previous.detail === line.detail
    ) {
      return;
    }
    // Keep only the latest 4 activity lines per finding to avoid clutter.
    const updated = [...lines, line].slice(-4);
    newMap.set(fingerprint, updated);
    this.state = { ...this.state, agentActivity: newMap };
    this.notify();
  }

  clearAgentActivity(fingerprint: string): void {
    const newMap = new Map(this.state.agentActivity);
    newMap.delete(fingerprint);
    this.state = { ...this.state, agentActivity: newMap };
    this.notify();
  }

  /** Initialize the pipeline stages. */
  initStages(stageIds: Array<{ id: string; label: string }>): void {
    this.state = {
      ...this.state,
      stages: stageIds.map((s) => ({
        id: s.id,
        label: s.label,
        status: "pending" as StageStatus,
        subTasks: [],
      })),
    };
    this.notify();
  }

  /** Mark a stage as active (and complete any previously active stage). */
  activateStage(stageId: string, detail?: string): void {
    const now = Date.now();
    const stages = this.state.stages.map((s) => {
      if (s.id === stageId) {
        return { ...s, status: "active" as StageStatus, detail, startedAt: now, subTasks: [] };
      }
      // Auto-complete any previously active stage
      if (s.status === "active") {
        return { ...s, status: "done" as StageStatus, elapsedMs: now - (s.startedAt ?? now) };
      }
      return s;
    });
    this.state = { ...this.state, stages };
    this.notify();
  }

  /** Mark a stage as done. */
  completeStage(stageId: string): void {
    const now = Date.now();
    const stages = this.state.stages.map((s) => {
      if (s.id === stageId) {
        return { ...s, status: "done" as StageStatus, elapsedMs: now - (s.startedAt ?? now) };
      }
      return s;
    });
    this.state = { ...this.state, stages };
    this.notify();
  }

  /** Add or update a sub-task under a stage (e.g. individual scanner, finding). */
  upsertSubTask(stageId: string, subTask: SubTask): void {
    const stages = this.state.stages.map((s) => {
      if (s.id === stageId) {
        const existing = s.subTasks.findIndex((t) => t.id === subTask.id);
        const updated = [...s.subTasks];
        if (existing >= 0) {
          updated[existing] = { ...updated[existing], ...subTask };
        } else {
          updated.push(subTask);
        }
        return { ...s, subTasks: updated };
      }
      return s;
    });
    this.state = { ...this.state, stages };
    this.notify();
  }

  recordSubTaskFinding(stageId: string, taskId: string, detail: string): void {
    const now = Date.now();
    const stages = this.state.stages.map((s) => {
      if (s.id !== stageId) {
        return s;
      }

      const updated = s.subTasks.map((task) => {
        if (task.id !== taskId) {
          return task;
        }

        return {
          ...task,
          findingCount: (task.findingCount ?? 0) + 1,
          lastFinding: detail,
          detail,
          startedAt: task.startedAt ?? now,
        };
      });

      return { ...s, subTasks: updated };
    });

    this.state = { ...this.state, stages };
    this.notify();
  }

  /**
   * Append an activity line to a scan sub-task.
   *
   * Prioritizes narrative lines (reasoning, finding-preview, tool-complete)
   * over mechanical ones (tool-start, tool-progress). Keeps up to 4 lines
   * but ensures the latest reasoning/finding always displaces old tool calls.
   */
  addScanActivity(taskId: string, line: Omit<AgentActivityLine, "index" | "total">): void {
    const now = Date.now();
    const stages = this.state.stages.map((s) => {
      if (s.id !== "scan") return s;
      const updated = s.subTasks.map((task) => {
        if (task.id !== taskId) return task;
        const existing = task.activityLines ?? [];
        const prev = existing[existing.length - 1];
        // Deduplicate consecutive identical lines.
        if (
          prev &&
          prev.kind === line.kind &&
          prev.toolName === line.toolName &&
          prev.detail === line.detail
        ) {
          return { ...task, lastEventAt: now };
        }
        const entry = { ...line, index: 0, total: 0 };
        const all = [...existing, entry];
        // Smart cap: keep narrative lines (reasoning, finding-preview,
        // tool-complete) and only the most recent tool-start/tool-progress.
        const activityLines = curateScanActivityLines(all, 4);
        return { ...task, activityLines, lastEventAt: now };
      });
      return { ...s, subTasks: updated };
    });
    this.state = { ...this.state, stages };
    this.notify();
  }

  /** Clear activity lines for a scan sub-task (e.g. on completion). */
  clearScanActivity(taskId: string): void {
    const stages = this.state.stages.map((s) => {
      if (s.id !== "scan") return s;
      const updated = s.subTasks.map((task) => {
        if (task.id !== taskId || !task.activityLines?.length) return task;
        const { activityLines: _, ...rest } = task;
        return rest;
      });
      return { ...s, subTasks: updated };
    });
    this.state = { ...this.state, stages };
    this.notify();
  }

  /** Update the detail text on an active stage. */
  updateStageDetail(stageId: string, detail: string): void {
    const stages = this.state.stages.map((s) => {
      if (s.id === stageId) {
        return { ...s, detail };
      }
      return s;
    });
    this.state = { ...this.state, stages };
    this.notify();
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    for (const listener of this.listeners) {
      listener();
    }
  }
}

export function createUIStore(): UIStore {
  return new UIStore();
}

/** Narrative line kinds that tell the investigation story. */
const NARRATIVE_KINDS = new Set<string>([
  "reasoning",
  "finding-preview",
  "tool-complete",
  "summary",
]);

/**
 * Keep up to `max` lines, prioritizing narrative (reasoning, findings,
 * summaries) over mechanical tool calls. Always keeps the most recent
 * tool-start so users can see what's happening right now.
 */
function curateScanActivityLines(lines: AgentActivityLine[], max: number): AgentActivityLine[] {
  if (lines.length <= max) return lines;

  const narrative: AgentActivityLine[] = [];
  const mechanical: AgentActivityLine[] = [];

  for (const line of lines) {
    if (NARRATIVE_KINDS.has(line.kind)) {
      narrative.push(line);
    } else {
      mechanical.push(line);
    }
  }

  // Keep all narrative (up to max), fill remaining slots with the latest tool calls.
  const kept = narrative.slice(-max);
  const remaining = max - kept.length;
  if (remaining > 0) {
    kept.push(...mechanical.slice(-remaining));
  }

  // Re-sort to preserve chronological order (by original position).
  const indexMap = new Map(lines.map((l, i) => [l, i]));
  kept.sort((a, b) => (indexMap.get(a) ?? 0) - (indexMap.get(b) ?? 0));

  return kept.slice(-max);
}

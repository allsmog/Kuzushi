/**
 * Observable UI state store.
 *
 * The report-worker writes state updates via `store.update()`.
 * The Ink app subscribes via `store.subscribe()` and re-renders reactively.
 */
import type { Verdict } from "../types.js";
import type { QualityGateResult } from "../quality-gate.js";
import type { RunMetrics } from "../scoring/run-metrics.js";
import type { ExploitChain } from "../types.js";
import type { WizardResult } from "./components/SetupWizard.js";
import type { ConfigConfirmData } from "./components/ConfigConfirm.js";

export type Phase = "idle" | "scanning" | "triaging" | "verifying" | "poc" | "summary" | "done";
export type UIMode = "preflight" | "running" | "summary" | "review" | "done";

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
  kind: "tool-start" | "tool-progress" | "tool-complete" | "summary" | "reasoning";
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
}

type Listener = () => void;

export class UIStore {
  private state: UIState;
  private listeners = new Set<Listener>();

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

  setPreflight(preflight: PreflightState | null): void {
    this.state = {
      ...this.state,
      preflight,
      mode: preflight ? "preflight" : this.state.mode === "preflight" ? "running" : this.state.mode,
    };
    this.notify();
  }

  setReview(review: ReviewSession | null): void {
    this.state = {
      ...this.state,
      review,
      mode: review ? "review" : this.state.mode === "review" ? "summary" : this.state.mode,
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

  addNotice(notice: Omit<UINotice, "id" | "createdAt"> & { id?: string; createdAt?: number }): void {
    const createdAt = notice.createdAt ?? Date.now();
    const id = notice.id ?? `${createdAt}-${Math.random().toString(36).slice(2, 8)}`;
    const duplicate = this.state.notices.find((entry) =>
      entry.level === notice.level
      && entry.message === notice.message
      && entry.detail === notice.detail,
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
      previous
      && previous.kind === line.kind
      && previous.toolName === line.toolName
      && previous.detail === line.detail
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
      stages: stageIds.map((s) => ({ id: s.id, label: s.label, status: "pending" as StageStatus, subTasks: [] })),
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

/**
 * Observable UI state store.
 *
 * The report-worker writes state updates via `store.update()`.
 * The Ink app subscribes via `store.subscribe()` and re-renders reactively.
 */

import type { ThreatModelDocument } from "../agents/tasks/threat-modeling/types.js";
import type { ShellPlan } from "../copilot/nl-planner.js";
import type { ModuleCategory, ModuleRank } from "../modules/types.js";

// Re-export so the UI layer can `import type { ShellPlan } from "../state.js"`
// without cross-cutting into `src/copilot/`.
export type { ShellPlan, ShellPlanChange } from "../copilot/nl-planner.js";

import type { QualityGateResult } from "../quality-gate.js";
import type { RunMetrics } from "../scoring/run-metrics.js";
import type {
  AttackPathAnalysis,
  CodeCitation,
  ExploitChain,
  KuzushiConfig,
  OperatorScanContext,
  SecurityControl,
  Verdict,
} from "../types.js";
import type { ConfigConfirmData } from "./components/ConfigConfirm.js";
import type { ConfigPatchEntry } from "./components/ConfigEditor.js";
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
    }
  | {
      kind: "config-editor";
      initialConfig: KuzushiConfig;
      configPath: string;
      focusKey?: string;
      onComplete: (patch: ConfigPatchEntry[]) => void;
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
  /** Human-readable finding title from triage (e.g. "Copilot shell enables Bash tool"). */
  title?: string;
  /** Triage-assessed display severity ("critical" | "high" | "medium" | "low"). */
  displaySeverity?: "critical" | "high" | "medium" | "low";
  /** 2-3 sentence Alice-and-Bob attack scenario from triage. */
  attackNarrative?: string;
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
  /** Per-phase cost breakdown — updated live. */
  costBreakdown: { triage: number; verify: number; poc: number };
  /** Estimated time remaining in ms for the active phase. */
  etaMs?: number;
  /** Active view tab during running mode. */
  scanView: "pipeline" | "findings" | "cost";
  /** Expand the B1 heartbeat strip into a per-agent list. Default false. */
  heartbeatExpanded?: boolean;
  /**
   * Expand the B2 NoticeRail from its collapsed rollup header into the
   * full per-notice list. Errors always render full regardless of this
   * flag. Default false.
   */
  noticeRailExpanded?: boolean;
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
  /**
   * Wayfinding state — optional breadcrumb shown at the top of the UI for
   * nested flows. Null/undefined means "hide the breadcrumb row".
   */
  breadcrumb?: {
    segments: ReadonlyArray<string>;
    currentStep?: number;
    totalSteps?: number;
  } | null;
}

const PREFLIGHT_STEP_ORDER = [
  "wizard",
  "confirm",
  "credentials",
  "context-intake",
  "threat-editor",
  "config-editor",
] as const;

const PREFLIGHT_SEGMENT_LABELS: Record<(typeof PREFLIGHT_STEP_ORDER)[number], string> = {
  wizard: "Preset",
  confirm: "Confirm",
  credentials: "Credentials",
  "context-intake": "Context Intake",
  "threat-editor": "Threat Model",
  "config-editor": "Config",
};

function preflightBreadcrumb(kind: (typeof PREFLIGHT_STEP_ORDER)[number]): UIState["breadcrumb"] {
  const stepIdx = PREFLIGHT_STEP_ORDER.indexOf(kind);
  if (stepIdx < 0) return null;
  return {
    segments: ["Setup", PREFLIGHT_SEGMENT_LABELS[kind]],
    currentStep: stepIdx + 1,
    totalSteps: PREFLIGHT_STEP_ORDER.length,
  };
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

/**
 * Which sub-surface the shell is showing right now.
 *
 * Introduced by the Ink UI v2 "modules calmed" redesign so the shell can
 * carry a catalog / module home / findings / finding / tune screen without
 * needing a separate UIMode. `mode === "shell"` && `shellView` together
 * drive the dispatcher in App.tsx.
 */
export type ShellView = "catalog" | "module" | "findings" | "finding" | "tune";

/**
 * Rich per-module info used by the v2 ModuleCatalog and ModuleHome screens.
 * Populated once at shell init from `core.listModules()`; kept as a plain
 * struct (no functions) so the UI layer never needs to reach into the core.
 */
export interface ShellModuleCard {
  id: string;
  displayName: string;
  category: ModuleCategory;
  description: string;
  rank?: ModuleRank;
  /** Number of tools this module exposes. */
  toolCount: number;
  /** True for packages loaded via `--load package:` (shown in EXTERNAL group). */
  external?: boolean;
  /** Unix epoch ms of the most recent run for this module; undefined = never run. */
  lastRunAt?: number;
  /** Human-readable one-liner summary of the last run (e.g. "ran 2h · 4 tp"). */
  lastRunSummary?: string;
  /** Tools this module exposes — pre-enumerated at shell init for ModuleHome. */
  toolSummaries?: ReadonlyArray<ShellModuleToolSummary>;
}

export interface ShellModuleToolSummary {
  /** Fully qualified name, e.g. "sast:scan". */
  name: string;
  /** Short verb — the text after the colon, rendered as the primary column. */
  verb: string;
  /** One-liner from the tool's `description`. */
  description: string;
  /** Tool runs in non-interactive / run mode. */
  headless: boolean;
}

/**
 * Lightweight view of the user's config, sliced down to the six controls the
 * v2 Tune screen renders. Read-only; edits still go through the full
 * ConfigEditor (opened via `p` / `/config`).
 */
export interface TuneSnapshot {
  /** e.g. "fast" | "standard" | "deep" — `scan --preset <name>` */
  preset?: string;
  /** Enabled task IDs from config.tasks. */
  tasks: string[];
  /** config.verify — whether the verify phase runs. */
  verify: boolean;
  /** config.autoPatchEnabled — whether auto-patch runs. */
  autoPatch: boolean;
  /** config.triageConcurrency — how many triage tasks in-flight. */
  triageConcurrency: number;
  /** config.model — default model identifier. */
  model: string;
  /** Optional operator house rules (contents of .kuzushi/house-rules/<id>.md). */
  houseRules?: string;
  /** Absolute path of the house-rules file, shown under the textarea. */
  houseRulesPath?: string;
}

export interface ShellState {
  /** Loaded module IDs. */
  modules: string[];
  /** Rich module info for the v2 catalog — populated at shell init. */
  moduleCatalog?: ShellModuleCard[];
  /** Available tool names. */
  tools: string[];
  /** Currently focused module (for shorthand commands). */
  focusedModule: string | null;
  /** Sub-surface within the shell (catalog / module / findings / finding / tune). */
  shellView: ShellView;
  /** When shellView === "finding", which finding ID is open (e.g. "F-0216"). */
  openFindingId: string | null;
  /** Active target. */
  target: string | null;
  /** Workspace ID. */
  workspace: string | null;
  /** Narrow projection of the user's config used by the v2 Tune screen. */
  tuneSnapshot?: TuneSnapshot;
  /**
   * Pending NL-planner proposal awaiting operator confirmation. While set,
   * the shell renders the PlanCard and routes `y` / `n` / Esc keys to
   * apply / revise / cancel.
   */
  pendingPlan?: ShellPlan | null;
  /** True while the planner LLM call is in flight. */
  plannerBusy?: boolean;
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

/**
 * Hard cap on `agentActivity` map size. Long-running shell/scan sessions can
 * emit activity for thousands of distinct fingerprints; without a cap the map
 * grows unboundedly and retains display strings that no longer matter.
 */
const MAX_AGENT_ACTIVITY_ENTRIES = 1000;

/** Default TTL for stale-activity eviction (seconds). */
const DEFAULT_AGENT_ACTIVITY_TTL_SEC = 600; // 10 minutes

export class UIStore {
  private state: UIState;
  private listeners = new Set<Listener>();
  private preflightReturnMode: UIMode = "running";
  private reviewReturnMode: UIMode = "summary";
  private agentActivityTimestamps = new Map<string, number>();

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
      costBreakdown: { triage: 0, verify: 0, poc: 0 },
      scanView: "pipeline",
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
      breadcrumb: null,
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
    const breadcrumb = preflight
      ? preflightBreadcrumb(preflight.kind)
      : this.state.mode === "preflight"
        ? null
        : (this.state.breadcrumb ?? null);
    this.state = {
      ...this.state,
      preflight,
      mode: preflight
        ? "preflight"
        : this.state.mode === "preflight"
          ? this.preflightReturnMode
          : this.state.mode,
      breadcrumb,
    };
    this.notify();
  }

  /**
   * Set (or clear) the wayfinding breadcrumb. Consumers can also rely on
   * `setPreflight` populating it automatically for preflight flows.
   */
  setBreadcrumb(breadcrumb: UIState["breadcrumb"]): void {
    this.state = { ...this.state, breadcrumb };
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
    const cost = result.costUsd ?? 0;
    const cb = { ...this.state.costBreakdown };
    if (result.kind === "triage") cb.triage += cost;
    else if (result.kind === "verify") cb.verify += cost;
    else if (result.kind === "poc") cb.poc += cost;

    this.state = {
      ...this.state,
      results: [...this.state.results, result],
      progress: { current: result.index, total: result.total },
      runningCostUsd: this.state.runningCostUsd + cost,
      costBreakdown: cb,
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
    this.agentActivityTimestamps.delete(fingerprint);
    this.agentActivityTimestamps.set(fingerprint, Date.now());

    while (newMap.size > MAX_AGENT_ACTIVITY_ENTRIES) {
      const oldest = newMap.keys().next();
      if (oldest.done || oldest.value === undefined) break;
      newMap.delete(oldest.value);
      this.agentActivityTimestamps.delete(oldest.value);
    }

    this.state = { ...this.state, agentActivity: newMap };
    this.notify();
  }

  clearAgentActivity(fingerprint: string): void {
    const newMap = new Map(this.state.agentActivity);
    newMap.delete(fingerprint);
    this.agentActivityTimestamps.delete(fingerprint);
    this.state = { ...this.state, agentActivity: newMap };
    this.notify();
  }

  /**
   * Drop `agentActivity` entries older than `maxAgeSec` seconds.
   * Called at phase boundaries or on a timer; non-destructive if nothing expired.
   */
  clearStaleActivity(maxAgeSec: number = DEFAULT_AGENT_ACTIVITY_TTL_SEC): void {
    const cutoff = Date.now() - maxAgeSec * 1000;
    let changed = false;
    const newMap = new Map(this.state.agentActivity);
    for (const [fingerprint, insertedAt] of this.agentActivityTimestamps) {
      if (insertedAt < cutoff) {
        newMap.delete(fingerprint);
        this.agentActivityTimestamps.delete(fingerprint);
        changed = true;
      }
    }
    if (!changed) return;
    this.state = { ...this.state, agentActivity: newMap };
    this.notify();
  }

  /**
   * Drop every `agentActivity` entry. Intended for phase boundaries (e.g. scan
   * -> triage -> verify) where prior-phase fingerprints are no longer relevant.
   */
  resetAgentActivity(): void {
    if (this.state.agentActivity.size === 0 && this.agentActivityTimestamps.size === 0) {
      return;
    }
    this.agentActivityTimestamps.clear();
    this.state = { ...this.state, agentActivity: new Map() };
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

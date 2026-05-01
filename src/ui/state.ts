/**
 * Observable UI state store.
 *
 * The report-worker writes state updates via `store.update()`.
 * The Ink app subscribes via `store.subscribe()` and re-renders reactively.
 */

import type { ThreatModelDocument } from "../agents/tasks/threat-modeling/types.js";
import type { ShellPlan } from "../copilot/nl-planner.js";
import type { ModuleCategory, ModuleRank } from "../modules/types.js";
import type { VendorAssessmentHomeSlice } from "../modules/vendor-assessment/types.js";
import type { ThreatModelPatchProposal } from "../threat-model-patch.js";

// Re-export so the UI layer can `import type { ShellPlan } from "../state.js"`
// without cross-cutting into `src/copilot/`.
export type { ShellPlan, ShellPlanChange } from "../copilot/nl-planner.js";

import type { ConfigPatchEntry } from "../config.js";
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
import type { ConfigConfirmData, CredentialChoice, WizardResult } from "./preflight-types.js";
import type { ResumeDiffData } from "./resume-types.js";
import type { ShellStoryEvent, ShellTaskStoryState } from "./task-story.js";

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
  /**
   * O3: epoch-ms timestamp of when this activity line was emitted. Optional
   * for backward compat — older callers may omit it; consumers should fall
   * back to "no pause-line render" rather than failing. ModuleRunView's
   * ActorsBlock uses this to surface "waiting on actor N of M — last
   * activity Ys ago" when the latest line is older than a stalled-actor
   * threshold.
   */
  tsMs?: number;
}

/**
 * Frozen copy of a single per-actor hunt run, captured on the `done:true`
 * activity event before `clearAgentActivity` drops the fingerprint. Powers
 * the `hunt-post-mortem` scrollback block — operators can expand it after
 * the run to see which actor made the last move and what that move was.
 */
export interface HuntActorSnapshot {
  fingerprint: string;
  lines: AgentActivityLine[];
  archivedAt: number;
}

/**
 * One sub-step in the rolling tail shown beneath a running shell tool.
 * Timestamps drive "just now / 5s ago" relative-age labels.
 */
export interface ToolActivityLine {
  text: string;
  ts: number;
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
  /**
   * Per-actor fingerprint stamped by `carlini-threat-hunt` so the v3
   * `ActorTranscriptView` can synthesize ★ Finding rows for completed and
   * replayed runs. Optional — non-actor findings leave it undefined.
   */
  actorFingerprint?: string;
  /**
   * Stable, durable id for the finding, separate from the (per-run-derived)
   * fingerprint used by the deduper. Operators rely on this for issue
   * trackers and suppression rules; it MUST survive scanner refactors that
   * legitimately change the fingerprint. Optional for backwards-compat —
   * when missing the fingerprint is the canonical id.
   */
  id?: string;
  /** CWE identifiers attributed to this finding (e.g. `["CWE-918", "CWE-601"]`). */
  cwe?: string[];
  /** Optional one-line remediation hint surfaced in PR comments / CI output. */
  remediation?: string;
  /** External references (vendor docs, OWASP, advisory URLs). */
  references?: string[];
  /** True when the finding is suppressed from PR / dashboard surfaces. */
  suppressed?: boolean;
  /** Deferred-until timestamp (ISO 8601). */
  snoozedUntil?: string;
  /** First time this finding was observed in this repo (ISO 8601). */
  firstSeenAt?: string;
  /**
   * Calibrated confidence score `[0, 1]` separate from triage `confidence`
   * so post-processors (rescore, corroboration) can write through without
   * trampling triage's raw output. Optional.
   */
  confidenceScore?: number;
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
  /** Expand the B1 heartbeat strip into a per-agent list. Default true. */
  heartbeatExpanded?: boolean;
  /**
   * Expand the B2 NoticeRail from its collapsed rollup header into the
   * full per-notice list. Errors always render full regardless of this
   * flag. Default false.
   */
  noticeRailExpanded?: boolean;
  /**
   * Timestamp (epoch ms) of the first press of the two-stage Ctrl+C.
   * When set and within CTRL_C_ARM_WINDOW_MS, a second press exits;
   * otherwise the armed state decays silently. B.4.
   */
  ctrlCArmedAt?: number;
  /**
   * True when the pipeline has crossed the cost budget and is awaiting
   * operator confirmation to continue or abort. B.4.
   */
  costCapHalted?: boolean;
  /** Optional budget snapshot the CostCapHalt card renders from. */
  costCapBudgetUsd?: number;
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
    budget?: number;
    scanMode?: string;
  } | null;
  results: ResultLine[];
  agentActivity: Map<string, AgentActivityLine[]>;
  /**
   * Completed per-actor activity snapshots from the most recent hunt run.
   * `archiveAgentActivity()` moves a fingerprint's final lines here before
   * clearing them from `agentActivity`, so the shell can emit a
   * `hunt-post-mortem` scrollback block summarising the run once the tool
   * resolves. Cleared by `consumeHuntSnapshot()` at dispatch-finally time.
   */
  lastHuntSnapshot: HuntActorSnapshot[];
  summary: SummaryData | null;
  qualityGate: QualityGateResult | null;
  notices: UINotice[];
  warnings: string[];
  bannerShown: boolean;
  /** True once the interactive shell welcome splash has been rendered. */
  shellSplashShown: boolean;
  compactBannerShown?: boolean;
  startBannerShown: boolean;
  /** Resume diff data — shown when resuming a previous run. */
  resumeDiff?: ResumeDiffData | null;
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
  type: "input" | "output" | "error" | "tool-progress" | "tool-call" | "hunt-post-mortem" | "story";
  text: string;
  timestamp: number;
  prompt?: string;
  /**
   * Optional stable id so tool-call entries can be mutated in place (e.g.
   * flipping the `⏺` from cyan→green on resolution, or filling in a
   * per-tool `renderResult` line). Any entry with `id` set is excluded
   * from `<Static>` until its `status` becomes terminal.
   */
  id?: string;
  /**
   * For `tool-call` entries seeded from an agent `tool_use` block: the
   * Anthropic-side tool_use id. Used to correlate with later
   * `tool-progress` / `tool-summary` events so agent-driven `⏺` entries
   * flip running → ok on resolution.
   */
  toolUseId?: string;
  /** For `tool-call`: qualified tool name (e.g. `context:build`). */
  tool?: string;
  /** For `tool-call`: human-friendly label rendered instead of `tool` when set. */
  displayName?: string;
  /** For `tool-call`: ≤40-char input summary rendered as `(…)`. */
  inputHint?: string;
  /**
   * For `tool-call`: lifecycle status driving the `⏺` glyph color.
   * - `running` (cyan, pulsing)
   * - `ok` (green static)
   * - `fail` (red static)
   * - `abort` (muted static)
   */
  status?: "running" | "ok" | "fail" | "abort";
  /**
   * For `tool-call`: elapsed seconds at resolution. Rendered as ` · Xs`
   * after the header once status leaves `running`.
   */
  elapsedSeconds?: number;
  /**
   * For `tool-call`: per-tool result summary (from `ModuleTool.renderResult`)
   * rendered as a `⎿  <text>` line directly under the header when the tool
   * resolves. Falls back to `"✓ done" / "✗ failed" / "· aborted"`.
   */
  resultOutput?: string;
  /** Structured task-story beat for story rows and story-backed progress/tool rows. */
  storyEvent?: ShellStoryEvent;
  /** Immediate abort receipt while cleanup is still unwinding. */
  abortStatus?: ShellTaskStoryState["abortStatus"];
  /**
   * For `tool-call` while `running`: rolling tail of activity lines
   * (latest at index 0). Shown beneath the `⏺` header as dim `⎿ <activity>`
   * lines until the tool resolves.
   *
   * Each row carries a stable `id` so Ink/React can keep line identity
   * across prepends; this avoids remount churn/flicker while progress
   * pulses stream in.
   */
  liveActivities?: Array<{ id: string; text: string }>;
  /** Older live activity lines dropped from the bounded in-memory tail. */
  liveActivitiesDropped?: number;
  /**
   * For `tool-progress`: status hint — success/failure/stale colorization.
   *
   * - `info` (default): free-form activity pulse ("scanning repo structure"),
   *   rendered muted like body text.
   * - `invocation`: a nested sub-agent tool-use header ("Read · path.ts" /
   *   "Glob \"*.go\" (300 files)"), rendered in base text like the parent
   *   `⏺` tool-call row — opencode/Claude Code convention.
   * - `ok` / `fail` / `abort`: terminal result of a shell-dispatched tool,
   *   colored green/red accordingly.
   */
  progressKind?: "info" | "invocation" | "ok" | "fail" | "abort";
  /**
   * For `hunt-post-mortem`: aggregated summary of the completed run —
   * collapsed `N actors · M findings · $X.XX` headline with per-actor
   * detail lines hidden behind `space to expand`. Consumed from
   * `state.lastHuntSnapshot` at tool-dispatch finally-block time, so this
   * stays fixed even if a subsequent hunt mutates the live map.
   */
  huntSummary?: {
    actorCount: number;
    findingsCount: number;
    costUsd: number;
    perActor: HuntActorSnapshot[];
  };
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
  /** Which optional context steps were enabled when generated. */
  options: { enrichment: boolean; threatModel?: boolean; scenarios?: boolean };

  // --- Single-project context (discovery=flat, or auto with single project) ---
  /** RepoContext from context-gatherer (languages, frameworks, auth, entry points). */
  repoContext?: unknown;
  /** FileIndex from context-gatherer (file tree, security pattern matches). */
  fileIndex?: unknown;
  /** Enrichment object from context-enricher (custom middleware, sanitizers, trust boundaries). */
  enrichedContext?: unknown;
  /** ApplicationModel from app-model-build (routes, outbound clients, data stores, jobs). */
  appModel?: unknown;
  /** Legacy snapshots may contain an embedded threat model; new runs persist via threat-model. */
  threatModel?: unknown;
  /** Legacy snapshots may contain embedded scenarios; new runs persist via threat-model. */
  scenarios?: unknown[];
  /** Generated slices included in the most recent context operation. */
  generatedSlices?: ContextGenerationSlice[];
  /** Slices that should be considered stale after a partial regeneration. */
  staleSlices?: ContextGenerationSlice[];

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
export type ShellView =
  | "catalog"
  | "module"
  | "findings"
  | "finding"
  | "since"
  | "tune"
  | "options"
  | "sast-tasks"
  // Threat model uses one view with shell.threatTab selecting the sub-surface.
  | "threats"
  // Live Build — ContextBuildView renders the 5 phases of
  // `gatherContextForRoot` (manifests → walk → path signals → grep sweep →
  // assemble) plus a pillar preview that fills in as signals land. Entered
  // via `/context build`; reads from `shell.contextBuild`.
  | "context-build"
  | "task-story"
  // ModuleRunView — Claude-Code-style live transcript for the focused
  // module's active tool run. Reads from `shell.moduleRun`.
  | "module-run"
  // ActorTranscriptView — full per-actor transcript drilled into from a
  // ModuleRunView. Reads from `shell.agentActivity[shell.focusedActor]`.
  | "actor-detail"
  // PromptsEditorView — list + verbs (edit, show, diff, reset, set) for
  // the focused module's prompt overrides.
  | "prompts-editor"
  // KbView — the focused module's knowledge base (operator-attached files).
  // Reads from `shell.kbState[shell.kb.moduleId]` (see `src/modules/_shared/
  // attachments/tools.ts:AttachmentsHomeSlice`). Entered via `/kb` or the
  // bare `attachments` verb inside a focused module.
  | "kb";

export type ThreatTab = "dfd" | "stride" | "stories" | "scope" | "summary";

export type ContextGenerationSlice = "all" | "repo" | "enrichment" | "app-model";

export type FindingScope =
  | { kind: "all" }
  | {
      kind: "changed-files";
      ref: string;
      repoRoot: string;
      changedFiles: string[];
      error?: string;
    };

export interface ActiveRunContext {
  runId: string;
  summaryPath?: string;
  aliasCount?: number;
}

export interface RunReadiness {
  blockers: Array<{
    kind: "auth" | "target" | "context" | "threat-model" | "budget-model";
    message: string;
    action?: string;
  }>;
}

/**
 * Phases of the deterministic `gatherContextForRoot` pipeline, mirrored in
 * `ContextBuildView`'s phase tracker. Kept in sync with
 * `BuildPhaseId` in `src/agents/tasks/context-gatherer.ts`.
 */
export type ContextBuildPhaseId = "manifests" | "walk" | "path-signals" | "grep" | "assemble";

export interface ContextBuildPhaseSlice {
  status: "pending" | "running" | "done" | "failed";
  startedAtMs?: number;
  durationMs?: number;
}

export interface ContextBuildGrepDomainSlice {
  name: string;
  matches: number;
  status: "pending" | "active" | "capped" | "skipped-no-ext";
}

/**
 * Live state for the `/context build` Ink view. A fresh instance is seeded
 * via `initContextBuildState()` when the command is invoked; phase observer
 * events then drive incremental updates until the run terminates.
 */
export interface ContextBuildState {
  /** 4-char id shown as "run 9a21" in the view header. */
  runId: string;
  repoRoot: string;
  startedAtMs: number;
  /** Terminal status. While "running", the view's live indicators animate. */
  status: "running" | "done" | "failed" | "aborted";
  phases: Record<ContextBuildPhaseId, ContextBuildPhaseSlice>;
  manifests: Partial<
    Record<
      "package.json" | "go.mod" | "pyproject" | "Cargo.toml" | "native-build",
      "found" | "miss"
    >
  >;
  walk?: { entries: number; dirs: number; sourceFiles: number; cap: number };
  pathSignals: ReadonlyArray<string>;
  grep?: {
    filesDone: number;
    filesTotal: number;
    workers: number;
    domainCap: number;
    domains: ReadonlyArray<ContextBuildGrepDomainSlice>;
  };
  /** Minimal pillar preview — gather-phase signals only; LLM-sourced pillars
   * ("scope", "historical") are rendered as placeholders in the view. */
  pillars: {
    architecture: {
      languages: ReadonlyArray<string>;
      frameworks: ReadonlyArray<string>;
      entryPoints: ReadonlyArray<string>;
      ormOrDb: ReadonlyArray<string>;
    };
    trust: {
      sanitizationLibs: ReadonlyArray<string>;
      authPatterns: ReadonlyArray<string>;
    };
  };
  tail: ReadonlyArray<{ tsMs: number; message: string; kind?: "info" | "warn" }>;
  tailExpanded: boolean;
  errorMessage?: string;
  /** Absolute path to the written `.kuzushi/scan-context.json`, once assembled. */
  scanContextPath?: string;
  /** Total grep matches across all domains, populated on assemble. */
  totalMatches?: number;
}

const ORDERED_BUILD_PHASES: ReadonlyArray<ContextBuildPhaseId> = [
  "manifests",
  "walk",
  "path-signals",
  "grep",
  "assemble",
];

export function initContextBuildState(
  repoRoot: string,
  now: number = Date.now(),
): ContextBuildState {
  const phases = {} as Record<ContextBuildPhaseId, ContextBuildPhaseSlice>;
  for (const id of ORDERED_BUILD_PHASES) phases[id] = { status: "pending" };
  return {
    runId: generateRunId(now),
    repoRoot,
    startedAtMs: now,
    status: "running",
    phases,
    manifests: {},
    pathSignals: [],
    pillars: {
      architecture: { languages: [], frameworks: [], entryPoints: [], ormOrDb: [] },
      trust: { sanitizationLibs: [], authPatterns: [] },
    },
    tail: [],
    tailExpanded: false,
  };
}

function generateRunId(now: number): string {
  // Short deterministic-looking 4-char hex derived from the timestamp + a
  // small random nibble — mirrors the "run 9a21" pattern in the design.
  const high = (now & 0xffff).toString(16).padStart(4, "0");
  const salt = Math.floor(Math.random() * 0xf).toString(16);
  return high.slice(0, 3) + salt;
}

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
  /**
   * Severity counts from the most recent contributing run, e.g.
   * `{ critical: 0, high: 2, medium: 5, low: 1, info: 0 }`. Undefined when no
   * run exists for this module or `metrics_json` was unparseable. Rendered as
   * a sparkline in the catalog's `LAST RUN` column.
   */
  lastRunSeverityCounts?: Record<string, number>;
  /** Best current run action surfaced by ModuleCatalog/ModuleHome. */
  runState?: {
    kind: "resume" | "complete";
    runId: string;
    summary: string;
    actions: ReadonlyArray<string>;
  };
  /** Tools this module exposes — pre-enumerated at shell init for ModuleHome. */
  toolSummaries?: ReadonlyArray<ShellModuleToolSummary>;
}

/**
 * One step in the ModuleRunView "Steps" block. The renderer maps `status`
 * → `STEP_GLYPH` (`✓` done, `→` running, `○` pending). `count` and
 * `elapsedSeconds` are advisory and right-aligned when present.
 */
export interface ModuleRunStep {
  id: string;
  title: string;
  status: "pending" | "running" | "done" | "error";
  /** Optional right-aligned counter — e.g. "3/5 actors" or "12 paths". */
  count?: string;
  /** Optional right-aligned elapsed seconds when the row is done/running. */
  elapsedSeconds?: number;
  /** Optional error message rendered under a failed row. */
  error?: string;
}

/** One artifact row rendered under the ModuleRunView "Artifacts" section. */
export interface ModuleRunArtifact {
  label: string;
  path: string;
  /** Optional bytes/size annotation rendered to the right. */
  size?: string;
}

/**
 * Snapshot of the active or most recent module run, owned by the shell so
 * the new ModuleRunView can render without needing to hit the bus or the
 * datastore. Populated by the report-worker when it sees agent activity
 * and tool lifecycle for the focused module.
 */
export interface ModuleRunSlice {
  /** Module that owns this run (matches `shell.focusedModule`). */
  moduleId: string;
  /** Presentation owner. Shell-owned runs keep the app in `mode="shell"`. */
  source?: "shell";
  /** Run-id from the bus (mirrors `shell.activeRun?.runId` when known). */
  runId?: string;
  /** Tool currently running, e.g. `"carlini-threat-hunt:run"`. */
  toolName?: string;
  /** Operator-friendly display name from `ModuleTool.displayName`. */
  displayName?: string;
  /** Pre-formatted input summary from the tool's `formatInput`, if any. */
  inputSummary?: string;
  /** Live queue-level control support declared by the running tool. */
  liveControl?: "pause-resume";
  /** Epoch ms the run started — drives the live elapsed counter. */
  startedAtMs: number;
  /** Epoch ms when the run reached a terminal state; freezes elapsed rendering. */
  completedAtMs?: number;
  /** Lifecycle status for the run as a whole. */
  status: "running" | "done" | "error" | "aborted";
  /** Pipeline post-processing mode, when this run is pipeline-backed. */
  postProcessMode?: "full" | "scan-only";
  /** Currently active scan/DAG task label, if the run is pipeline-backed. */
  activeTaskLabel?: string;
  /** Aggregate findings observed for this run. */
  findingCount?: number;
  /** Review candidates emitted when the agent/backend did not confirm findings. */
  reviewCandidateCount?: number;
  /** Agent runtime backend used by the focused module run. */
  agentRuntimeBackend?: string;
  /** Normalized agent output status such as valid-json or invalid-json. */
  agentStatus?: string;
  /** Deterministic candidate count reported by hunt-class module tools. */
  candidateCount?: number;
  /** Deterministic linked source-to-sink/control story count. */
  linkedStoryCount?: number;
  /** Backend path evidence count. */
  backendPathCount?: number;
  /** Number of warnings surfaced by the module result. */
  warningCount?: number;
  /** Explicit session model override used for this run, when set. */
  model?: string;
  /** Effort tier (low/medium/high/max/xhigh) the run resolved to, when set. */
  effort?: string;
  /** Whether thinking was force-disabled for this run (KUZUSHI_DISABLE_THINKING or proxy). */
  thinkingDisabled?: boolean;
  /** Step rows in display order (top-to-bottom). */
  steps: ReadonlyArray<ModuleRunStep>;
  /**
   * Recent activity tail flattened across all fingerprints — ring buffer
   * trimmed by the report-worker. Rendered as the "Evidence" table.
   */
  evidenceTail: ReadonlyArray<AgentActivityLine>;
  /** Aggregate cost for this run, in USD. */
  costUsd?: number;
  /** Artifacts produced — paths the operator may want to crack open. */
  artifacts?: ReadonlyArray<ModuleRunArtifact>;
}

/**
 * After-vim confirmation state for the PromptsEditorView. The
 * "Saved prompt override" card renders while `lastSavedAt` is fresh
 * (within ~5s); the editor view also reads pre-computed audit rows
 * from `audit` (populated when the operator opens the view).
 */
export interface PromptsEditorSlice {
  /**
   * Cached audit rows for the focused module. Re-populated by the shell
   * router on entry to `shellView === "prompts-editor"` so the renderer
   * doesn't need a `CopilotCore` handle.
   */
  audit?: ReadonlyArray<{
    moduleId: string;
    toolName: string;
    verb: string;
    promptKey: string;
    effective: {
      source: "default" | "inline" | "file" | "unset";
      filePath?: string;
      byteLen?: number;
      rawValue?: string;
    };
  }>;
  lastSavedAt?: number;
  lastSaved?: {
    /** Verb that was edited (e.g. "triage"). */
    name: string;
    /** Absolute path of the override file. */
    path: string;
    /** File size in bytes. */
    size: number;
  };
}

export interface OptionsViewSlice {
  toolName: string;
  rows: ReadonlyArray<{
    optionName: string;
    valueLabel: string;
    defaultLabel: string;
    description: string;
    isSet: boolean;
  }>;
  taskSummary?: {
    stateLine: string;
    commands: string;
  };
  tip?: string;
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
  /** Resume behavior declared by the module SDK. */
  resumeMode?: "checkpoint" | "restart-only" | "none";
  /** Live queue-level control support for an active run. */
  liveControl?: "pause-resume";
  /**
   * True for DAG-internal nodes that should be filtered out of the default
   * ModuleHome tools table. Surfaces only via `/tools --all` or `/info <tool>`.
   * Mirrors `ModuleTool.hidden` — see `src/modules/types.ts`.
   */
  hidden?: boolean;
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

export interface ShellArtifactStatus {
  /** Unix epoch ms of the most recent best-effort shell rehydration pass. */
  refreshedAt: number;
  /** Filesystem target used for artifact reads; null for URL/non-file targets. */
  target: string | null;
  /** Context snapshot path inspected during rehydration. */
  contextSnapshotPath?: string;
  /** Threat model source path read during rehydration, when present. */
  threatModelPath?: string;
  /** Findings database path read during rehydration, when present. */
  findingsDbPath?: string;
  /** Number of persisted pipeline runs visible to the shell catalog. */
  runCount?: number;
  /** Actionable findings count from the hydrated summary/database. */
  findingsCount?: number;
  /** KB attachment manifest path inspected for the focused KB-enabled module. */
  kbPath?: string;
  /** Vendor-assessment draft scope path, when that module is focused. */
  vendorAssessmentScopePath?: string;
  /**
   * Non-fatal refresh issue. Artifact reads are deliberately best-effort so a
   * broken or missing sidecar file does not crash the shell renderer.
   */
  lastError?: string;
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
  /**
   * When `shellView === "actor-detail"`, the per-actor fingerprint to
   * render the transcript for (e.g. `"carlini-threat-hunt:Unauthenticated_User:0"`).
   * Optional / null when the drill-in is not active.
   */
  focusedActor?: string | null;
  /**
   * Live snapshot of the focused module's currently running (or most recent)
   * tool, populated by the report-worker. Drives the ModuleRunView header,
   * step rows, and Evidence/Findings/Cost/Artifacts blocks.
   */
  moduleRun?: ModuleRunSlice | null;
  /** Transient state for the PromptsEditorView's after-vim confirmation card. */
  promptsEditor?: PromptsEditorSlice | null;
  /** Cached rows for the focused tool options view. */
  optionsView?: OptionsViewSlice | null;
  /** Vendor assessment draft-scope summary for the custom module home. */
  vendorAssessment?: VendorAssessmentHomeSlice | null;
  /**
   * Knowledge-base attachments for KB-enabled modules (`threat-model`,
   * `context`, `carlini-threat-hunt`, `vendor-assessment`). Keyed by module id; each
   * entry is the slice produced by the shared attachment factory's
   * `buildHomeSlice`. Read by both the per-module `AttachmentsBlock` on
   * the module home view and the dedicated `/kb` view.
   */
  kbState?: Record<string, import("../modules/_shared/attachments/index.js").AttachmentsHomeSlice>;
  /**
   * Cursor + collapse state for the `/kb` view. Persists across `/back`
   * within a single shell session so the operator returns to the same row.
   */
  kb?: {
    moduleId: string;
    cursor: number;
    collapsed: boolean;
  } | null;
  /**
   * Cursor index into the (severity-sorted) loose-findings list rendered by
   * FindingsView. Driven by j/k/ArrowDown/ArrowUp/g/G/PgUp/PgDown at the
   * idle prompt when `shellView === "findings"`. Clamped to the list size
   * by the input handler; undefined means "anchor at top".
   */
  findingCursor?: number;
  /**
   * Page size for FindingsView virtualization and for PgUp/PgDown scroll
   * increments. Optional — FindingsView falls back to its own default when
   * unset. Operators don't tweak this today; kept as state so a future
   * terminal-size effect can thread the value through.
   */
  findingPageSize?: number;
  /** Cursor into the SAST task selector rows. */
  sastTaskCursor?: number;
  /** Active target. */
  target: string | null;
  /** Workspace display label. The execution workspace id stays in ShellOptions. */
  workspace: string | null;
  /** Narrow projection of the user's config used by the v2 Tune screen. */
  tuneSnapshot?: TuneSnapshot;
  /** Last best-effort artifact refresh used by catalog/status/readiness views. */
  artifactStatus?: ShellArtifactStatus | null;
  /**
   * Pending NL-planner proposal awaiting operator confirmation. While set,
   * the shell renders the PlanCard and routes `y` / `n` / Esc keys to
   * apply / revise / cancel.
   */
  pendingPlan?: ShellPlan | null;
  /** True while the planner LLM call is in flight. */
  plannerBusy?: boolean;
  /**
   * Loaded randori threat model — shared across all `threats` tabs.
   * Populated lazily on entry; null when no scan has produced a threat
   * model yet.
   */
  threatModel?: ThreatModelDocument | null;
  /** Selected tab when shellView === "threats". */
  threatTab?: ThreatTab;
  /** Selected DFD node/flow id for the attack-surface workspace. */
  threatDfdSelection?: string;
  /** True when the `/context regen` palette is open in threat/context views. */
  contextRegenPaletteOpen?: boolean;
  /** Pending AI-produced threat-model patch awaiting explicit accept/reject. */
  pendingThreatPatch?: ThreatModelPatchProposal | null;
  /** True when accepted in-memory edits have not yet been written. */
  threatModelDirty?: boolean;
  /**
   * Path the threat model snapshot came from (`.kuzushi/threat-model.json`
   * or a per-run fallback), used in the "loaded from … (modified Xh ago)"
   * hint at the top of threat views so staleness is visible.
   */
  threatModelSource?: { path: string; mtimeMs: number };
  /**
   * Diff-aware scope populated on `/since <ref>` — the list of repo-
   * relative paths that differ between HEAD and the operator-supplied
   * ref. Read by DiffSinceView to filter findings + threat elements.
   */
  diffSince?: {
    ref: string;
    repoRoot: string;
    changedFiles: string[];
    error?: string;
  } | null;
  /** Canonical findings scope. `diffSince` remains as compatibility storage for existing renderers. */
  findingScope?: FindingScope;
  /** Hydrated run context after replay/load, used by aliases and detail pages. */
  activeRun?: ActiveRunContext | null;
  /** Blocking setup issues for the next scan run. */
  runReadiness?: RunReadiness | null;
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
  /**
   * Live-build progress for the current `/context build` run. Seeded on
   * command entry by `initContextBuildState()`, then mutated by the phase
   * observer in `runContextBuildLive`. `null` when no build is active and no
   * completed build is being kept around for re-viewing.
   */
  contextBuild?: ContextBuildState | null;
  /** Transient assistant text streamed before the turn finalizes. */
  pendingAssistantText?: string;
  /** Whether the agent is currently processing a query. */
  processing: boolean;
  /**
   * Currently executing tool (shown as inline activity).
   * `startedAt` (epoch ms) lets the UI tick elapsed locally without poking
   * shell state every second. `elapsedSeconds` is a one-shot push from SDK
   * tool-progress messages that self-report elapsed time. `subLabel` is a
   * fine-grained phase ("phase 2 (S4 threats)") populated from
   * `task:phase-progress` bus events and reset whenever `name` changes.
   */
  currentTool?: {
    name: string;
    startedAt?: number;
    elapsedSeconds?: number;
    subLabel?: string;
    /** Current phase label from `task:phase-progress` (populated live). */
    phase?: string;
    /**
     * Epoch ms the current phase began. Used to compute per-phase elapsed
     * time so each phase entry in scrollback can be retroactively annotated
     * (e.g. "scanning repo structure · 3s") when the phase transitions.
     */
    phaseStartedAt?: number;
    /** Step index parsed from phase when formatted as "<label> (N/M)". */
    step?: number;
    /** Total step count parsed from phase when formatted as "<label> (N/M)". */
    total?: number;
    /** Rolling buffer of recent sub-steps (max 5, newest at index 0). */
    activities?: ToolActivityLine[];
    /** Rich recent story events for the active task card. */
    storyTail?: ShellStoryEvent[];
    /** Abort lifecycle for the active tool row. */
    abortStatus?: ShellTaskStoryState["abortStatus"];
    /** Epoch ms of the most recent event — feeds stale-spinner detection. */
    lastEventAt?: number;
    /**
     * Id of the `tool-call` history entry associated with this tool run.
     * Populated by `runToolFromDispatcher` so bus subscriptions can route
     * activity/phase lines into the entry's `liveActivities` tail.
     */
    historyEntryId?: string;
    /**
     * Human-friendly label (from `ModuleTool.displayName`) — surfaced
     * here too so the bottom status block can render "Scan" instead of
     * "sast:scan" without another lookup.
     */
    displayName?: string;
    /** Current shell turn this tool belongs to; used for story correlation. */
    turnId?: string;
    /** Current bus run id this tool belongs to; used for stale-event suppression. */
    runId?: string;
    /** Background job id if this tool has been detached through the jobs manager. */
    backgroundJobId?: string;
    /** Whether the tool is visible as a background task instead of active prompt work. */
    backgrounded?: boolean;
  };
  /** Progressive story for the active or most recent shell turn. */
  taskStory?: ShellTaskStoryState;
  /**
   * Rolling LLM-call heartbeat for the active turn — populated from
   * `llm:call-start/complete/error` bus events so the shell spinner can show
   * a second line like "· sonnet-4-6 · 2 calls · $0.03". Undefined until the
   * first LLM call of a turn; reset on new input and on turn completion.
   */
  llmHeartbeat?: {
    /** Calls started but not yet completed. */
    activeCalls: number;
    /** Calls that finished (complete or error). */
    completedCalls: number;
    /** Last model string observed on a start event. */
    latestModel?: string;
    /** Running total cost for this turn, in USD. */
    totalCostUsd: number;
  };
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

/** Minimum interval before duplicate scan activity can refresh heartbeat state. */
const SCAN_ACTIVITY_DUPLICATE_REFRESH_MS = 1000;

/**
 * Cap on `shell.moduleRun.evidenceTail` length. The view renders the
 * last ~8 rows, but we keep a few more in memory so the operator can
 * see what arrived just before the visible window.
 */
const MAX_MODULE_RUN_EVIDENCE = 32;

function sameActivityDisplayLine(a: AgentActivityLine, b: AgentActivityLine): boolean {
  return (
    a.kind === b.kind &&
    a.toolName === b.toolName &&
    a.detail === b.detail &&
    a.index === b.index &&
    a.total === b.total
  );
}

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
      lastHuntSnapshot: [],
      heartbeatExpanded: true,
      summary: null,
      qualityGate: null,
      notices: [],
      warnings: [],
      bannerShown: false,
      shellSplashShown: false,
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

  /**
   * Seed `shell.moduleRun` for the focused module — called on tool-start
   * by the dispatcher when the module exposes a v3 home renderer. Drops
   * any prior run for this module (operators only watch one at a time).
   */
  beginModuleRun(slice: ModuleRunSlice): void {
    if (!this.state.shell) return;
    this.state = {
      ...this.state,
      shell: { ...this.state.shell, moduleRun: slice },
    };
    this.notify();
  }

  /**
   * Patch fields onto `shell.moduleRun` (status, costUsd, artifacts, etc.).
   * No-op if no run is currently active.
   */
  patchModuleRun(patch: Partial<ModuleRunSlice>): void {
    const shell = this.state.shell;
    if (!shell?.moduleRun) return;
    this.state = {
      ...this.state,
      shell: { ...shell, moduleRun: { ...shell.moduleRun, ...patch } },
    };
    this.notify();
  }

  /** Replace the steps array on the active module run (idempotent reorder). */
  setModuleRunSteps(steps: ReadonlyArray<ModuleRunStep>): void {
    const shell = this.state.shell;
    if (!shell?.moduleRun) return;
    this.state = {
      ...this.state,
      shell: { ...shell, moduleRun: { ...shell.moduleRun, steps } },
    };
    this.notify();
  }

  /**
   * Push one row onto `shell.moduleRun.evidenceTail` — bounded ring buffer
   * of the last `MAX_MODULE_RUN_EVIDENCE` rows. Caller decides whether the
   * event belongs to the active run (we don't gate by toolName here).
   */
  pushModuleRunActivity(line: AgentActivityLine): boolean {
    const shell = this.state.shell;
    if (!shell?.moduleRun) return false;
    const previous = shell.moduleRun.evidenceTail[shell.moduleRun.evidenceTail.length - 1];
    if (previous && sameActivityDisplayLine(previous, line)) {
      return false;
    }
    const next = [...shell.moduleRun.evidenceTail, line].slice(-MAX_MODULE_RUN_EVIDENCE);
    this.state = {
      ...this.state,
      shell: { ...shell, moduleRun: { ...shell.moduleRun, evidenceTail: next } },
    };
    this.notify();
    return true;
  }

  /** Drop the active module run snapshot. Used on `/clear`. */
  clearModuleRun(): void {
    const shell = this.state.shell;
    if (!shell?.moduleRun) return;
    this.state = { ...this.state, shell: { ...shell, moduleRun: null } };
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

  addAgentActivity(fingerprint: string, line: AgentActivityLine): boolean {
    const newMap = new Map(this.state.agentActivity);
    const lines = newMap.get(fingerprint) ?? [];
    const previous = lines[lines.length - 1];
    if (previous && sameActivityDisplayLine(previous, line)) {
      return false;
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
    return true;
  }

  clearAgentActivity(fingerprint: string): void {
    const newMap = new Map(this.state.agentActivity);
    newMap.delete(fingerprint);
    this.agentActivityTimestamps.delete(fingerprint);
    this.state = { ...this.state, agentActivity: newMap };
    this.notify();
  }

  /**
   * Move a fingerprint's current activity lines into `lastHuntSnapshot`
   * before its `clearAgentActivity` drop. Called from the report-worker's
   * `handleAgentActivity` on `done:true` carlini-threat-hunt events — preserves the
   * per-actor breakdown for the post-mortem block even after `HeartbeatStrip`
   * stops rendering. No-op if the fingerprint has no active lines (e.g. an
   * actor that errored before its first activity tick).
   */
  archiveAgentActivity(fingerprint: string): void {
    const lines = this.state.agentActivity.get(fingerprint);
    if (!lines || lines.length === 0) return;
    const snapshot: HuntActorSnapshot = {
      fingerprint,
      lines: lines.slice(),
      archivedAt: Date.now(),
    };
    this.state = {
      ...this.state,
      lastHuntSnapshot: [...this.state.lastHuntSnapshot, snapshot],
    };
    this.notify();
  }

  /**
   * Read + clear `lastHuntSnapshot` in one shot. The shell's
   * direct-tool-dispatch `finally` block calls this when a hunt tool
   * resolves so the snapshot embeds in a `hunt-post-mortem` history entry
   * instead of leaking into the next tool's result rendering.
   */
  consumeHuntSnapshot(): HuntActorSnapshot[] {
    const snapshot = this.state.lastHuntSnapshot;
    if (snapshot.length === 0) return snapshot;
    this.state = { ...this.state, lastHuntSnapshot: [] };
    this.notify();
    return snapshot;
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
    let changed = false;
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
          if (
            task.lastEventAt != null &&
            now - task.lastEventAt < SCAN_ACTIVITY_DUPLICATE_REFRESH_MS
          ) {
            return task;
          }
          changed = true;
          return { ...task, lastEventAt: now };
        }
        const entry = { ...line, index: 0, total: 0 };
        const all = [...existing, entry];
        // Smart cap: keep narrative lines (reasoning, finding-preview,
        // tool-complete) and only the most recent tool-start/tool-progress.
        const activityLines = curateScanActivityLines(all, 4);
        changed = true;
        return { ...task, activityLines, lastEventAt: now };
      });
      return { ...s, subTasks: updated };
    });
    if (!changed) return;
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

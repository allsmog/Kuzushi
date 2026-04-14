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

export type Phase = "idle" | "scanning" | "triaging" | "verifying" | "poc" | "summary" | "done";

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
  kind: "tool-start" | "tool-progress" | "tool-complete" | "summary";
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
  corroboratingSignals: Array<{ taskId: string }>;
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
  phase: Phase;
  repoName: string;
  tasks: string[];
  totalFindings: number;
  selectedForTriage: number;
  skippedAlreadyTriaged: number;
  model: string;
  progress: { current: number; total: number };
  results: ResultLine[];
  agentActivity: Map<string, AgentActivityLine[]>;
  summary: SummaryData | null;
  qualityGate: QualityGateResult | null;
  warnings: string[];
  bannerShown: boolean;
  startBannerShown: boolean;
}

type Listener = () => void;

export class UIStore {
  private state: UIState;
  private listeners = new Set<Listener>();

  constructor() {
    this.state = {
      phase: "idle",
      repoName: "",
      tasks: [],
      totalFindings: 0,
      selectedForTriage: 0,
      skippedAlreadyTriaged: 0,
      model: "",
      progress: { current: 0, total: 0 },
      results: [],
      agentActivity: new Map(),
      summary: null,
      qualityGate: null,
      warnings: [],
      bannerShown: false,
      startBannerShown: false,
    };
  }

  getState(): UIState {
    return this.state;
  }

  update(partial: Partial<UIState>): void {
    this.state = { ...this.state, ...partial };
    this.notify();
  }

  addResult(result: ResultLine): void {
    this.state = {
      ...this.state,
      results: [...this.state.results, result],
      progress: { current: result.index, total: result.total },
    };
    this.notify();
  }

  addAgentActivity(fingerprint: string, line: AgentActivityLine): void {
    const newMap = new Map(this.state.agentActivity);
    const lines = newMap.get(fingerprint) ?? [];
    // Keep only latest 5 activity lines per finding to avoid clutter
    const updated = [...lines, line].slice(-5);
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

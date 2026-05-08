// ── Data Flow Diagram ──

export interface ThreatModelProvenance {
  source?: string;
  generatedAt?: string;
  model?: string;
  fallback?: boolean;
  notes?: string[];
}

export interface DfdNode {
  id: string;
  type: "external-entity" | "process" | "data-store";
  name: string;
  description: string;
  trustZone: string;
  evidenceAnchors?: EvidenceAnchor[];
  provenance?: ThreatModelProvenance;
}

/** Deprecated compatibility alias for older callers; graph v2 uses DfdNode. */
export type DfdElement = DfdNode;

export interface DfdFlow {
  id: string;
  name?: string;
  description: string;
  sourceId: string;
  targetId: string;
  protocol?: string;
  dataClassification?: string;
  trustBoundaryIds: string[];
  evidenceAnchors?: EvidenceAnchor[];
  provenance?: ThreatModelProvenance;
}

export interface TrustBoundary {
  id: string;
  name: string;
  innerZone: string;
  outerZone: string;
  crossingFlowIds: string[];
  evidenceAnchors?: EvidenceAnchor[];
  provenance?: ThreatModelProvenance;
}

// ── STRIDE ──

export type StrideCategory =
  | "spoofing"
  | "tampering"
  | "repudiation"
  | "information-disclosure"
  | "denial-of-service"
  | "elevation-of-privilege";

export type ThreatModelMethodology = "pasta" | "stride" | "dread";

/**
 * Evidence anchor tying a threat-model element or finding to a source location.
 *
 * This is the canonical definition. The `ModelEvidenceAnchor` alias in
 * `src/types.ts` re-exports this type for backward compatibility with
 * application-model and threat-scenario consumers.
 */
export interface EvidenceAnchor {
  filePath: string;
  startLine: number;
  endLine?: number;
  symbol?: string;
  description: string;
  snippet?: string;
  source?: string;
  provenance?: ThreatModelProvenance;
}

export interface ThreatModelReference {
  kind?: "source" | "sink" | "guard" | "sanitizer" | string;
  name?: string;
  elementId?: string;
  filePath?: string;
  startLine?: number;
  endLine?: number;
  symbol?: string;
  description?: string;
  snippet?: string;
  source?: string;
  provenance?: ThreatModelProvenance;
}

export interface StrideThreat {
  id: string;
  targetElementIds: string[];
  actorIds?: string[];
  entrypointIds?: string[];
  flowIds?: string[];
  category: StrideCategory;
  title: string;
  description: string;
  attackVector: string;
  preconditions: string[];
  impact: "critical" | "high" | "medium" | "low";
  likelihood: "high" | "medium" | "low";
  probability?: number;
  confidence?: "high" | "medium" | "low";
  existingMitigations: string[];
  missingMitigations: string[];
  relatedCwe: string[];
  affectedFiles: Array<{ filePath: string; startLine: number }>;
  evidenceAnchors?: EvidenceAnchor[];
  sources?: ThreatModelReference[];
  sinks?: ThreatModelReference[];
  guards?: ThreatModelReference[];
  sanitizers?: ThreatModelReference[];
  requiredCapabilities?: string[];
  provenance?: ThreatModelProvenance;
  /** Deprecated compatibility alias for older renderers/tests. */
  elementId?: string;
}

export interface DreadThreatScore {
  threatId: string;
  damage: number;
  reproducibility: number;
  exploitability: number;
  affectedUsers: number;
  discoverability: number;
  score: number;
  rating: "critical" | "high" | "medium" | "low";
  rationale: string[];
}

export interface DreadRiskScores {
  methodology: "dread";
  scale: "0-10";
  threats: DreadThreatScore[];
}

/**
 * Narrative layer overlaid on top of the DFD/STRIDE data, matching the
 * codex-cyber-style threat-model document (Overview; Trust boundaries &
 * assumptions with categorised inputs; Attack surface with attacker stories;
 * Criticality calibration; Out-of-scope).
 *
 * All fields are optional at the document level (populated by the Randori
 * narrative-synthesis stage) so older persisted models keep loading.
 */
export interface ThreatModelInputCategories {
  /** Inputs an external attacker can shape (repo content, network, PR body, …). */
  attackerControlled: string[];
  /** Inputs the trusted operator supplies (CLI flags, config, env vars, creds). */
  operatorControlled: string[];
  /** Inputs committed by developers (prompts, built-in tasks, tool policies). */
  developerControlled: string[];
  /** Upstream services / providers trusted by the application. */
  externalServices: string[];
  /** Isolation / sandbox guarantees and fallbacks. */
  sandboxBoundary: string[];
  /** Free-form assumptions under which the model holds. */
  assumptions: string[];
}

export interface ThreatModelAttackerStory {
  title: string;
  /** 2-4 sentence Alice-and-Bob narrative describing the attack. */
  narrative: string;
  /** How the attack is mitigated today (or what should mitigate it). */
  mitigation: string;
  /** Related StrideThreat.id values from `threats[]`. */
  threatIds?: string[];
}

export interface ThreatModelCriticalityBuckets {
  critical: string[];
  high: string[];
  medium: string[];
  low: string[];
}

export interface ThreatModelNarrative {
  /** 1-3 paragraph overview of the application's runtime and exposure. */
  overview: string;
  inputCategories: ThreatModelInputCategories;
  attackerStories: ThreatModelAttackerStory[];
  /** Concrete examples of what belongs in each severity bucket for this app. */
  criticalityBuckets: ThreatModelCriticalityBuckets;
  /** Classes of issues explicitly declared out-of-scope. */
  outOfScope: string[];
}

export interface ThreatModelDocument {
  version: "2.0" | string;
  /** Methodology selected by the operator for this normalized document. */
  methodology?: ThreatModelMethodology;
  dfd: {
    nodes: DfdNode[];
    flows: DfdFlow[];
    trustBoundaries: TrustBoundary[];
    /** Deprecated compatibility alias; canonical graph v2 uses `nodes`. */
    elements?: DfdElement[];
  };
  threats: StrideThreat[];
  summary: {
    total: number;
    bySeverity: Record<string, number>;
    byCategory: Record<StrideCategory, number>;
  };
  /** Narrative layer (Overview / Trust boundaries / Attacker stories / …). */
  narrative?: ThreatModelNarrative;
  /** Metadata about generated/fallback model construction. */
  provenance?: ThreatModelProvenance;
  /** Optional risk-prioritization overlay for methodologies such as DREAD. */
  riskScores?: DreadRiskScores;
  /** Operator annotations keyed by threat ID. */
  userAnnotations?: Record<string, string>;
  /** Operator-confirmed mitigations that the scanner should trust. */
  confirmedMitigations?: string[];
  /** Threat IDs the operator marked as not applicable — excluded from detection. */
  dismissedThreats?: string[];
  /** Whether this document has been edited by an operator. */
  userEdited?: boolean;
  /** ISO timestamp of last human edit. */
  lastEditedAt?: string;
}

// ── Config ──

export interface ThreatModelConfig {
  methodology: ThreatModelMethodology;
  model: string;
  maxElements: number;
  maxThreats: number;
  emitFindings: boolean;
  findingThreshold: string;
  /** Which Randori PASTA stages to run (default: s1-s4). */
  randoriStages: string[];
  /**
   * Reasoning effort passed to the runtime. `"max"` engages full extended
   * thinking on Opus, which Randori needs to enumerate threats without
   * confabulating against defended code.
   */
  effort?: import("../../../agent-runtime/types.js").AgentEffort;
  /**
   * Per-task wall-clock cap in milliseconds. When the timer fires we abort
   * the in-flight runtime.query so the pipeline progresses instead of
   * hanging on a silent SDK stall. `0` disables the cap.
   */
  wallClockBudgetMs: number;
}

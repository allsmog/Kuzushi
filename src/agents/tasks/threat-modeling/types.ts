// ── Data Flow Diagram ──

export interface DfdElement {
  id: string;
  type: "external-entity" | "process" | "data-store" | "data-flow";
  name: string;
  description: string;
  trustZone: string;
  source?: string;
  target?: string;
  protocol?: string;
  dataClassification?: string;
}

export interface TrustBoundary {
  id: string;
  name: string;
  innerZone: string;
  outerZone: string;
  crossingFlows: string[];
  evidenceAnchors?: EvidenceAnchor[];
}

// ── STRIDE ──

export type StrideCategory =
  | "spoofing"
  | "tampering"
  | "repudiation"
  | "information-disclosure"
  | "denial-of-service"
  | "elevation-of-privilege";

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
  description: string;
}

export interface StrideThreat {
  id: string;
  elementId: string;
  category: StrideCategory;
  title: string;
  description: string;
  attackVector: string;
  preconditions: string[];
  impact: "critical" | "high" | "medium" | "low";
  likelihood: "high" | "medium" | "low";
  existingMitigations: string[];
  missingMitigations: string[];
  relatedCwe: string[];
  affectedFiles: Array<{ filePath: string; startLine: number }>;
  evidenceAnchors?: EvidenceAnchor[];
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
  version: string;
  dfd: {
    elements: DfdElement[];
    trustBoundaries: TrustBoundary[];
  };
  threats: StrideThreat[];
  summary: {
    total: number;
    bySeverity: Record<string, number>;
    byCategory: Record<StrideCategory, number>;
  };
  /** Narrative layer (Overview / Trust boundaries / Attacker stories / …). */
  narrative?: ThreatModelNarrative;
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

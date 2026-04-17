import type { KuzushiConfig } from "../../../types.js";
import { isRecord } from "../../../utils.js";

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
}

export const DEFAULT_THREAT_MODEL_CONFIG: ThreatModelConfig = {
  model: "anthropic:claude-sonnet-4-6",
  maxElements: 50,
  maxThreats: 100,
  emitFindings: true,
  findingThreshold: "medium",
  randoriStages: ["s1", "s2", "s3", "s4"],
};

export function resolveThreatModelConfig(config: KuzushiConfig): ThreatModelConfig {
  const raw = config.taskConfig["threat-model"];
  if (!isRecord(raw)) return { ...DEFAULT_THREAT_MODEL_CONFIG, model: config.model };

  return {
    model: normalizeString(raw["model"] ?? raw["strideModel"], config.model),
    maxElements: normalizePositiveInt(raw["maxElements"], DEFAULT_THREAT_MODEL_CONFIG.maxElements),
    maxThreats: normalizePositiveInt(raw["maxThreats"], DEFAULT_THREAT_MODEL_CONFIG.maxThreats),
    emitFindings: normalizeBoolean(raw["emitFindings"], DEFAULT_THREAT_MODEL_CONFIG.emitFindings),
    findingThreshold: normalizeString(
      raw["findingThreshold"],
      DEFAULT_THREAT_MODEL_CONFIG.findingThreshold,
    ),
    randoriStages: normalizeStringArray(
      raw["randoriStages"],
      DEFAULT_THREAT_MODEL_CONFIG.randoriStages,
    ),
  };
}

// ── Helpers ──

function normalizeString(value: unknown, fallback: string): string {
  if (typeof value !== "string") return fallback;
  const trimmed = value.trim();
  return trimmed || fallback;
}

function normalizePositiveInt(value: unknown, fallback: number): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 1) return fallback;
  return Math.floor(numeric);
}

function normalizeBoolean(value: unknown, fallback: boolean): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.trim().toLowerCase() === "true") return true;
    if (value.trim().toLowerCase() === "false") return false;
  }
  return fallback;
}

function normalizeStringArray(value: unknown, fallback: string[]): string[] {
  if (!Array.isArray(value)) return fallback;
  const result = value.map((v) => String(v).trim()).filter(Boolean);
  return result.length > 0 ? result : fallback;
}

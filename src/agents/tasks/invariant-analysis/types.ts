import type { KuzushiConfig } from "../../../types.js";
import { isRecord } from "../../../utils.js";

export type InvariantKind =
  | "precondition"
  | "postcondition"
  | "class-invariant"
  | "loop-invariant"
  | "data-invariant"
  | "security-invariant";

export interface Invariant {
  id: string;
  kind: InvariantKind;
  scope: {
    filePath: string;
    startLine: number;
    endLine: number;
    functionName?: string;
    className?: string;
  };
  statement: string;
  formalExpression?: string;
  confidence: number;
  derivedFrom: string;
  securityRelevance: "high" | "medium" | "low" | "none";
  category?: string;
}

export interface InvariantDocument {
  version: string;
  invariants: Invariant[];
  coverage: {
    filesAnalyzed: number;
    functionsAnalyzed: number;
    invariantsFound: number;
  };
}

export interface InvariantViolation {
  invariantId: string;
  invariantStatement: string;
  violatingFilePath: string;
  violatingStartLine: number;
  violationDescription: string;
  severity: "ERROR" | "WARNING" | "INFO";
  confidence: number;
  cwe?: string;
  attackScenario?: string;
}

export interface InvariantAnalysisConfig {
  extractionModel: string;
  checkModel: string;
  maxInvariants: number;
  securityOnly: boolean;
  confidenceThreshold: number;
  checkBatchSize: number;
}

export const DEFAULT_INVARIANT_ANALYSIS_CONFIG: InvariantAnalysisConfig = {
  extractionModel: "anthropic:claude-sonnet-4-6",
  checkModel: "anthropic:claude-sonnet-4-6",
  maxInvariants: 200,
  securityOnly: true,
  confidenceThreshold: 0.4,
  checkBatchSize: 15,
};

export function resolveInvariantAnalysisConfig(config: KuzushiConfig): InvariantAnalysisConfig {
  const raw = config.scannerConfig["invariant-analysis"];
  if (!isRecord(raw)) return { ...DEFAULT_INVARIANT_ANALYSIS_CONFIG, extractionModel: config.model, checkModel: config.model };

  return {
    extractionModel: normalizeString(raw["extractionModel"], config.model),
    checkModel: normalizeString(raw["checkModel"], config.model),
    maxInvariants: normalizePositiveInt(raw["maxInvariants"], DEFAULT_INVARIANT_ANALYSIS_CONFIG.maxInvariants),
    securityOnly: normalizeBoolean(raw["securityOnly"], DEFAULT_INVARIANT_ANALYSIS_CONFIG.securityOnly),
    confidenceThreshold: normalizeUnitInterval(raw["confidenceThreshold"], DEFAULT_INVARIANT_ANALYSIS_CONFIG.confidenceThreshold),
    checkBatchSize: normalizePositiveInt(raw["checkBatchSize"], DEFAULT_INVARIANT_ANALYSIS_CONFIG.checkBatchSize),
  };
}

export const INVARIANT_EXTRACT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["invariants"],
  properties: {
    invariants: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "kind", "filePath", "startLine", "endLine", "statement", "confidence", "derivedFrom", "securityRelevance"],
        properties: {
          id: { type: "string" },
          kind: { type: "string", enum: ["precondition", "postcondition", "class-invariant", "loop-invariant", "data-invariant", "security-invariant"] },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          endLine: { type: "integer", minimum: 1 },
          functionName: { type: "string" },
          className: { type: "string" },
          statement: { type: "string" },
          formalExpression: { type: "string" },
          confidence: { type: "number", minimum: 0, maximum: 1 },
          derivedFrom: { type: "string" },
          securityRelevance: { type: "string", enum: ["high", "medium", "low", "none"] },
          category: { type: "string" },
        },
      },
    },
  },
} as const;

export const INVARIANT_CHECK_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["violations"],
  properties: {
    violations: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["invariantId", "invariantStatement", "violatingFilePath", "violatingStartLine", "violationDescription", "severity", "confidence"],
        properties: {
          invariantId: { type: "string" },
          invariantStatement: { type: "string" },
          violatingFilePath: { type: "string" },
          violatingStartLine: { type: "integer", minimum: 1 },
          violationDescription: { type: "string" },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          confidence: { type: "number", minimum: 0, maximum: 1 },
          cwe: { type: "string" },
          attackScenario: { type: "string" },
        },
      },
    },
  },
} as const;

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

function normalizeUnitInterval(value: unknown, fallback: number): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0 || numeric > 1) return fallback;
  return numeric;
}

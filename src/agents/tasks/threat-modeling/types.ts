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
}

// ── STRIDE ──

export type StrideCategory =
  | "spoofing"
  | "tampering"
  | "repudiation"
  | "information-disclosure"
  | "denial-of-service"
  | "elevation-of-privilege";

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
}

// ── PASTA Attack Trees ──

export interface AttackTreeNode {
  id: string;
  description: string;
  type: "AND" | "OR" | "LEAF";
  probability: number;
  impact: string;
  children: AttackTreeNode[];
  technique?: string;
  relatedFindings?: string[];
  relatedThreats?: string[];
}

export interface AttackTree {
  goal: string;
  rootNode: AttackTreeNode;
  overallRisk: "critical" | "high" | "medium" | "low";
}

export interface AttackSimulationDocument {
  version: string;
  trees: AttackTree[];
  summary: {
    totalTrees: number;
    criticalPaths: number;
  };
}

// ── Config ──

export interface ThreatModelConfig {
  strideModel: string;
  pastaModel: string;
  maxElements: number;
  maxThreats: number;
  maxTrees: number;
  emitFindings: boolean;
  findingThreshold: string;
}

export const DEFAULT_THREAT_MODEL_CONFIG: ThreatModelConfig = {
  strideModel: "anthropic:claude-sonnet-4-6",
  pastaModel: "anthropic:claude-sonnet-4-6",
  maxElements: 50,
  maxThreats: 100,
  maxTrees: 10,
  emitFindings: true,
  findingThreshold: "high",
};

export function resolveThreatModelConfig(config: KuzushiConfig): ThreatModelConfig {
  const raw = config.scannerConfig["threat-model"];
  if (!isRecord(raw)) return { ...DEFAULT_THREAT_MODEL_CONFIG, strideModel: config.model, pastaModel: config.model };

  return {
    strideModel: normalizeString(raw["strideModel"], config.model),
    pastaModel: normalizeString(raw["pastaModel"], config.model),
    maxElements: normalizePositiveInt(raw["maxElements"], DEFAULT_THREAT_MODEL_CONFIG.maxElements),
    maxThreats: normalizePositiveInt(raw["maxThreats"], DEFAULT_THREAT_MODEL_CONFIG.maxThreats),
    maxTrees: normalizePositiveInt(raw["maxTrees"], DEFAULT_THREAT_MODEL_CONFIG.maxTrees),
    emitFindings: normalizeBoolean(raw["emitFindings"], DEFAULT_THREAT_MODEL_CONFIG.emitFindings),
    findingThreshold: normalizeString(raw["findingThreshold"], DEFAULT_THREAT_MODEL_CONFIG.findingThreshold),
  };
}

// ── JSON Schemas ──

export const STRIDE_RESPONSE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["elements", "trustBoundaries", "threats"],
  properties: {
    elements: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "type", "name", "description", "trustZone"],
        properties: {
          id: { type: "string" },
          type: { type: "string", enum: ["external-entity", "process", "data-store", "data-flow"] },
          name: { type: "string" },
          description: { type: "string" },
          trustZone: { type: "string" },
          source: { type: "string" },
          target: { type: "string" },
          protocol: { type: "string" },
          dataClassification: { type: "string" },
        },
      },
    },
    trustBoundaries: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "name", "innerZone", "outerZone", "crossingFlows"],
        properties: {
          id: { type: "string" },
          name: { type: "string" },
          innerZone: { type: "string" },
          outerZone: { type: "string" },
          crossingFlows: { type: "array", items: { type: "string" } },
        },
      },
    },
    threats: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "elementId", "category", "title", "description", "attackVector", "impact", "likelihood"],
        properties: {
          id: { type: "string" },
          elementId: { type: "string" },
          category: { type: "string", enum: ["spoofing", "tampering", "repudiation", "information-disclosure", "denial-of-service", "elevation-of-privilege"] },
          title: { type: "string" },
          description: { type: "string" },
          attackVector: { type: "string" },
          preconditions: { type: "array", items: { type: "string" } },
          impact: { type: "string", enum: ["critical", "high", "medium", "low"] },
          likelihood: { type: "string", enum: ["high", "medium", "low"] },
          existingMitigations: { type: "array", items: { type: "string" } },
          missingMitigations: { type: "array", items: { type: "string" } },
          relatedCwe: { type: "array", items: { type: "string" } },
          affectedFiles: {
            type: "array",
            items: {
              type: "object",
              additionalProperties: false,
              required: ["filePath", "startLine"],
              properties: {
                filePath: { type: "string" },
                startLine: { type: "integer", minimum: 1 },
              },
            },
          },
        },
      },
    },
  },
} as const;

export const PASTA_RESPONSE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["trees"],
  properties: {
    trees: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["goal", "rootNode", "overallRisk"],
        properties: {
          goal: { type: "string" },
          overallRisk: { type: "string", enum: ["critical", "high", "medium", "low"] },
          rootNode: {
            type: "object",
            additionalProperties: false,
            required: ["id", "description", "type", "probability", "impact"],
            properties: {
              id: { type: "string" },
              description: { type: "string" },
              type: { type: "string", enum: ["AND", "OR", "LEAF"] },
              probability: { type: "number", minimum: 0, maximum: 1 },
              impact: { type: "string" },
              technique: { type: "string" },
              relatedFindings: { type: "array", items: { type: "string" } },
              relatedThreats: { type: "array", items: { type: "string" } },
              children: {
                type: "array",
                items: {
                  type: "object",
                  required: ["id", "description", "type", "probability", "impact"],
                  properties: {
                    id: { type: "string" },
                    description: { type: "string" },
                    type: { type: "string", enum: ["AND", "OR", "LEAF"] },
                    probability: { type: "number", minimum: 0, maximum: 1 },
                    impact: { type: "string" },
                    technique: { type: "string" },
                    relatedFindings: { type: "array", items: { type: "string" } },
                    relatedThreats: { type: "array", items: { type: "string" } },
                    children: { type: "array" },
                  },
                },
              },
            },
          },
        },
      },
    },
  },
} as const;

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

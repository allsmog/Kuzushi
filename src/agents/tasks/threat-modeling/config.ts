import type { AgentEffort } from "../../../agent-runtime/types.js";
import type { KuzushiConfig } from "../../../types.js";
import { isRecord } from "../../../utils.js";
import { normalizeThreatModelMethodology } from "./methodology.js";
import type { ThreatModelConfig } from "./types.js";

export type { ThreatModelConfig } from "./types.js";

// Randori defaults to Opus with max thinking — STRIDE enumeration on
// defended code reliably regresses to "everything is exploitable" on
// Sonnet without extended reasoning. Operators can downgrade via
// `taskConfig["threat-model"].model` / `.effort`.
export const DEFAULT_THREAT_MODEL_CONFIG: ThreatModelConfig = {
  methodology: "pasta",
  model: "anthropic:claude-opus-4-6",
  maxElements: 50,
  maxThreats: 20,
  emitFindings: true,
  findingThreshold: "medium",
  randoriStages: ["s1", "s2", "s3", "s4"],
  effort: "max",
  wallClockBudgetMs: 15 * 60_000,
};

export function resolveThreatModelConfig(config: KuzushiConfig): ThreatModelConfig {
  const raw = config.taskConfig["threat-model"];
  if (!isRecord(raw)) return { ...DEFAULT_THREAT_MODEL_CONFIG, model: config.model };

  return {
    methodology: normalizeThreatModelMethodology(
      raw["methodology"] ?? raw["modelType"] ?? raw["type"],
      DEFAULT_THREAT_MODEL_CONFIG.methodology,
    ),
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
    effort: normalizeEffort(raw["effort"], DEFAULT_THREAT_MODEL_CONFIG.effort),
    wallClockBudgetMs: normalizeNonNegativeInt(
      raw["wallClockBudgetMs"],
      DEFAULT_THREAT_MODEL_CONFIG.wallClockBudgetMs,
    ),
  };
}

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

function normalizeNonNegativeInt(value: unknown, fallback: number): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) return fallback;
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

function normalizeEffort(
  value: unknown,
  fallback: AgentEffort | undefined,
): AgentEffort | undefined {
  if (value === "low" || value === "medium" || value === "high" || value === "max") return value;
  return fallback;
}

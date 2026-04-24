import type { KuzushiConfig } from "../../../types.js";
import { isRecord } from "../../../utils.js";
import type { ThreatModelConfig } from "./types.js";

export type { ThreatModelConfig } from "./types.js";

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

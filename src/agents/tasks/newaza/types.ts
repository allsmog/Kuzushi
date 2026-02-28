import path from "node:path";
import { augurRoot as newazaRoot } from "@kuzushi/augur";
import type { KuzushiConfig } from "../../../types.js";
import { isRecord } from "../../../utils.js";

export type NewazaLanguage = "python" | "go" | "java" | "javascript" | "csharp";

export interface NewazaPassDefinition {
  passId: 1 | 2 | 3 | 4 | 5 | 6;
  passKey: string;
  focus: string;
  cwes: string[];
}

export interface NewazaTaskConfig {
  newazaPath: string;
  dbPath?: string;
  passes: Array<1 | 2 | 3 | 4 | 5 | 6>;
  labelingModel: string;
  extractionModel?: string;
  labelingBatchSize: number;
  labelingConfidenceThreshold: number;
  workspaceDir: string;
  codeqlBinary?: string;
  python3Binary: string;
  threads?: number;
  ram?: number;
  maxFindings?: number;
  codeqlApiProfile?: "auto" | string;
  codeqlProbeTimeoutMs?: number;
  codeqlProfileFallbacks?: boolean;
}

export interface NewazaCandidate {
  id: string;
  candidateKind: "source_candidate" | "sink_candidate";
  callable: string;
  flowKind: "param" | "argument" | "return" | "receiver" | "field" | "unknown";
  receiverHint?: string;
  moduleHint?: string;
  argIndex: number | null;
  locationFile: string;
  locationLine: number;
  snippet?: string;
}

export interface NewazaPassEntry {
  id: string;
  role: "source" | "sink" | "sanitizer" | "summary" | "none";
  classification: "tp" | "fp" | "candidate" | "unknown";
  confidence: number;
  signature: {
    package: string | null;
    module: string | null;
    type: string | null;
    callable: string;
    arg_index: number | null;
    flow_kind: "param" | "argument" | "return" | "receiver" | "field" | "unknown";
  };
  location: {
    file: string;
    line: number;
  };
  rationale: string;
  evidence?: string[];
}

export interface NewazaLabelsDocument {
  version: string;
  metadata: {
    run_id: string;
    generated_at: string;
    language: NewazaLanguage;
    framework: string | null;
    model: string;
    project: string;
    notes?: string[];
  };
  passes: Array<{
    pass_id: 1 | 2 | 3 | 4 | 5 | 6;
    focus: string;
    cwes: string[];
    entries: NewazaPassEntry[];
  }>;
}

export interface NewazaPreflightOutput {
  newazaPath: string;
  workspaceDir: string;
  dbPath: string;
  codeqlBinary: string;
  codeqlVersion: string;
  codeqlApiProfileId: string;
  language: NewazaLanguage;
  framework: string | null;
  referenceFiles: string[];
  passes: Array<1 | 2 | 3 | 4 | 5 | 6>;
  extraction: {
    sourcesQueryPath: string;
    sinksQueryPath: string;
    sourcesCsvPath: string;
    sinksCsvPath: string;
    sourcesRowCount: number;
    sinksRowCount: number;
  };
}

export interface NewazaLabelOutput {
  newazaPath: string;
  workspaceDir: string;
  dbPath: string;
  codeqlBinary: string;
  codeqlVersion: string;
  codeqlApiProfileId: string;
  language: NewazaLanguage;
  framework: string | null;
  passes: Array<1 | 2 | 3 | 4 | 5 | 6>;
  labelsPath: string;
  labels: NewazaLabelsDocument;
  reviewSummary: string;
  labelCounts: Record<string, number>;
}

export const NEWAZA_PASSES: NewazaPassDefinition[] = [
  { passId: 1, passKey: "path_traversal", focus: "Path Traversal", cwes: ["022", "023", "036", "073"] },
  { passId: 2, passKey: "command_injection", focus: "Command/Argument Injection", cwes: ["077", "078", "088"] },
  { passId: 3, passKey: "ssrf", focus: "SSRF", cwes: ["918", "099", "610"] },
  { passId: 4, passKey: "code_injection", focus: "Code Injection", cwes: ["094", "095"] },
  { passId: 5, passKey: "sql_injection", focus: "SQL Injection", cwes: ["089"] },
  { passId: 6, passKey: "unsafe_deserialization", focus: "Unsafe Deserialization", cwes: ["502"] },
];

const NEWAZA_PASS_IDS = new Set([1, 2, 3, 4, 5, 6]);

const DEFAULT_NEWAZA_PATH = normalizeDefaultNewazaPath();

export const DEFAULT_NEWAZA_TASK_CONFIG: NewazaTaskConfig = {
  newazaPath: DEFAULT_NEWAZA_PATH,
  dbPath: undefined,
  passes: [1, 2, 3, 4, 5, 6],
  labelingModel: "anthropic:claude-sonnet-4-6",
  extractionModel: undefined,
  labelingBatchSize: 20,
  labelingConfidenceThreshold: 0.55,
  workspaceDir: "./iris",
  codeqlBinary: undefined,
  python3Binary: "python3",
  threads: undefined,
  ram: undefined,
  maxFindings: undefined,
  codeqlApiProfile: "auto",
  codeqlProbeTimeoutMs: 20_000,
  codeqlProfileFallbacks: true,
};

function normalizeDefaultNewazaPath(): string {
  const envPath = process.env["NEWAZA_PATH"]?.trim();
  if (envPath) {
    return path.normalize(envPath);
  }

  return newazaRoot;
}

export function resolveNewazaConfig(config: KuzushiConfig): NewazaTaskConfig {
  const raw = config.scannerConfig["newaza"];
  const merged = isRecord(raw)
    ? { ...DEFAULT_NEWAZA_TASK_CONFIG, ...raw }
    : { ...DEFAULT_NEWAZA_TASK_CONFIG };

  return {
    newazaPath: normalizePath(merged["newazaPath"], DEFAULT_NEWAZA_TASK_CONFIG.newazaPath),
    dbPath: normalizeOptionalPath(merged["dbPath"]),
    passes: normalizePasses(merged["passes"]),
    labelingModel: normalizeString(merged["labelingModel"], config.model),
    extractionModel: normalizeOptionalString(merged["extractionModel"]),
    labelingBatchSize: normalizePositiveInt(merged["labelingBatchSize"], DEFAULT_NEWAZA_TASK_CONFIG.labelingBatchSize),
    labelingConfidenceThreshold: normalizeUnitInterval(
      merged["labelingConfidenceThreshold"],
      DEFAULT_NEWAZA_TASK_CONFIG.labelingConfidenceThreshold,
    ),
    workspaceDir: normalizePath(merged["workspaceDir"], DEFAULT_NEWAZA_TASK_CONFIG.workspaceDir),
    codeqlBinary: normalizeOptionalPath(merged["codeqlBinary"]),
    python3Binary: normalizeString(merged["python3Binary"], DEFAULT_NEWAZA_TASK_CONFIG.python3Binary),
    threads: normalizeOptionalPositiveInt(merged["threads"]),
    ram: normalizeOptionalPositiveInt(merged["ram"]),
    maxFindings: normalizeOptionalPositiveInt(merged["maxFindings"]),
    codeqlApiProfile: normalizeCodeqlApiProfile(merged["codeqlApiProfile"]),
    codeqlProbeTimeoutMs: normalizePositiveInt(
      merged["codeqlProbeTimeoutMs"],
      DEFAULT_NEWAZA_TASK_CONFIG.codeqlProbeTimeoutMs ?? 20_000,
    ),
    codeqlProfileFallbacks: normalizeBoolean(
      merged["codeqlProfileFallbacks"],
      DEFAULT_NEWAZA_TASK_CONFIG.codeqlProfileFallbacks ?? true,
    ),
  };
}

export function mapFrameworkToReference(framework: string): string | null {
  const normalized = framework.trim().toLowerCase();
  if (!normalized) {
    return null;
  }

  if (normalized.includes("fastapi")) return "fastapi";
  if (normalized.includes("django")) return "django";
  if (normalized.includes("flask")) return "flask";
  if (normalized.includes("gin")) return "gin";
  if (normalized.includes("echo")) return "echo";
  if (normalized.includes("spring")) return "spring";
  if (normalized.includes("express")) return "express";
  if (normalized.includes("asp.net") || normalized.includes("aspnet") || normalized.includes("api controller")) {
    return "aspnet";
  }

  return null;
}

export function normalizeNewazaLanguage(value: string): NewazaLanguage {
  const raw = value.trim().toLowerCase();
  if (raw.includes("python")) return "python";
  if (raw.includes("go")) return "go";
  if (raw.includes("javascript") || raw.includes("typescript") || raw === "js" || raw === "ts") {
    return "javascript";
  }
  if (raw.includes("java")) return "java";
  if (raw.includes("c#") || raw.includes("csharp")) return "csharp";
  return "javascript";
}

function normalizePasses(value: unknown): Array<1 | 2 | 3 | 4 | 5 | 6> {
  if (!Array.isArray(value)) {
    return [...DEFAULT_NEWAZA_TASK_CONFIG.passes];
  }

  const seen = new Set<1 | 2 | 3 | 4 | 5 | 6>();
  for (const item of value) {
    const asInt = Math.floor(Number(item));
    if (NEWAZA_PASS_IDS.has(asInt)) {
      seen.add(asInt as 1 | 2 | 3 | 4 | 5 | 6);
    }
  }

  if (seen.size === 0) {
    return [...DEFAULT_NEWAZA_TASK_CONFIG.passes];
  }

  return [...seen].sort((a, b) => a - b);
}

function normalizeOptionalPositiveInt(value: unknown): number | undefined {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 1) {
    return undefined;
  }

  return Math.floor(numeric);
}

function normalizePositiveInt(value: unknown, fallback: number): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 1) {
    return fallback;
  }

  return Math.floor(numeric);
}

function normalizeString(value: unknown, fallback: string): string {
  if (typeof value !== "string") {
    return fallback;
  }

  const trimmed = value.trim();
  return trimmed || fallback;
}

function normalizeOptionalPath(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }

  return path.normalize(trimmed);
}

function normalizePath(value: unknown, fallback: string): string {
  if (typeof value !== "string") {
    return fallback;
  }

  const trimmed = value.trim();
  return trimmed ? path.normalize(trimmed) : fallback;
}

function normalizeOptionalString(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed || undefined;
}

function normalizeCodeqlApiProfile(value: unknown): "auto" | string {
  if (typeof value !== "string") {
    return "auto";
  }

  const trimmed = value.trim();
  return trimmed || "auto";
}

function normalizeBoolean(value: unknown, fallback: boolean): boolean {
  if (typeof value === "boolean") {
    return value;
  }

  if (typeof value === "string") {
    const trimmed = value.trim().toLowerCase();
    if (trimmed === "true") {
      return true;
    }
    if (trimmed === "false") {
      return false;
    }
  }

  return fallback;
}

function normalizeUnitInterval(value: unknown, fallback: number): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0 || numeric > 1) {
    return fallback;
  }

  return numeric;
}

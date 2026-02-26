import path from "node:path";
import { augurRoot } from "@kuzushi/augur";
import type { KuzushiConfig } from "../../types.js";
import { isRecord } from "../../utils.js";

export type AugurLanguage = "python" | "go" | "java" | "javascript" | "csharp";

export interface AugurPassDefinition {
  passId: 1 | 2 | 3 | 4 | 5 | 6;
  passKey: string;
  focus: string;
  cwes: string[];
}

export interface AugurTaskConfig {
  augurPath: string;
  dbPath?: string;
  passes: Array<1 | 2 | 3 | 4 | 5 | 6>;
  labelingModel: string;
  labelingBatchSize: number;
  labelingConfidenceThreshold: number;
  autoApproveCheckpoint: boolean;
  workspaceDir: string;
  codeqlBinary?: string;
  python3Binary: string;
  threads?: number;
  ram?: number;
  maxFindings?: number;
}

export interface AugurCandidate {
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

export interface AugurPassEntry {
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

export interface AugurLabelsDocument {
  version: string;
  metadata: {
    run_id: string;
    generated_at: string;
    language: AugurLanguage;
    framework: string | null;
    model: string;
    project: string;
    notes?: string[];
  };
  passes: Array<{
    pass_id: 1 | 2 | 3 | 4 | 5 | 6;
    focus: string;
    cwes: string[];
    entries: AugurPassEntry[];
  }>;
}

export interface AugurPreflightOutput {
  augurPath: string;
  workspaceDir: string;
  dbPath: string;
  codeqlBinary: string;
  language: AugurLanguage;
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

export interface AugurLabelOutput {
  augurPath: string;
  workspaceDir: string;
  dbPath: string;
  codeqlBinary: string;
  language: AugurLanguage;
  framework: string | null;
  passes: Array<1 | 2 | 3 | 4 | 5 | 6>;
  labelsPath: string;
  labels: AugurLabelsDocument;
  reviewSummary: string;
  labelCounts: Record<string, number>;
  checkpointRequired: true;
}

export const AUGUR_PASSES: AugurPassDefinition[] = [
  { passId: 1, passKey: "path_traversal", focus: "Path Traversal", cwes: ["022", "023", "036", "073"] },
  { passId: 2, passKey: "command_injection", focus: "Command/Argument Injection", cwes: ["077", "078", "088"] },
  { passId: 3, passKey: "ssrf", focus: "SSRF", cwes: ["918", "099", "610"] },
  { passId: 4, passKey: "code_injection", focus: "Code Injection", cwes: ["094", "095"] },
  { passId: 5, passKey: "sql_injection", focus: "SQL Injection", cwes: ["089"] },
  { passId: 6, passKey: "unsafe_deserialization", focus: "Unsafe Deserialization", cwes: ["502"] },
];

const AUGUR_PASS_IDS = new Set([1, 2, 3, 4, 5, 6]);

const DEFAULT_AUGUR_PATH = normalizeDefaultAugurPath();

export const DEFAULT_AUGUR_TASK_CONFIG: AugurTaskConfig = {
  augurPath: DEFAULT_AUGUR_PATH,
  dbPath: undefined,
  passes: [1, 2, 3, 4, 5, 6],
  labelingModel: "claude-sonnet-4-20250514",
  labelingBatchSize: 20,
  labelingConfidenceThreshold: 0.55,
  autoApproveCheckpoint: false,
  workspaceDir: "./iris",
  codeqlBinary: undefined,
  python3Binary: "python3",
  threads: undefined,
  ram: undefined,
  maxFindings: undefined,
};

function normalizeDefaultAugurPath(): string {
  const envPath = process.env["AUGUR_PATH"]?.trim();
  if (envPath) {
    return path.normalize(envPath);
  }

  return augurRoot;
}

export function resolveAugurConfig(config: KuzushiConfig): AugurTaskConfig {
  const raw = config.scannerConfig["augur"];
  const merged = isRecord(raw)
    ? { ...DEFAULT_AUGUR_TASK_CONFIG, ...raw }
    : { ...DEFAULT_AUGUR_TASK_CONFIG };

  return {
    augurPath: normalizePath(merged["augurPath"], DEFAULT_AUGUR_TASK_CONFIG.augurPath),
    dbPath: normalizeOptionalPath(merged["dbPath"]),
    passes: normalizePasses(merged["passes"]),
    labelingModel: normalizeString(merged["labelingModel"], config.model),
    labelingBatchSize: normalizePositiveInt(merged["labelingBatchSize"], DEFAULT_AUGUR_TASK_CONFIG.labelingBatchSize),
    labelingConfidenceThreshold: normalizeUnitInterval(
      merged["labelingConfidenceThreshold"],
      DEFAULT_AUGUR_TASK_CONFIG.labelingConfidenceThreshold,
    ),
    autoApproveCheckpoint: normalizeBoolean(
      merged["autoApproveCheckpoint"],
      DEFAULT_AUGUR_TASK_CONFIG.autoApproveCheckpoint,
    ),
    workspaceDir: normalizePath(merged["workspaceDir"], DEFAULT_AUGUR_TASK_CONFIG.workspaceDir),
    codeqlBinary: normalizeOptionalPath(merged["codeqlBinary"]),
    python3Binary: normalizeString(merged["python3Binary"], DEFAULT_AUGUR_TASK_CONFIG.python3Binary),
    threads: normalizeOptionalPositiveInt(merged["threads"]),
    ram: normalizeOptionalPositiveInt(merged["ram"]),
    maxFindings: normalizeOptionalPositiveInt(merged["maxFindings"]),
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

export function normalizeAugurLanguage(value: string): AugurLanguage {
  const raw = value.trim().toLowerCase();
  if (raw.includes("python")) return "python";
  if (raw.includes("go")) return "go";
  if (raw.includes("java")) return "java";
  if (raw.includes("javascript") || raw.includes("typescript") || raw === "js" || raw === "ts") {
    return "javascript";
  }
  if (raw.includes("c#") || raw.includes("csharp")) return "csharp";
  return "javascript";
}

function normalizePasses(value: unknown): Array<1 | 2 | 3 | 4 | 5 | 6> {
  if (!Array.isArray(value)) {
    return [...DEFAULT_AUGUR_TASK_CONFIG.passes];
  }

  const seen = new Set<1 | 2 | 3 | 4 | 5 | 6>();
  for (const item of value) {
    const asInt = Math.floor(Number(item));
    if (AUGUR_PASS_IDS.has(asInt)) {
      seen.add(asInt as 1 | 2 | 3 | 4 | 5 | 6);
    }
  }

  if (seen.size === 0) {
    return [...DEFAULT_AUGUR_TASK_CONFIG.passes];
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

function normalizeBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function normalizeUnitInterval(value: unknown, fallback: number): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0 || numeric > 1) {
    return fallback;
  }

  return numeric;
}

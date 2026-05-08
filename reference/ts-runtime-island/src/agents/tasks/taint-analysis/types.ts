import path from "node:path";
import { augurRoot as taintAnalysisRoot } from "@kuzushi/augur";
import type { KuzushiConfig, RepoContext } from "../../../types.js";
import { isRecord } from "../../../utils.js";
import { normalizeLanguageName, SQL_DB_PATTERN, WEB_FRAMEWORKS } from "../category-filter.js";

export type TaintAnalysisLanguage = "python" | "go" | "java" | "javascript" | "csharp";

export type TaintAnalysisPassId =
  | 1
  | 2
  | 3
  | 4
  | 5
  | 6
  | 7
  | 8
  | 9
  | 10
  | 11
  | 12
  | 13
  | 14
  | 15
  | 16
  | 17
  | 18
  | 19;

export interface DiffScope {
  base: string;
  changedFiles: string[];
  mode: "delta" | "baseline";
  affectedPassIds: TaintAnalysisPassId[];
  fellBackToFull: boolean;
  fallbackReason?: string;
}

export interface TaintAnalysisPassDefinition {
  passId: TaintAnalysisPassId;
  passKey: string;
  focus: string;
  cwes: string[];
}

export interface TaintAnalysisTaskConfig {
  taintAnalysisPath: string;
  dbPath?: string;
  passes: TaintAnalysisPassId[];
  labelingModel: string;
  extractionModel?: string;
  /**
   * When `true`, the preflight will substitute `labelingModel` for an
   * unset `extractionModel` instead of erroring. Defaults to `false` so
   * Kuzushi never silently runs extraction on a different model than the
   * operator configured. Operators who want the substitution explicitly
   * opt in via `taskConfig["taint-analysis"].consentToExtractionLabelingFallback = true`.
   */
  consentToExtractionLabelingFallback?: boolean;
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
  tiMode: "live-required";
  tiFailurePolicy: "continue_without_ti";
  tiTimeoutMs?: number;
  refinementEnabled?: boolean;
  refinementIterations?: number;
  refinementDeltaOnly?: boolean;
  refinementModel?: string;
  crossService?: boolean;
  crossServiceBoundaryModel?: string;
  crossServiceStitchModel?: string;
  crossServiceMaxServices?: number;
  crossServiceConcurrency?: number;
  crossServiceContinueOnError?: boolean;
  crossServiceBoundaryThreshold?: number;
  crossServiceStitchThreshold?: number;
  crossServiceMaxPathDepth?: number;
  refinementConfidenceCap?: number;
  summarySupplementsDisabled?: boolean;
  extractionSupplementsDisabled?: boolean;
  renderingHintsDisabled?: boolean;
  groundingEnabled?: boolean;
  taintDiffBase?: string;
  taintDiffMode?: "delta" | "baseline";
}

export interface TaintAnalysisCandidate {
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

export type ExtractionDegradationReason =
  | "sources_extraction_unavailable"
  | "sinks_extraction_unavailable"
  | "sources_agent_returned_no_query"
  | "sinks_agent_returned_no_query"
  | "zero_usable_sources"
  | "zero_usable_sinks"
  | "low_source_count_for_framework";

export interface ExtractionDegradation {
  status: "ok" | "degraded" | "failed";
  reasons: ExtractionDegradationReason[];
}

export interface TaintAnalysisPassEntry {
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

export interface TaintAnalysisLabelsDocument {
  version: string;
  metadata: {
    run_id: string;
    generated_at: string;
    language: TaintAnalysisLanguage;
    framework: string | null;
    model: string;
    project: string;
    notes?: string[];
  };
  passes: Array<{
    pass_id: TaintAnalysisPassId;
    focus: string;
    cwes: string[];
    entries: TaintAnalysisPassEntry[];
  }>;
}

export interface TaintAnalysisPreflightOutput {
  taintAnalysisPath: string;
  workspaceDir: string;
  dbPath: string;
  codeqlBinary: string;
  codeqlVersion: string;
  codeqlApiProfileId: string;
  language: TaintAnalysisLanguage;
  framework: string | null;
  referenceFiles: string[];
  passes: TaintAnalysisPassId[];
  tiPriorMarkdownPath: string;
  tiPriorJsonPath: string;
  tiPriorDegraded: boolean;
  extraction: {
    sourcesQueryPath: string;
    sinksQueryPath: string;
    sourcesCsvPath: string;
    sinksCsvPath: string;
    sourcesRowCount: number;
    sinksRowCount: number;
  };
  extractionDegradation: ExtractionDegradation;
  diffScope?: DiffScope;
}

export interface TaintAnalysisLabelOutput {
  taintAnalysisPath: string;
  workspaceDir: string;
  dbPath: string;
  codeqlBinary: string;
  codeqlVersion: string;
  codeqlApiProfileId: string;
  language: TaintAnalysisLanguage;
  framework: string | null;
  passes: TaintAnalysisPassId[];
  tiPriorMarkdownPath: string;
  tiPriorJsonPath: string;
  tiPriorDegraded: boolean;
  extractionDegradation: ExtractionDegradation;
  diffScope?: DiffScope;
  labelsPath: string;
  labels: TaintAnalysisLabelsDocument;
  taintModelPath: string;
  /** Advisory only — for human review. No downstream pipeline stage gates on this value. */
  reviewSummary: string;
  /** Advisory only — for human review. No downstream pipeline stage gates on this value. */
  labelCounts: Record<string, number>;
}

export const TAINT_ANALYSIS_PASSES: TaintAnalysisPassDefinition[] = [
  {
    passId: 1,
    passKey: "path_traversal",
    focus: "Path Traversal",
    cwes: ["022", "023", "036", "073"],
  },
  {
    passId: 2,
    passKey: "command_injection",
    focus: "Command/Argument Injection",
    cwes: ["077", "078", "088"],
  },
  { passId: 3, passKey: "ssrf", focus: "SSRF", cwes: ["918", "099", "610"] },
  { passId: 4, passKey: "code_injection", focus: "Code Injection", cwes: ["094", "095"] },
  { passId: 5, passKey: "sql_injection", focus: "SQL Injection", cwes: ["089"] },
  { passId: 6, passKey: "unsafe_deserialization", focus: "Unsafe Deserialization", cwes: ["502"] },
  { passId: 7, passKey: "xss", focus: "Cross-Site Scripting (XSS)", cwes: ["079"] },
  { passId: 8, passKey: "xxe", focus: "XML External Entity (XXE)", cwes: ["611"] },
  { passId: 9, passKey: "open_redirect", focus: "Open Redirect", cwes: ["601"] },
  { passId: 10, passKey: "header_injection", focus: "HTTP Header Injection", cwes: ["113"] },
  { passId: 11, passKey: "log_injection", focus: "Log Injection / Forging", cwes: ["117"] },
  { passId: 12, passKey: "ldap_injection", focus: "LDAP Injection", cwes: ["090"] },
  { passId: 13, passKey: "ssti", focus: "Server-Side Template Injection (SSTI)", cwes: ["1336"] },
  { passId: 14, passKey: "prototype_pollution", focus: "Prototype Pollution", cwes: ["1321"] },
  { passId: 15, passKey: "mass_assignment", focus: "Mass Assignment / Autobinding", cwes: ["915"] },
  { passId: 16, passKey: "file_upload", focus: "Insecure File Upload", cwes: ["434"] },
  {
    passId: 17,
    passKey: "integer_overflow",
    focus: "Integer Overflow in Security-Critical Computation",
    cwes: ["190"],
  },
  { passId: 18, passKey: "regex_injection", focus: "Regex Injection (ReDoS)", cwes: ["1333"] },
  {
    passId: 19,
    passKey: "second_order_injection",
    focus: "Second-Order Injection (Stored Taint)",
    cwes: ["089", "079"],
  },
];

export const TAINT_ANALYSIS_PASS_IDS: ReadonlySet<number> = new Set(
  TAINT_ANALYSIS_PASSES.map((p) => p.passId),
);

/* ------------------------------------------------------------------ */
/*  Context-aware pass selection                                      */
/* ------------------------------------------------------------------ */

export interface PassRelevance {
  passId: TaintAnalysisPassId;
  always?: boolean;
  languages?: string[];
  requiresSqlDb?: boolean;
  requiresWebFramework?: boolean;
}

export const PASS_RELEVANCE_MAP: PassRelevance[] = [
  { passId: 1, always: true },
  { passId: 2, always: true },
  { passId: 3, requiresWebFramework: true },
  { passId: 4, languages: ["JavaScript", "TypeScript", "Python", "Ruby", "PHP"] },
  { passId: 5, requiresSqlDb: true },
  { passId: 6, always: true },
  { passId: 7, requiresWebFramework: true },
  { passId: 8, languages: ["Java", "Kotlin", "Python", "PHP", "Ruby", "Go"] },
  { passId: 9, requiresWebFramework: true },
  { passId: 10, requiresWebFramework: true },
  { passId: 11, always: true },
  { passId: 12, languages: ["Java", "Kotlin", "Python", "PHP", "Ruby"] },
  {
    passId: 13,
    languages: ["JavaScript", "TypeScript", "Python", "Ruby", "PHP", "Java", "Kotlin"],
  },
  { passId: 14, languages: ["JavaScript", "TypeScript"] },
  { passId: 15, languages: ["JavaScript", "TypeScript", "Ruby", "Python", "Java", "Kotlin"] },
  { passId: 16, requiresWebFramework: true },
  { passId: 17, languages: ["C", "C++", "Go", "Rust"] },
  { passId: 18, languages: ["JavaScript", "TypeScript", "Python", "Ruby", "PHP", "Java"] },
  { passId: 19, requiresSqlDb: true },
];

/**
 * Select taint analysis passes based on repo context.
 * When context is available, the agent chooses from all 19 passes.
 * When no context, falls back to the provided fallback passes.
 */
export function resolveContextAwarePasses(
  repoContext: RepoContext | undefined,
  fallbackPasses: TaintAnalysisPassId[],
): TaintAnalysisPassId[] {
  if (!repoContext) return fallbackPasses;

  const repoLangs = new Set(repoContext.languages.map(normalizeLanguageName));
  const hasWebFramework = repoContext.frameworks.some((f) =>
    WEB_FRAMEWORKS.has(f.toLowerCase().trim()),
  );
  const hasSqlDb = repoContext.ormOrDb.some((db) => SQL_DB_PATTERN.test(db));

  const included: TaintAnalysisPassId[] = [];

  for (const mapping of PASS_RELEVANCE_MAP) {
    if (mapping.always) {
      included.push(mapping.passId);
      continue;
    }

    let match = false;

    if (mapping.languages?.some((l) => repoLangs.has(normalizeLanguageName(l)))) {
      match = true;
    }

    if (!match && mapping.requiresWebFramework && hasWebFramework) {
      match = true;
    }

    if (!match && mapping.requiresSqlDb && hasSqlDb) {
      match = true;
    }

    if (match) {
      included.push(mapping.passId);
    }
  }

  return included.sort((a, b) => a - b);
}

const DEFAULT_TAINT_ANALYSIS_PATH = normalizeDefaultTaintAnalysisPath();

export const DEFAULT_TAINT_ANALYSIS_TASK_CONFIG: TaintAnalysisTaskConfig = {
  taintAnalysisPath: DEFAULT_TAINT_ANALYSIS_PATH,
  dbPath: undefined,
  passes: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19],
  labelingModel: "anthropic:claude-haiku-4-5",
  extractionModel: undefined,
  labelingBatchSize: 20,
  labelingConfidenceThreshold: 0.55,
  workspaceDir: ".kuzushi/iris",
  codeqlBinary: undefined,
  python3Binary: "python3",
  threads: undefined,
  ram: undefined,
  maxFindings: undefined,
  codeqlApiProfile: "auto",
  codeqlProbeTimeoutMs: 20_000,
  codeqlProfileFallbacks: true,
  tiMode: "live-required",
  tiFailurePolicy: "continue_without_ti",
  tiTimeoutMs: 15_000,
  refinementEnabled: true,
  refinementIterations: 2,
  refinementDeltaOnly: true,
  refinementModel: undefined,
  crossService: false,
  crossServiceBoundaryModel: undefined,
  crossServiceStitchModel: undefined,
  crossServiceMaxServices: 20,
  crossServiceConcurrency: 3,
  crossServiceContinueOnError: true,
  crossServiceBoundaryThreshold: 0.5,
  crossServiceStitchThreshold: 0.6,
  crossServiceMaxPathDepth: 5,
  refinementConfidenceCap: 0.5,
  summarySupplementsDisabled: false,
  extractionSupplementsDisabled: false,
  renderingHintsDisabled: false,
  groundingEnabled: true,
  taintDiffBase: undefined,
  taintDiffMode: "delta",
};

function normalizeDefaultTaintAnalysisPath(): string {
  const envPath = process.env["TAINT_ANALYSIS_PATH"]?.trim();
  if (envPath) {
    return path.normalize(envPath);
  }

  return taintAnalysisRoot;
}

export function resolveTaintAnalysisConfig(config: KuzushiConfig): TaintAnalysisTaskConfig {
  const raw = config.taskConfig["taint-analysis"];
  const merged = isRecord(raw)
    ? { ...DEFAULT_TAINT_ANALYSIS_TASK_CONFIG, ...raw }
    : { ...DEFAULT_TAINT_ANALYSIS_TASK_CONFIG };

  return {
    taintAnalysisPath: normalizePath(
      merged["taintAnalysisPath"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.taintAnalysisPath,
    ),
    dbPath: normalizeOptionalPath(merged["dbPath"]),
    passes: normalizePasses(merged["passes"]),
    labelingModel: normalizeString(isRecord(raw) ? raw["labelingModel"] : undefined, config.model),
    extractionModel: normalizeOptionalString(isRecord(raw) ? raw["extractionModel"] : undefined),
    labelingBatchSize: normalizePositiveInt(
      merged["labelingBatchSize"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.labelingBatchSize,
    ),
    labelingConfidenceThreshold: normalizeUnitInterval(
      merged["labelingConfidenceThreshold"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.labelingConfidenceThreshold,
    ),
    workspaceDir: normalizePath(
      merged["workspaceDir"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.workspaceDir,
    ),
    codeqlBinary: normalizeOptionalPath(merged["codeqlBinary"]),
    python3Binary: normalizeString(
      merged["python3Binary"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.python3Binary,
    ),
    threads: normalizeOptionalPositiveInt(merged["threads"]),
    ram: normalizeOptionalPositiveInt(merged["ram"]),
    maxFindings: normalizeOptionalPositiveInt(merged["maxFindings"]),
    codeqlApiProfile: normalizeCodeqlApiProfile(merged["codeqlApiProfile"]),
    codeqlProbeTimeoutMs: normalizePositiveInt(
      merged["codeqlProbeTimeoutMs"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.codeqlProbeTimeoutMs ?? 20_000,
    ),
    codeqlProfileFallbacks: normalizeBoolean(
      merged["codeqlProfileFallbacks"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.codeqlProfileFallbacks ?? true,
    ),
    tiMode: normalizeTiMode(merged["tiMode"]),
    tiFailurePolicy: normalizeTiFailurePolicy(merged["tiFailurePolicy"]),
    tiTimeoutMs: normalizeOptionalPositiveInt(merged["tiTimeoutMs"]),
    refinementEnabled: normalizeBoolean(
      merged["refinementEnabled"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.refinementEnabled ?? false,
    ),
    refinementIterations: normalizePositiveInt(
      merged["refinementIterations"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.refinementIterations ?? 1,
    ),
    refinementDeltaOnly: normalizeBoolean(
      merged["refinementDeltaOnly"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.refinementDeltaOnly ?? true,
    ),
    refinementModel: normalizeOptionalString(merged["refinementModel"]),
    crossService: normalizeBoolean(
      merged["crossService"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.crossService ?? false,
    ),
    crossServiceBoundaryModel: normalizeOptionalString(merged["crossServiceBoundaryModel"]),
    crossServiceStitchModel: normalizeOptionalString(merged["crossServiceStitchModel"]),
    crossServiceMaxServices: normalizePositiveInt(
      merged["crossServiceMaxServices"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.crossServiceMaxServices ?? 20,
    ),
    crossServiceConcurrency: normalizePositiveInt(
      merged["crossServiceConcurrency"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.crossServiceConcurrency ?? 3,
    ),
    crossServiceContinueOnError: normalizeBoolean(
      merged["crossServiceContinueOnError"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.crossServiceContinueOnError ?? true,
    ),
    crossServiceBoundaryThreshold: normalizeUnitInterval(
      merged["crossServiceBoundaryThreshold"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.crossServiceBoundaryThreshold ?? 0.5,
    ),
    crossServiceStitchThreshold: normalizeUnitInterval(
      merged["crossServiceStitchThreshold"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.crossServiceStitchThreshold ?? 0.6,
    ),
    crossServiceMaxPathDepth: normalizePositiveInt(
      merged["crossServiceMaxPathDepth"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.crossServiceMaxPathDepth ?? 5,
    ),
    refinementConfidenceCap: normalizeUnitInterval(
      merged["refinementConfidenceCap"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.refinementConfidenceCap ?? 0.3,
    ),
    summarySupplementsDisabled: normalizeBoolean(
      merged["summarySupplementsDisabled"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.summarySupplementsDisabled ?? false,
    ),
    extractionSupplementsDisabled: normalizeBoolean(
      merged["extractionSupplementsDisabled"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.extractionSupplementsDisabled ?? false,
    ),
    renderingHintsDisabled: normalizeBoolean(
      merged["renderingHintsDisabled"],
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.renderingHintsDisabled ?? false,
    ),
    groundingEnabled: normalizeBoolean(
      isRecord(raw) && raw["groundingEnabled"] !== undefined
        ? raw["groundingEnabled"]
        : config.taintGroundingEnabled,
      DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.groundingEnabled ?? true,
    ),
    taintDiffBase: normalizeOptionalString(
      isRecord(raw) && raw["taintDiffBase"] !== undefined
        ? raw["taintDiffBase"]
        : config.taintDiffBase,
    ),
    taintDiffMode: normalizeDiffMode(
      isRecord(raw) && raw["taintDiffMode"] !== undefined
        ? raw["taintDiffMode"]
        : config.taintDiffMode,
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
  if (
    normalized.includes("asp.net") ||
    normalized.includes("aspnet") ||
    normalized.includes("api controller")
  ) {
    return "aspnet";
  }

  return null;
}

export function normalizeTaintAnalysisLanguage(value: string): TaintAnalysisLanguage {
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

function normalizePasses(value: unknown): TaintAnalysisPassId[] {
  if (!Array.isArray(value)) {
    return [...DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.passes];
  }

  const seen = new Set<TaintAnalysisPassId>();
  for (const item of value) {
    const asInt = Math.floor(Number(item));
    if (TAINT_ANALYSIS_PASS_IDS.has(asInt)) {
      seen.add(asInt as TaintAnalysisPassId);
    }
  }

  if (seen.size === 0) {
    return [...DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.passes];
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

function normalizeTiMode(value: unknown): "live-required" {
  if (typeof value !== "string") {
    return "live-required";
  }
  const trimmed = value.trim().toLowerCase();
  return trimmed === "live-required" ? "live-required" : "live-required";
}

function normalizeTiFailurePolicy(value: unknown): "continue_without_ti" {
  if (typeof value !== "string") {
    return "continue_without_ti";
  }
  const trimmed = value.trim().toLowerCase();
  return trimmed === "continue_without_ti" ? "continue_without_ti" : "continue_without_ti";
}

function normalizeDiffMode(value: unknown): "delta" | "baseline" {
  if (typeof value !== "string") {
    return "delta";
  }
  const trimmed = value.trim().toLowerCase();
  return trimmed === "baseline" ? "baseline" : "delta";
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

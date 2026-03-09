import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import type { AgentRuntimeConfig, KuzushiConfig, Verdict } from "./types.js";
import type { ScannerConfig } from "./scanners/types.js";
import { isRecord } from "./utils.js";
import { augurRoot as taintAnalysisRoot } from "@kuzushi/augur";

const CONFIG_DIR = path.join(os.homedir(), ".kuzushi");
const CONFIG_PATH = path.join(CONFIG_DIR, "config.json");
const PROJECT_CONFIG_REL_PATH = path.join(".kuzushi", "config.json");
const BUS_BACKENDS = new Set<string>([
  "in-process",
  "redis",
  "google-pubsub",
  "nats",
]);
const AGENT_RUNTIME_BACKENDS = new Set<string>([
  "pi-ai",
  "acp",
]);
const DEFAULT_TAINT_ANALYSIS_PATH = process.env["TAINT_ANALYSIS_PATH"]?.trim() || taintAnalysisRoot;
type ConfigLayer = Record<string, unknown>;
type WritableConfigLayer = Partial<KuzushiConfig> & ConfigLayer;

/** Hard defaults — the bottom of the precedence stack. */
export const DEFAULTS: KuzushiConfig = {
  model: "anthropic:claude-sonnet-4-6",
  triageMaxTurns: null,
  verify: false,
  verifyMaxTurns: 15,
  verifyConcurrency: 1,
  verifyVerdicts: ["tp"],
  verifyMinConfidence: 0,
  pocHarness: false,
  pocHarnessMaxTurns: 20,
  pocHarnessConcurrency: 1,
  enableContextGathering: true,
  auditLog: false,
  reportOutput: undefined,
  sarifOutput: undefined,
  maxTriageRetries: 2,
  maxVerifyRetries: 2,
  maxPocHarnessRetries: 2,
  retryBackoffMs: 5000,
  retryBackoffMultiplier: 2,
  busBackend: "in-process",
  triageBatchSize: 15,
  triageConcurrency: 1,
  scanMode: "sequential",
  agentRuntimeBackend: "pi-ai",
  agentRuntimeConfig: undefined,
  enabledTasks: [],
  scanners: ["semgrep"],
  severity: ["ERROR", "WARNING"],
  excludePatterns: [
    "test", "tests", "spec", "vendor",
    "node_modules", "__tests__", "*.min.js", "*.min.css",
  ],
  fpFilterEnabled: true,
  fpFilterCustomExclusions: [],
  variantAnalysis: false,
  variantAnalysisMaxFindings: 10,
  enableContextEnrichment: false,
  prioritizeFindings: true,
  diffBase: undefined,
  scannerConfig: {
    semgrep: { configFlag: "auto" },
    agentic: { model: "anthropic:claude-sonnet-4-6", maxFindings: 20 },
    codeql: {},
    "dangerous-api": { maxFindings: 50 },
    "taint-analysis": {
      taintAnalysisPath: DEFAULT_TAINT_ANALYSIS_PATH,
      dbPath: undefined,
      passes: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
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
      tiMode: "live-required",
      tiFailurePolicy: "continue_without_ti",
      tiTimeoutMs: 15_000,
      refinementEnabled: false,
      refinementIterations: 1,
      refinementDeltaOnly: true,
      refinementModel: undefined,
    },
  },
};

const VALID_TOP_LEVEL_KEYS = new Set<string>([
  ...Object.keys(DEFAULTS),
  "triageModel",
  "verifyModel",
  "pocHarnessModel",
  "variantAnalysisModel",
  "contextEnrichmentModel",
  "llmRescoreEnabled",
  "llmRescoreModel",
  "llmRescoreThreshold",
  "chainAnalysis",
  "chainAnalysisModel",
  "precedentsPath",
  "securityProfilesPath",
  "prioritizeFindings",
  "costBudgetUsd",
]);

/** Load config from ~/.kuzushi/config.json + optional <repo>/.kuzushi/config.json. */
export function loadConfig(repoRoot?: string): KuzushiConfig {
  const { globalRaw, projectRaw } = loadConfigLayers(repoRoot);
  return mergeConfigLayers(globalRaw, projectRaw);
}

/** Save config. If repoRoot is provided, writes project config. */
export function saveConfig(config: KuzushiConfig, repoRoot?: string): void {
  writeConfigFile(
    repoRoot ? projectConfigPath(repoRoot) : CONFIG_PATH,
    normalizeConfig(config),
  );
}

function saveConfigLayer(config: ConfigLayer, repoRoot?: string): void {
  writeConfigFile(
    repoRoot ? projectConfigPath(repoRoot) : CONFIG_PATH,
    sanitizeConfigLayer(config),
  );
}

function writeConfigFile(targetPath: string, config: unknown): void {
  const targetDir = path.dirname(targetPath);

  if (!existsSync(targetDir)) {
    mkdirSync(targetDir, { recursive: true });
  }

  writeFileSync(targetPath, JSON.stringify(config, null, 2) + "\n");
}

/** Get a config value by key (supports dotted paths like scannerConfig.semgrep.binary). */
export function getConfigValue(key: string, repoRoot?: string): unknown {
  const config = loadConfig(repoRoot);

  if (!key.includes(".")) {
    if (!VALID_TOP_LEVEL_KEYS.has(key)) return undefined;
    return config[key as keyof KuzushiConfig];
  }

  return getByPath(config, key.split("."));
}

/** Set a config value by key (supports dotted paths like scannerConfig.semgrep.binary). */
export function setConfigValue(key: string, raw: string, repoRoot?: string): void {
  const config = loadWritableConfigLayer(repoRoot);

  if (key.includes(".")) {
    const parts = key.split(".");
    validatePathParts(parts);
    setByPath(config, parts, parseFlexibleValue(raw));
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (!VALID_TOP_LEVEL_KEYS.has(key)) {
    throw new Error(`Unknown config key: ${key}. Valid keys: ${[...VALID_TOP_LEVEL_KEYS].join(", ")}`);
  }

  if (key === "scanners") {
    config.scanners = coerceStringArray(raw);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "enabledTasks") {
    config.enabledTasks = coerceStringArray(raw);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "scannerConfig") {
    const parsed = parseFlexibleValue(raw);
    if (!isRecord(parsed)) {
      throw new Error("scannerConfig must be an object");
    }
    config.scannerConfig = coerceScannerConfigMap(parsed);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "agentRuntimeConfig") {
    const parsed = parseFlexibleValue(raw);
    if (!isRecord(parsed)) {
      throw new Error("agentRuntimeConfig must be an object");
    }
    config.agentRuntimeConfig = normalizeAgentRuntimeConfig(parsed);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "triageBatchSize") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("triageBatchSize must be a positive number");
    }
    config.triageBatchSize = Math.floor(n);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "triageConcurrency") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("triageConcurrency must be a positive number");
    }
    config.triageConcurrency = Math.floor(n);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "triageMaxTurns") {
    if (raw === "null" || raw === "unlimited" || raw === "0") {
      config.triageMaxTurns = null;
    } else {
      const n = Number(raw);
      if (!Number.isFinite(n) || n < 1) {
        throw new Error("triageMaxTurns must be a positive number, 0, or 'unlimited'");
      }
      config.triageMaxTurns = Math.floor(n);
    }
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "verify") {
    const parsed = parseFlexibleValue(raw);
    if (typeof parsed !== "boolean") {
      throw new Error("verify must be true or false");
    }
    config.verify = parsed;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "verifyMaxTurns") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("verifyMaxTurns must be a positive number");
    }
    config.verifyMaxTurns = Math.floor(n);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "verifyConcurrency") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("verifyConcurrency must be a positive number");
    }
    config.verifyConcurrency = Math.floor(n);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "verifyVerdicts") {
    config.verifyVerdicts = coerceVerdictArray(raw);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "verifyMinConfidence") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0 || n > 1) {
      throw new Error("verifyMinConfidence must be a number between 0 and 1");
    }
    config.verifyMinConfidence = n;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "pocHarness") {
    const parsed = parseFlexibleValue(raw);
    if (typeof parsed !== "boolean") {
      throw new Error("pocHarness must be true or false");
    }
    config.pocHarness = parsed;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "pocHarnessMaxTurns") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("pocHarnessMaxTurns must be a positive number");
    }
    config.pocHarnessMaxTurns = Math.floor(n);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "pocHarnessConcurrency") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("pocHarnessConcurrency must be a positive number");
    }
    config.pocHarnessConcurrency = Math.floor(n);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "enableContextGathering") {
    const parsed = parseFlexibleValue(raw);
    if (typeof parsed !== "boolean") {
      throw new Error("enableContextGathering must be true or false");
    }
    config.enableContextGathering = parsed;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "auditLog") {
    const parsed = parseFlexibleValue(raw);
    if (typeof parsed !== "boolean") {
      throw new Error("auditLog must be true or false");
    }
    config.auditLog = parsed;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "reportOutput") {
    config.reportOutput = raw.trim() || undefined;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "sarifOutput") {
    config.sarifOutput = raw.trim() || undefined;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "maxTriageRetries") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0) {
      throw new Error("maxTriageRetries must be a non-negative number");
    }
    config.maxTriageRetries = Math.floor(n);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "maxVerifyRetries") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0) {
      throw new Error("maxVerifyRetries must be a non-negative number");
    }
    config.maxVerifyRetries = Math.floor(n);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "maxPocHarnessRetries") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0) {
      throw new Error("maxPocHarnessRetries must be a non-negative number");
    }
    config.maxPocHarnessRetries = Math.floor(n);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "retryBackoffMs") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0) {
      throw new Error("retryBackoffMs must be a non-negative number");
    }
    config.retryBackoffMs = Math.floor(n);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "retryBackoffMultiplier") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n <= 0) {
      throw new Error("retryBackoffMultiplier must be a positive number");
    }
    config.retryBackoffMultiplier = n;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "scanMode") {
    const mode = raw.trim();
    if (mode !== "sequential" && mode !== "concurrent") {
      throw new Error("scanMode must be one of: sequential, concurrent");
    }
    config.scanMode = mode;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "agentRuntimeBackend") {
    const backend = raw.trim();
    if (!AGENT_RUNTIME_BACKENDS.has(backend)) {
      throw new Error(
        `agentRuntimeBackend must be one of: ${[...AGENT_RUNTIME_BACKENDS].join(", ")}`,
      );
    }
    config.agentRuntimeBackend = backend as KuzushiConfig["agentRuntimeBackend"];
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "busBackend") {
    const backend = raw.trim();
    if (!BUS_BACKENDS.has(backend)) {
      throw new Error(`busBackend must be one of: ${[...BUS_BACKENDS].join(", ")}`);
    }
    config.busBackend = backend as KuzushiConfig["busBackend"];
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "severity") {
    config.severity = coerceStringArray(raw);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "excludePatterns") {
    config.excludePatterns = coerceStringArray(raw);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "model") {
    config.model = raw;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "triageModel") {
    config.triageModel = raw.trim() || undefined;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "verifyModel") {
    config.verifyModel = raw.trim() || undefined;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "pocHarnessModel") {
    config.pocHarnessModel = raw.trim() || undefined;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "costBudgetUsd") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n <= 0) {
      throw new Error("costBudgetUsd must be a positive number");
    }
    config.costBudgetUsd = n;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "prioritizeFindings") {
    const parsed = parseFlexibleValue(raw);
    if (typeof parsed !== "boolean") {
      throw new Error("prioritizeFindings must be true or false");
    }
    config.prioritizeFindings = parsed;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  throw new Error(`Unknown config key: ${key}`);
}

/** Unset a config key (supports dotted paths). */
export function unsetConfigValue(key: string, repoRoot?: string): void {
  const config = loadWritableConfigLayer(repoRoot);

  if (key.includes(".")) {
    const parts = key.split(".");
    validatePathParts(parts);
    unsetByPath(config, parts);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (!VALID_TOP_LEVEL_KEYS.has(key)) {
    throw new Error(`Unknown config key: ${key}. Valid keys: ${[...VALID_TOP_LEVEL_KEYS].join(", ")}`);
  }

  delete config[key];
  saveUpdatedConfigLayer(config, repoRoot);
}

/** Return global config file path. */
export function configPath(): string {
  return CONFIG_PATH;
}

/** Return project config file path. */
export function projectConfigPath(repoRoot: string): string {
  return path.join(repoRoot, PROJECT_CONFIG_REL_PATH);
}

function normalizeConfig(config: KuzushiConfig): KuzushiConfig {
  const scanners = normalizeStringArray(config.scanners);
  const severity = normalizeStringArray(config.severity);
  const excludePatterns = normalizeStringArray(config.excludePatterns);
  const busBackend = normalizeBusBackend(config.busBackend);
  const triageBatchSize = normalizePositiveInt(config.triageBatchSize, DEFAULTS.triageBatchSize);
  const triageConcurrency = normalizePositiveInt(config.triageConcurrency, DEFAULTS.triageConcurrency);
  const triageMaxTurns = config.triageMaxTurns == null
    ? null
    : normalizePositiveInt(config.triageMaxTurns, DEFAULTS.triageMaxTurns ?? 10);
  const verify = normalizeBoolean(config.verify, DEFAULTS.verify ?? false);
  const verifyModel = normalizeOptionalString(config.verifyModel);
  const verifyMaxTurns = normalizePositiveInt(
    config.verifyMaxTurns,
    DEFAULTS.verifyMaxTurns ?? 15,
  );
  const verifyConcurrency = normalizePositiveInt(
    config.verifyConcurrency,
    DEFAULTS.verifyConcurrency ?? 1,
  );
  const verifyVerdictsRaw = normalizeVerdictArray(config.verifyVerdicts);
  const verifyVerdicts = verifyVerdictsRaw.length > 0
    ? verifyVerdictsRaw
    : [...(DEFAULTS.verifyVerdicts ?? ["tp"])];
  const verifyMinConfidence = normalizeUnitInterval(
    config.verifyMinConfidence,
    DEFAULTS.verifyMinConfidence ?? 0,
  );
  const pocHarness = normalizeBoolean(config.pocHarness, DEFAULTS.pocHarness ?? false);
  const pocHarnessModel = normalizeOptionalString(config.pocHarnessModel);
  const pocHarnessMaxTurns = normalizePositiveInt(
    config.pocHarnessMaxTurns,
    DEFAULTS.pocHarnessMaxTurns ?? 20,
  );
  const pocHarnessConcurrency = normalizePositiveInt(
    config.pocHarnessConcurrency,
    DEFAULTS.pocHarnessConcurrency ?? 1,
  );
  const enableContextGathering = normalizeBoolean(
    config.enableContextGathering,
    DEFAULTS.enableContextGathering ?? true,
  );
  const auditLog = normalizeBoolean(config.auditLog, DEFAULTS.auditLog ?? false);
  const reportOutput = normalizeOptionalString(config.reportOutput);
  const sarifOutput = normalizeOptionalString(config.sarifOutput);
  const maxTriageRetries = normalizeNonNegativeInt(
    config.maxTriageRetries,
    DEFAULTS.maxTriageRetries ?? 2,
  );
  const maxVerifyRetries = normalizeNonNegativeInt(
    config.maxVerifyRetries,
    DEFAULTS.maxVerifyRetries ?? 2,
  );
  const maxPocHarnessRetries = normalizeNonNegativeInt(
    config.maxPocHarnessRetries,
    DEFAULTS.maxPocHarnessRetries ?? 2,
  );
  const retryBackoffMs = normalizeNonNegativeInt(
    config.retryBackoffMs,
    DEFAULTS.retryBackoffMs ?? 5000,
  );
  const retryBackoffMultiplier = normalizePositiveNumber(
    config.retryBackoffMultiplier,
    DEFAULTS.retryBackoffMultiplier ?? 2,
  );
  const scanMode = normalizeScanMode(config.scanMode);
  const agentRuntimeBackend = normalizeAgentRuntimeBackend(config.agentRuntimeBackend);
  const agentRuntimeConfig = normalizeAgentRuntimeConfig(config.agentRuntimeConfig);
  const triageModel = normalizeOptionalString(config.triageModel);
  const enabledTasks = normalizeStringArray(config.enabledTasks);

  return {
    ...config,
    verify,
    verifyModel,
    verifyMaxTurns,
    verifyConcurrency,
    verifyVerdicts,
    verifyMinConfidence,
    pocHarness,
    pocHarnessModel,
    pocHarnessMaxTurns,
    pocHarnessConcurrency,
    enableContextGathering,
    auditLog,
    reportOutput,
    sarifOutput,
    maxTriageRetries,
    maxVerifyRetries,
    maxPocHarnessRetries,
    retryBackoffMs,
    retryBackoffMultiplier,
    busBackend,
    triageBatchSize,
    triageConcurrency,
    triageMaxTurns,
    scanMode,
    agentRuntimeBackend,
    agentRuntimeConfig,
    triageModel,
    enabledTasks,
    scanners: scanners.length > 0 ? scanners : [...DEFAULTS.scanners],
    severity: severity.length > 0 ? severity : [...DEFAULTS.severity],
    excludePatterns,
    scannerConfig: coerceScannerConfigMap(config.scannerConfig),
  };
}

function mergeConfigLayers(...layers: Array<unknown>): KuzushiConfig {
  const merged: KuzushiConfig = {
    ...DEFAULTS,
    scannerConfig: cloneScannerConfig(DEFAULTS.scannerConfig),
    enabledTasks: [...(DEFAULTS.enabledTasks ?? [])],
    scanners: [...DEFAULTS.scanners],
    severity: [...DEFAULTS.severity],
    excludePatterns: [...DEFAULTS.excludePatterns],
    verifyVerdicts: [...(DEFAULTS.verifyVerdicts ?? [])],
  };

  for (const layer of layers) {
    if (!isRecord(layer)) {
      continue;
    }

    for (const [key, value] of Object.entries(layer)) {
      if (!VALID_TOP_LEVEL_KEYS.has(key)) {
        continue;
      }

      if (key === "scannerConfig") {
        if (!isRecord(value)) {
          continue;
        }

        const layerConfig = coerceScannerConfigMap(value);
        for (const [scannerId, scannerConfig] of Object.entries(layerConfig)) {
          merged.scannerConfig[scannerId] = {
            ...(merged.scannerConfig[scannerId] ?? {}),
            ...scannerConfig,
          };
        }
        continue;
      }

      if (key === "agentRuntimeConfig") {
        if (value == null) {
          merged.agentRuntimeConfig = undefined;
          continue;
        }

        if (!isRecord(value)) {
          continue;
        }

        merged.agentRuntimeConfig = {
          ...(merged.agentRuntimeConfig ?? {}),
          ...cloneLayerValue(value),
        };
        continue;
      }

      Reflect.set(merged as object, key, cloneLayerValue(value));
    }
  }

  return normalizeConfig(merged);
}

function loadConfigLayers(repoRoot?: string): {
  globalRaw: WritableConfigLayer;
  projectRaw: WritableConfigLayer;
} {
  return {
    globalRaw: readConfigFile(CONFIG_PATH),
    projectRaw: repoRoot ? readConfigFile(projectConfigPath(repoRoot)) : {},
  };
}

function loadWritableConfigLayer(repoRoot?: string): WritableConfigLayer {
  return repoRoot
    ? readConfigFile(projectConfigPath(repoRoot))
    : readConfigFile(CONFIG_PATH);
}

function saveUpdatedConfigLayer(config: WritableConfigLayer, repoRoot?: string): void {
  const layer = sanitizeConfigLayer(config) as WritableConfigLayer;
  validateConfigLayer(layer, repoRoot);
  saveConfigLayer(layer, repoRoot);
}

function validateConfigLayer(layer: WritableConfigLayer, repoRoot?: string): void {
  if (!repoRoot) {
    mergeConfigLayers(layer);
    return;
  }

  const globalRaw = readConfigFile(CONFIG_PATH);
  mergeConfigLayers(globalRaw, layer);
}

function readConfigFile(configFilePath: string): WritableConfigLayer {
  try {
    const content = readFileSync(configFilePath, "utf-8");
    const parsed = JSON.parse(content);
    return isRecord(parsed) ? parsed : {};
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
    console.warn(`Warning: config file ${configFilePath} is corrupt and will be ignored: ${err}`);
    return {};
  }
}

function sanitizeConfigLayer(value: unknown): unknown {
  if (value === undefined) {
    return undefined;
  }

  if (Array.isArray(value)) {
    return value
      .map((item) => sanitizeConfigLayer(item))
      .filter((item) => item !== undefined);
  }

  if (isRecord(value)) {
    const sanitized: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      const cleaned = sanitizeConfigLayer(entry);
      if (cleaned === undefined) {
        continue;
      }

      if (isRecord(cleaned) && Object.keys(cleaned).length === 0) {
        continue;
      }

      sanitized[key] = cleaned;
    }
    return sanitized;
  }

  return value;
}

function cloneLayerValue<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item) => cloneLayerValue(item)) as T;
  }

  if (isRecord(value)) {
    const cloned: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      cloned[key] = cloneLayerValue(entry);
    }
    return cloned as T;
  }

  return value;
}

function coerceScannerConfigMap(value: unknown): Record<string, ScannerConfig> {
  if (!isRecord(value)) return {};

  const result: Record<string, ScannerConfig> = {};
  for (const [k, v] of Object.entries(value)) {
    if (!isRecord(v)) continue;
    result[k] = { ...v };
  }

  return result;
}

function coerceStringArray(raw: string): string[] {
  const parsed = raw.trim().startsWith("[")
    ? parseFlexibleValue(raw)
    : raw.split(",").map((part) => part.trim()).filter(Boolean);

  if (!Array.isArray(parsed)) {
    throw new Error("Expected an array value");
  }

  const values = normalizeStringArray(parsed);
  if (values.length === 0) {
    throw new Error("Value must include at least one item");
  }

  return values;
}

function coerceVerdictArray(raw: string): Verdict[] {
  const parsed = raw.trim().startsWith("[")
    ? parseFlexibleValue(raw)
    : raw.split(",").map((part) => part.trim()).filter(Boolean);

  if (!Array.isArray(parsed)) {
    throw new Error("Expected an array value");
  }

  const rawValues = parsed.map((v) => String(v).trim()).filter(Boolean);
  if (rawValues.length === 0) {
    throw new Error("Value must include at least one item");
  }

  const normalized = normalizeVerdictArray(rawValues);
  if (normalized.length !== rawValues.length) {
    throw new Error("verifyVerdicts must contain only: tp, fp, needs_review");
  }

  return normalized;
}

function normalizeStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((v) => String(v).trim()).filter(Boolean);
}

function normalizeVerdictArray(value: unknown): Verdict[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const seen = new Set<Verdict>();
  for (const raw of value) {
    const verdict = String(raw).trim();
    if (verdict === "tp" || verdict === "fp" || verdict === "needs_review") {
      seen.add(verdict);
    }
  }

  return [...seen];
}

function normalizeBusBackend(value: unknown): KuzushiConfig["busBackend"] {
  if (typeof value !== "string") return DEFAULTS.busBackend;
  if (BUS_BACKENDS.has(value)) {
    return value as KuzushiConfig["busBackend"];
  }

  throw new Error(
    `Invalid busBackend "${value}". Valid values: ${[...BUS_BACKENDS].join(", ")}`,
  );
}

function normalizeScanMode(value: unknown): KuzushiConfig["scanMode"] {
  if (value === "sequential" || value === "concurrent") {
    return value;
  }
  return DEFAULTS.scanMode;
}

function normalizeAgentRuntimeBackend(value: unknown): KuzushiConfig["agentRuntimeBackend"] {
  if (typeof value !== "string") {
    return DEFAULTS.agentRuntimeBackend;
  }

  if (AGENT_RUNTIME_BACKENDS.has(value)) {
    return value as KuzushiConfig["agentRuntimeBackend"];
  }

  throw new Error(
    `Invalid agentRuntimeBackend "${value}". `
    + `Valid values: ${[...AGENT_RUNTIME_BACKENDS].join(", ")}`,
  );
}

function normalizePositiveInt(value: unknown, fallback: number): number {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 1) {
    return fallback;
  }
  return Math.floor(n);
}

function normalizeNonNegativeInt(value: unknown, fallback: number): number {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) {
    return fallback;
  }
  return Math.floor(n);
}

function normalizePositiveNumber(value: unknown, fallback: number): number {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) {
    return fallback;
  }
  return n;
}

function normalizeUnitInterval(value: unknown, fallback: number): number {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0 || n > 1) {
    return fallback;
  }
  return n;
}

function normalizeBoolean(value: unknown, fallback: boolean): boolean {
  if (typeof value !== "boolean") {
    return fallback;
  }

  return value;
}

function normalizeOptionalString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function normalizeAgentRuntimeConfig(value: unknown): AgentRuntimeConfig | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  const apiKey = normalizeOptionalString(value["apiKey"]);
  const baseUrl = normalizeOptionalString(value["baseUrl"]);

  if (!apiKey && !baseUrl) {
    return undefined;
  }

  const normalized: AgentRuntimeConfig = {};
  if (apiKey) normalized.apiKey = apiKey;
  if (baseUrl) normalized.baseUrl = baseUrl;
  return normalized;
}

function parseFlexibleValue(raw: string): unknown {
  const trimmed = raw.trim();

  if (!trimmed) return "";
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      return JSON.parse(trimmed);
    } catch {
      throw new Error(`Invalid JSON value: ${trimmed.slice(0, 80)}`);
    }
  }

  if (trimmed === "true") return true;
  if (trimmed === "false") return false;

  const num = Number(trimmed);
  if (!Number.isNaN(num) && trimmed !== "") return num;

  return raw;
}

const UNSAFE_PATH_SEGMENTS = new Set(["__proto__", "constructor", "prototype"]);

function validatePathParts(pathParts: string[]): void {
  for (const part of pathParts) {
    if (UNSAFE_PATH_SEGMENTS.has(part)) {
      throw new Error(`Invalid config key segment: ${part}`);
    }
  }
}

function getByPath(root: unknown, pathParts: string[]): unknown {
  let cursor: unknown = root;
  for (const part of pathParts) {
    if (!isRecord(cursor) || !(part in cursor)) return undefined;
    cursor = cursor[part];
  }
  return cursor;
}

function setByPath(root: unknown, pathParts: string[], value: unknown): void {
  if (!isRecord(root)) return;
  let cursor: Record<string, unknown> = root;

  for (let i = 0; i < pathParts.length - 1; i++) {
    const part = pathParts[i];
    const current = cursor[part];

    if (!isRecord(current)) {
      cursor[part] = {};
    }

    cursor = cursor[part] as Record<string, unknown>;
  }

  cursor[pathParts[pathParts.length - 1]] = value;
}

function unsetByPath(root: unknown, pathParts: string[]): void {
  if (pathParts.length === 0) return;
  if (!isRecord(root)) return;

  let cursor: Record<string, unknown> = root;
  for (let i = 0; i < pathParts.length - 1; i++) {
    const part = pathParts[i];
    const next = cursor[part];
    if (!isRecord(next)) return;
    cursor = next;
  }

  delete cursor[pathParts[pathParts.length - 1]];
}

function cloneScannerConfig(value: Record<string, ScannerConfig>): Record<string, ScannerConfig> {
  const result: Record<string, ScannerConfig> = {};
  for (const [k, v] of Object.entries(value)) {
    result[k] = { ...v };
  }
  return result;
}

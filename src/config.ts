import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { normalizeTaskConfigAliases } from "./capabilities.js";
import { AGENT_RUNTIME_BACKENDS, BUS_BACKENDS, DEFAULTS } from "./config/defaults.js";
import { CONFIG_DIR, CONFIG_PATH, configPath, projectConfigPath } from "./config/paths.js";
import {
  type ConfigFormat,
  detectConfigFormat,
  parseConfigFile,
  resolveFileReferences,
  serializeConfig,
} from "./config-io.js";
import { getLogger } from "./logger.js";
import type { QualityGateConfig } from "./quality-gate-types.js";
import type { TaskConfig } from "./scanners/types.js";
import { KuzushiConfigSchema } from "./schemas.js";
import type { ConfidenceSignalWeights } from "./scoring/composite-confidence.js";
import type { AgentRuntimeConfig, KuzushiConfig, Verdict } from "./types.js";
import { isPathWithinRoot, isRecord } from "./utils.js";

type ConfigLayer = Record<string, unknown>;
type WritableConfigLayer = Partial<KuzushiConfig> & ConfigLayer;
const log = getLogger("config");

export { configPath, DEFAULTS, projectConfigPath };

/** Derived from KuzushiConfigSchema so that adding a new config key to the
 *  interface automatically makes it valid here — no manual list to maintain. */
const VALID_TOP_LEVEL_KEYS = new Set<string>(Object.keys(KuzushiConfigSchema.shape));

const UNSAFE_PROJECT_CONFIG_KEYS = new Set<string>([
  "agentRuntimeBackend",
  "agentRuntimeConfig",
  "verify",
  "pocHarness",
  "pocExecute",
  "pocSandbox",
  "dynamicAnalysisEnabled",
  "patchingEnabled",
  "patchBuildCommand",
  "patchTestCommand",
  "autoPatchEnabled",
  "reportOutput",
  "sarifOutput",
  "jsonOutput",
  "csvOutput",
  "jsonlOutput",
  "streamingEnabled",
  "streamingPort",
  "externalTasks",
  "enableExternalTasks",
  "hooks",
  "enableExternalHooks",
  "precedentsPath",
  "securityProfilesPath",
  "triagePromptFile",
  "verifyPromptFile",
  "bootstrapFiles",
  "toolPolicies",
]);

const UNSAFE_PROJECT_TASK_CONFIG_KEYS = new Set<string>([
  "binary",
  "codeqlBinary",
  "python3Binary",
  "dbPath",
  "taintAnalysisPath",
  "workspaceDir",
]);

export interface LoadConfigOptions {
  trustProjectConfig?: boolean;
}

/** Load config from ~/.kuzushi/config.json + optional <repo>/.kuzushi/config.json. */
export function loadConfig(repoRoot?: string, options?: LoadConfigOptions): KuzushiConfig {
  const { globalRaw, projectRaw } = loadConfigLayers(repoRoot);
  const effectiveProjectRaw = repoRoot
    ? sanitizeProjectConfigLayer(projectRaw, repoRoot, options)
    : projectRaw;
  return mergeConfigLayers(globalRaw, effectiveProjectRaw);
}

/** Save config. If repoRoot is provided, writes project config. */
export function saveConfig(config: KuzushiConfig, repoRoot?: string): void {
  writeConfigFile(repoRoot ? projectConfigPath(repoRoot) : CONFIG_PATH, normalizeConfig(config));
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

  const format: ConfigFormat = detectConfigFormat(targetPath);
  writeFileSync(targetPath, serializeConfig(config, format));
}

/** Get a config value by key (supports dotted paths like taskConfig.semgrep.binary). */
export function getConfigValue(key: string, repoRoot?: string): unknown {
  const config = loadConfig(repoRoot);

  if (!key.includes(".")) {
    if (!VALID_TOP_LEVEL_KEYS.has(key)) return undefined;
    return config[key as keyof KuzushiConfig];
  }

  return getByPath(config, key.split("."));
}

/** Set a config value by key (supports dotted paths like taskConfig.semgrep.binary). */
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
    throw new Error(
      `Unknown config key: ${key}. Valid keys: ${[...VALID_TOP_LEVEL_KEYS].join(", ")}`,
    );
  }

  if (key === "tasks") {
    config.tasks = coerceStringArray(raw);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "taskConfig") {
    const parsed = parseFlexibleValue(raw);
    if (!isRecord(parsed)) {
      throw new Error("taskConfig must be an object");
    }
    config.taskConfig = coerceTaskConfigMap(parsed);
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
    if (!Number.isFinite(n) || n < 0 || n > 100) {
      throw new Error(
        "verifyMinConfidence must be a number between 0 and 1 (or 0-100 as a percentage)",
      );
    }
    config.verifyMinConfidence = n > 1 ? n / 100 : n;
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

  if (key === "jsonOutput") {
    config.jsonOutput = raw.trim() || undefined;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "csvOutput") {
    config.csvOutput = raw.trim() || undefined;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "jsonlOutput") {
    config.jsonlOutput = raw.trim() || undefined;
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

  if (key === "confidenceCalibration") {
    const parsed = parseFlexibleValue(raw);
    if (typeof parsed !== "boolean") {
      throw new Error("confidenceCalibration must be true or false");
    }
    config.confidenceCalibration = parsed;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "confidenceSignalWeights") {
    const parsed = parseFlexibleValue(raw);
    if (!isRecord(parsed)) {
      throw new Error("confidenceSignalWeights must be an object");
    }
    config.confidenceSignalWeights = normalizeConfidenceSignalWeights(parsed);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "trajectoryMemory") {
    const parsed = parseFlexibleValue(raw);
    if (typeof parsed !== "boolean") {
      throw new Error("trajectoryMemory must be true or false");
    }
    config.trajectoryMemory = parsed;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "trajectoryMaxExemplars") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0) {
      throw new Error("trajectoryMaxExemplars must be a non-negative number");
    }
    config.trajectoryMaxExemplars = Math.floor(n);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "triageStrategy") {
    const strategy = raw.trim();
    if (strategy !== "single" && strategy !== "multi-agent") {
      throw new Error("triageStrategy must be one of: single, multi-agent");
    }
    config.triageStrategy = strategy;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "triageSpecialistMaxTurns") {
    if (raw === "null" || raw === "unlimited" || raw === "0") {
      config.triageSpecialistMaxTurns = null;
    } else {
      const n = Number(raw);
      if (!Number.isFinite(n) || n < 1) {
        throw new Error("triageSpecialistMaxTurns must be a positive number, 0, or 'unlimited'");
      }
      config.triageSpecialistMaxTurns = Math.floor(n);
    }
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "llmRescoreEnabled") {
    const parsed = parseFlexibleValue(raw);
    if (typeof parsed !== "boolean") throw new Error("llmRescoreEnabled must be true or false");
    config.llmRescoreEnabled = parsed;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "llmRescoreThreshold") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0 || n > 10) throw new Error("llmRescoreThreshold must be 0-10");
    config.llmRescoreThreshold = n;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "verifyBatchSize") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("verifyBatchSize must be a positive number");
    }
    config.verifyBatchSize = Math.floor(n);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "externalTasks") {
    config.externalTasks = coerceStringArray(raw);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "enableExternalTasks") {
    const parsed = parseFlexibleValue(raw);
    if (typeof parsed !== "boolean") {
      throw new Error("enableExternalTasks must be true or false");
    }
    config.enableExternalTasks = parsed;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "skipTriageForHighConfidenceAgentic") {
    const parsed = parseFlexibleValue(raw);
    if (typeof parsed !== "boolean") {
      throw new Error("skipTriageForHighConfidenceAgentic must be true or false");
    }
    config.skipTriageForHighConfidenceAgentic = parsed;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "ensembleModels") {
    config.ensembleModels = coerceStringArray(raw);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "pocRefinementMaxIterations") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("pocRefinementMaxIterations must be a positive number");
    }
    config.pocRefinementMaxIterations = Math.floor(n);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "pocReflectionInterval") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("pocReflectionInterval must be a positive number");
    }
    config.pocReflectionInterval = Math.floor(n);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "verifyRefinementMaxIterations") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("verifyRefinementMaxIterations must be a positive number");
    }
    config.verifyRefinementMaxIterations = Math.floor(n);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "verifyReflectionInterval") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("verifyReflectionInterval must be a positive number");
    }
    config.verifyReflectionInterval = Math.floor(n);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "triagePromptFile") {
    config.triagePromptFile = raw.trim() || undefined;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "verifyPromptFile") {
    config.verifyPromptFile = raw.trim() || undefined;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "cryptoBehavioralTestEnabled") {
    const parsed = parseFlexibleValue(raw);
    if (typeof parsed !== "boolean") {
      throw new Error("cryptoBehavioralTestEnabled must be true or false");
    }
    config.cryptoBehavioralTestEnabled = parsed;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "cryptoBehavioralTimeoutMs") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("cryptoBehavioralTimeoutMs must be a positive number");
    }
    config.cryptoBehavioralTimeoutMs = Math.floor(n);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "cryptoBehavioralMaxFindings") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("cryptoBehavioralMaxFindings must be a positive number");
    }
    config.cryptoBehavioralMaxFindings = Math.floor(n);
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "cryptoBehavioralPerFindingBudgetUsd") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n <= 0) {
      throw new Error("cryptoBehavioralPerFindingBudgetUsd must be a positive number");
    }
    config.cryptoBehavioralPerFindingBudgetUsd = n;
    saveUpdatedConfigLayer(config, repoRoot);
    return;
  }

  if (key === "qualityGates") {
    const parsed = parseFlexibleValue(raw);
    if (!isRecord(parsed)) {
      throw new Error("qualityGates must be an object");
    }
    config.qualityGates = normalizeQualityGateConfig(parsed);
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
    throw new Error(
      `Unknown config key: ${key}. Valid keys: ${[...VALID_TOP_LEVEL_KEYS].join(", ")}`,
    );
  }

  delete config[key];
  saveUpdatedConfigLayer(config, repoRoot);
}

function normalizeConfig(config: KuzushiConfig): KuzushiConfig {
  const tasks = normalizeStringArray(config.tasks);
  const severity = normalizeStringArray(config.severity);
  const excludePatterns = normalizeStringArray(config.excludePatterns);
  const busBackend = normalizeBusBackend(config.busBackend);
  const triageBatchSize = normalizePositiveInt(config.triageBatchSize, DEFAULTS.triageBatchSize);
  const triageConcurrency = normalizePositiveInt(
    config.triageConcurrency,
    DEFAULTS.triageConcurrency,
  );

  const verify = normalizeBoolean(config.verify, DEFAULTS.verify ?? false);
  const verifyMaxTurns =
    config.verifyMaxTurns == null ? undefined : normalizePositiveInt(config.verifyMaxTurns, 15);
  const verifyConcurrency = normalizePositiveInt(
    config.verifyConcurrency,
    DEFAULTS.verifyConcurrency ?? 1,
  );
  const verifyBatchSize = normalizePositiveInt(
    config.verifyBatchSize,
    DEFAULTS.verifyBatchSize ?? 5,
  );
  const verifyVerdictsRaw = normalizeVerdictArray(config.verifyVerdicts);
  const verifyVerdicts =
    verifyVerdictsRaw.length > 0 ? verifyVerdictsRaw : [...(DEFAULTS.verifyVerdicts ?? ["tp"])];
  const verifyMinConfidence = normalizeUnitInterval(
    config.verifyMinConfidence,
    DEFAULTS.verifyMinConfidence ?? 0,
  );
  const pocHarness = normalizeBoolean(config.pocHarness, DEFAULTS.pocHarness ?? false);
  const pocHarnessMaxTurns =
    config.pocHarnessMaxTurns == null
      ? undefined
      : normalizePositiveInt(config.pocHarnessMaxTurns, 20);
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
  const jsonOutput = normalizeOptionalString(config.jsonOutput);
  const csvOutput = normalizeOptionalString(config.csvOutput);
  const jsonlOutput = normalizeOptionalString(config.jsonlOutput);
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
  const confidenceSignalWeights = normalizeConfidenceSignalWeights(config.confidenceSignalWeights);
  const ensembleModels = normalizeStringArray(config.ensembleModels);
  const pocRefinementMaxIterations = normalizePositiveInt(
    config.pocRefinementMaxIterations,
    DEFAULTS.pocRefinementMaxIterations ?? 3,
  );
  const pocReflectionInterval = normalizePositiveInt(
    config.pocReflectionInterval,
    DEFAULTS.pocReflectionInterval ?? 2,
  );
  const verifyRefinementMaxIterations = normalizePositiveInt(
    config.verifyRefinementMaxIterations,
    DEFAULTS.verifyRefinementMaxIterations ?? 3,
  );
  const verifyReflectionInterval = normalizePositiveInt(
    config.verifyReflectionInterval,
    DEFAULTS.verifyReflectionInterval ?? 2,
  );
  const cryptoBehavioralTestEnabled = normalizeBoolean(
    config.cryptoBehavioralTestEnabled,
    DEFAULTS.cryptoBehavioralTestEnabled ?? false,
  );
  const cryptoBehavioralTimeoutMs = normalizePositiveInt(
    config.cryptoBehavioralTimeoutMs,
    DEFAULTS.cryptoBehavioralTimeoutMs ?? 120_000,
  );
  const cryptoBehavioralMaxFindings = normalizePositiveInt(
    config.cryptoBehavioralMaxFindings,
    DEFAULTS.cryptoBehavioralMaxFindings ?? 10,
  );
  const cryptoBehavioralPerFindingBudgetUsd = normalizePositiveNumber(
    config.cryptoBehavioralPerFindingBudgetUsd,
    DEFAULTS.cryptoBehavioralPerFindingBudgetUsd ?? 1,
  );
  const externalTasks = normalizeStringArray(config.externalTasks);
  const enableExternalTasks = normalizeBoolean(
    config.enableExternalTasks,
    DEFAULTS.enableExternalTasks ?? false,
  );
  const monorepo = normalizeMonorepoConfig(config.monorepo);

  const skipTriageForHighConfidenceAgentic = normalizeBoolean(
    config.skipTriageForHighConfidenceAgentic,
    DEFAULTS.skipTriageForHighConfidenceAgentic ?? false,
  );
  const normalizedTasks =
    tasks.length > 0 ? dedupeStringsPreserveOrder(tasks) : [...DEFAULTS.tasks];
  if (cryptoBehavioralTestEnabled) {
    normalizedTasks.push("crypto-behavioral-test");
  }
  if (config.codeGraphEnabled === true) {
    normalizedTasks.push("code-graph-build", "code-graph-enrich");
  }

  return {
    ...config,
    verify,
    verifyMaxTurns,
    verifyConcurrency,
    verifyBatchSize,
    verifyVerdicts,
    verifyMinConfidence,
    pocHarness,
    pocHarnessMaxTurns,
    pocHarnessConcurrency,
    enableContextGathering,
    auditLog,
    reportOutput,
    sarifOutput,
    jsonOutput,
    csvOutput,
    jsonlOutput,
    maxTriageRetries,
    maxVerifyRetries,
    maxPocHarnessRetries,
    retryBackoffMs,
    retryBackoffMultiplier,
    busBackend,
    triageBatchSize,
    triageConcurrency,
    scanMode,
    agentRuntimeBackend,
    agentRuntimeConfig,
    confidenceSignalWeights,
    ensembleModels,
    pocRefinementMaxIterations,
    pocReflectionInterval,
    verifyRefinementMaxIterations,
    verifyReflectionInterval,
    cryptoBehavioralTestEnabled,
    cryptoBehavioralTimeoutMs,
    cryptoBehavioralMaxFindings,
    cryptoBehavioralPerFindingBudgetUsd,
    externalTasks,
    enableExternalTasks,
    monorepo,
    skipTriageForHighConfidenceAgentic,
    tasks: dedupeStringsPreserveOrder(normalizedTasks),
    severity: severity.length > 0 ? severity : [...DEFAULTS.severity],
    excludePatterns,
    taskConfig: normalizeTaskConfigAliases(coerceTaskConfigMap(config.taskConfig)),
  };
}

function mergeConfigLayers(...layers: Array<unknown>): KuzushiConfig {
  const merged: KuzushiConfig = {
    ...DEFAULTS,
    taskConfig: cloneTaskConfig(DEFAULTS.taskConfig),
    externalTasks: [...(DEFAULTS.externalTasks ?? [])],
    ensembleModels: [...(DEFAULTS.ensembleModels ?? [])],
    tasks: [...DEFAULTS.tasks],
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

      if (key === "taskConfig") {
        if (!isRecord(value)) {
          continue;
        }

        const layerConfig = coerceTaskConfigMap(value);
        for (const [taskId, taskConfig] of Object.entries(layerConfig)) {
          merged.taskConfig[taskId] = {
            ...(merged.taskConfig[taskId] ?? {}),
            ...taskConfig,
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

      if (key === "confidenceSignalWeights") {
        if (value == null) {
          merged.confidenceSignalWeights = undefined;
          continue;
        }

        if (!isRecord(value)) {
          continue;
        }

        merged.confidenceSignalWeights = {
          ...(merged.confidenceSignalWeights ?? {}),
          ...normalizeConfidenceSignalWeights(value),
        };
        continue;
      }

      if (key === "qualityGates") {
        if (value == null) {
          merged.qualityGates = undefined;
          continue;
        }

        if (!isRecord(value)) {
          continue;
        }

        merged.qualityGates = normalizeQualityGateConfig({
          ...(merged.qualityGates ?? {}),
          ...cloneLayerValue(value),
        });
        continue;
      }

      if (key === "monorepo") {
        if (value == null) {
          merged.monorepo = undefined;
          continue;
        }

        if (!isRecord(value)) {
          continue;
        }

        merged.monorepo = {
          ...(merged.monorepo ?? {}),
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
    globalRaw: readConfigFile(configPath(), [CONFIG_DIR]),
    projectRaw: repoRoot ? readConfigFile(projectConfigPath(repoRoot), [repoRoot]) : {},
  };
}

function loadWritableConfigLayer(repoRoot?: string): WritableConfigLayer {
  return repoRoot
    ? readConfigFile(projectConfigPath(repoRoot), [repoRoot])
    : readConfigFile(configPath(), [CONFIG_DIR]);
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

  const globalRaw = readConfigFile(configPath(), [CONFIG_DIR]);
  mergeConfigLayers(globalRaw, layer);
}

/** Maximum config file size (1MB). */
const MAX_CONFIG_FILE_BYTES = 1_024 * 1_024;

/** Track config files being loaded to detect circular includes. */
const configLoadStack = new Set<string>();

function readConfigFile(configFilePath: string, allowedRoots: string[] = []): WritableConfigLayer {
  try {
    const resolvedPath = path.resolve(configFilePath);

    // Guard: circular reference detection
    if (configLoadStack.has(resolvedPath)) {
      log.warn(`Circular config reference detected for ${resolvedPath}, skipping`);
      return {};
    }

    // Guard: file size cap
    try {
      const stats = lstatSync(resolvedPath);
      if (stats.isSymbolicLink()) {
        const realPath = realpathSync(resolvedPath);
        if (
          allowedRoots.length > 0 &&
          !allowedRoots.some((root) => isPathWithinRoot(root, realPath))
        ) {
          log.warn(`Config symlink ${resolvedPath} points outside allowed directories, skipping`);
          return {};
        }
        const targetStats = lstatSync(realPath);
        if (targetStats.size > MAX_CONFIG_FILE_BYTES) {
          log.warn(`Config file ${realPath} exceeds 1MB limit, skipping`);
          return {};
        }
      } else if (stats.size > MAX_CONFIG_FILE_BYTES) {
        log.warn(`Config file ${resolvedPath} exceeds 1MB limit, skipping`);
        return {};
      }
    } catch (statErr) {
      if ((statErr as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw statErr;
    }

    configLoadStack.add(resolvedPath);
    try {
      const content = readFileSync(resolvedPath, "utf-8");
      const format: ConfigFormat = detectConfigFormat(resolvedPath);
      const parsed = parseConfigFile(content, format);
      if (!isRecord(parsed)) return {};
      // Resolve any file:// references relative to the config file's directory
      const resolved = resolveFileReferences(parsed, path.dirname(resolvedPath));
      return isRecord(resolved) ? resolved : {};
    } finally {
      configLoadStack.delete(resolvedPath);
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
    log.warn(`Config file ${configFilePath} is corrupt and will be ignored: ${err}`);
    return {};
  }
}

function sanitizeProjectConfigLayer(
  layer: WritableConfigLayer,
  repoRoot: string,
  options?: LoadConfigOptions,
): WritableConfigLayer {
  if (options?.trustProjectConfig === true) {
    return layer;
  }

  const stripped: string[] = [];
  const sanitized = stripUnsafeProjectConfigValue(cloneLayerValue(layer), [], stripped);
  if (stripped.length > 0) {
    log.warn(
      `Ignoring unsafe repo-local config keys from ${projectConfigPath(repoRoot)}: ${stripped.join(", ")}. ` +
        "Pass --trust-repo-config to opt in.",
    );
  }

  return isRecord(sanitized) ? (sanitized as WritableConfigLayer) : {};
}

function stripUnsafeProjectConfigValue(
  value: unknown,
  pathParts: string[],
  stripped: string[],
): unknown {
  if (pathParts.length > 0 && shouldStripProjectConfigPath(pathParts)) {
    stripped.push(pathParts.join("."));
    return undefined;
  }

  if (Array.isArray(value)) {
    return value
      .map((entry) => stripUnsafeProjectConfigValue(entry, pathParts, stripped))
      .filter((entry) => entry !== undefined);
  }

  if (!isRecord(value)) {
    return value;
  }

  const sanitized: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    const cleaned = stripUnsafeProjectConfigValue(entry, [...pathParts, key], stripped);
    if (cleaned !== undefined) {
      sanitized[key] = cleaned;
    }
  }

  return sanitized;
}

function shouldStripProjectConfigPath(pathParts: string[]): boolean {
  if (pathParts.length === 1 && UNSAFE_PROJECT_CONFIG_KEYS.has(pathParts[0])) {
    return true;
  }

  return (
    pathParts[0] === "taskConfig" &&
    pathParts.length >= 3 &&
    UNSAFE_PROJECT_TASK_CONFIG_KEYS.has(pathParts[pathParts.length - 1])
  );
}

function sanitizeConfigLayer(value: unknown): unknown {
  if (value === undefined) {
    return undefined;
  }

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeConfigLayer(item)).filter((item) => item !== undefined);
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

function coerceTaskConfigMap(value: unknown): Record<string, TaskConfig> {
  if (!isRecord(value)) return {};

  const result: Record<string, TaskConfig> = {};
  for (const [k, v] of Object.entries(value)) {
    if (!isRecord(v)) continue;
    result[k] = { ...v };
  }

  return result;
}

function coerceStringArray(raw: string): string[] {
  const parsed = raw.trim().startsWith("[")
    ? parseFlexibleValue(raw)
    : raw
        .split(",")
        .map((part) => part.trim())
        .filter(Boolean);

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
    : raw
        .split(",")
        .map((part) => part.trim())
        .filter(Boolean);

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

function dedupeStringsPreserveOrder(values: Iterable<string>): string[] {
  const result: string[] = [];
  const seen = new Set<string>();
  for (const raw of values) {
    const value = raw.trim();
    if (!value || seen.has(value)) {
      continue;
    }
    seen.add(value);
    result.push(value);
  }
  return result;
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

  throw new Error(`Invalid busBackend "${value}". Valid values: ${[...BUS_BACKENDS].join(", ")}`);
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
    `Invalid agentRuntimeBackend "${value}". ` +
      `Valid values: ${[...AGENT_RUNTIME_BACKENDS].join(", ")}`,
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
  if (!Number.isFinite(n) || n < 0 || n > 100) {
    return fallback;
  }
  if (n > 1) return n / 100;
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

function normalizeMonorepoConfig(value: unknown): KuzushiConfig["monorepo"] {
  if (!isRecord(value)) {
    return undefined;
  }

  const rawMode = normalizeOptionalString(value["mode"])?.toLowerCase();
  const mode = rawMode === "auto" || rawMode === "off" ? rawMode : undefined;

  const modules = Array.isArray(value["modules"])
    ? value["modules"]
        .filter((entry): entry is Record<string, unknown> => isRecord(entry))
        .map((entry) => {
          const name = normalizeOptionalString(entry["name"]);
          const modulePath = normalizeOptionalString(entry["path"]);
          if (!name || !modulePath) {
            return null;
          }

          return {
            name,
            path: modulePath,
            description: normalizeOptionalString(entry["description"]) ?? "",
            language: normalizeOptionalString(entry["language"]) ?? "unknown",
            buildSystem: normalizeOptionalString(entry["buildSystem"]),
            moduleKind:
              (normalizeOptionalString(entry["moduleKind"]) as
                | import("./discovery/types.js").ModuleKind
                | undefined) ?? "standalone",
            productPath: normalizeOptionalString(entry["productPath"]),
            discoveryEvidence: Array.isArray(entry["discoveryEvidence"])
              ? entry["discoveryEvidence"].filter((e): e is string => typeof e === "string")
              : ["config"],
          };
        })
        .filter((entry): entry is NonNullable<typeof entry> => entry !== null)
    : undefined;

  const excludeModules = normalizeStringArray(value["excludeModules"]);
  const discoveryModel = normalizeOptionalString(value["discoveryModel"]);
  const rawMaxModules = Number(value["maxModules"]);
  const maxModules =
    Number.isFinite(rawMaxModules) && rawMaxModules > 0 ? Math.floor(rawMaxModules) : undefined;
  const rawBudgetUsd = Number(value["budgetUsd"]);
  const budgetUsd = Number.isFinite(rawBudgetUsd) && rawBudgetUsd >= 0 ? rawBudgetUsd : undefined;
  const rawCrossModuleReserve = Number(value["crossModuleReserve"]);
  const crossModuleReserve =
    Number.isFinite(rawCrossModuleReserve) &&
    rawCrossModuleReserve >= 0 &&
    rawCrossModuleReserve <= 1
      ? rawCrossModuleReserve
      : undefined;
  const crossModuleTracing =
    typeof value["crossModuleTracing"] === "boolean" ? value["crossModuleTracing"] : undefined;
  const architecturalThreatModel =
    typeof value["architecturalThreatModel"] === "boolean"
      ? value["architecturalThreatModel"]
      : undefined;

  if (
    !mode &&
    !modules &&
    excludeModules.length === 0 &&
    !discoveryModel &&
    maxModules == null &&
    budgetUsd == null &&
    crossModuleReserve == null &&
    crossModuleTracing == null &&
    architecturalThreatModel == null
  ) {
    return undefined;
  }

  return {
    mode,
    modules,
    excludeModules: excludeModules.length > 0 ? excludeModules : undefined,
    discoveryModel,
    maxModules,
    budgetUsd,
    crossModuleReserve,
    crossModuleTracing,
    architecturalThreatModel,
  };
}

const VALID_SIGNAL_WEIGHT_KEYS = new Set<string>([
  "scanner",
  "triage",
  "verification",
  "history",
  "context",
]);

function normalizeConfidenceSignalWeights(value: unknown): ConfidenceSignalWeights | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  const result: ConfidenceSignalWeights = {};
  let hasAny = false;

  for (const [key, raw] of Object.entries(value)) {
    if (!VALID_SIGNAL_WEIGHT_KEYS.has(key)) {
      continue;
    }
    const n = Number(raw);
    if (Number.isFinite(n) && n >= 0) {
      result[key as keyof ConfidenceSignalWeights] = n;
      hasAny = true;
    }
  }

  return hasAny ? result : undefined;
}

function normalizeAgentRuntimeConfig(value: unknown): AgentRuntimeConfig | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  const apiKey = normalizeOptionalString(value["apiKey"]);
  const apiKeyFile = normalizeOptionalString(value["apiKeyFile"]);
  const baseUrl = normalizeOptionalString(value["baseUrl"]);

  if (!apiKey && !apiKeyFile && !baseUrl) {
    return undefined;
  }

  const normalized: AgentRuntimeConfig = {};
  if (apiKey) normalized.apiKey = apiKey;
  if (apiKeyFile) normalized.apiKeyFile = apiKeyFile;
  if (baseUrl) normalized.baseUrl = baseUrl;
  return normalized;
}

function normalizeQualityGateConfig(value: unknown): QualityGateConfig | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  const config: QualityGateConfig = {};
  let hasAnyField = false;

  if (typeof value["failOnHighSeverityTP"] === "boolean") {
    config.failOnHighSeverityTP = value["failOnHighSeverityTP"];
    hasAnyField = true;
  }

  if (value["maxOpenFindings"] != null) {
    const n = Number(value["maxOpenFindings"]);
    if (Number.isFinite(n) && n >= 0) {
      config.maxOpenFindings = Math.floor(n);
      hasAnyField = true;
    }
  }

  if (value["minTriageConfidence"] != null) {
    const n = Number(value["minTriageConfidence"]);
    if (Number.isFinite(n) && n >= 0 && n <= 1) {
      config.minTriageConfidence = n;
      hasAnyField = true;
    }
  }

  if (typeof value["failOnExploitable"] === "boolean") {
    config.failOnExploitable = value["failOnExploitable"];
    hasAnyField = true;
  }

  return hasAnyField ? config : undefined;
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

function cloneTaskConfig(value: Record<string, TaskConfig>): Record<string, TaskConfig> {
  const result: Record<string, TaskConfig> = {};
  for (const [k, v] of Object.entries(value)) {
    result[k] = { ...v };
  }
  return result;
}

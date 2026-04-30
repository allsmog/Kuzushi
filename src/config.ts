import { execFileSync } from "node:child_process";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { normalizeTaskConfigAliases } from "./capabilities.js";
import { AGENT_RUNTIME_BACKENDS, BUS_BACKENDS, DEFAULTS } from "./config/defaults.js";
import {
  CONFIG_DIR,
  CONFIG_PATH,
  configPath,
  findProjectConfigRoot,
  projectConfigPath,
} from "./config/paths.js";
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
import type {
  AgentRuntimeBackend,
  AgentRuntimeConfig,
  AgentRuntimeCredentials,
  KuzushiConfig,
  Verdict,
} from "./types.js";
import { isPathWithinRoot, isRecord, toErrorMessage } from "./utils.js";

type ConfigLayer = Record<string, unknown>;
type WritableConfigLayer = Partial<KuzushiConfig> & ConfigLayer;
const log = getLogger("config");

export { configPath, DEFAULTS, projectConfigPath };

const LOCAL_CREDENTIALS_FILENAME = "credentials.json";

/**
 * Resolve the project-local credentials file path: `<cwd>/.kuzushi/credentials.json`.
 * This file is treated as user-trusted (it's never embedded in a repo by an
 * attacker — the user types it through `/auth`) so it bypasses the
 * UNSAFE_PROJECT_CONFIG_KEYS strip applied to project `config.json`.
 */
export function localCredentialsPath(cwd: string = process.cwd()): string {
  return path.join(cwd, ".kuzushi", LOCAL_CREDENTIALS_FILENAME);
}

/**
 * Read the project-local credentials file at `<cwd>/.kuzushi/credentials.json`.
 *
 * Accepts the per-backend shape: `{ claude: {...}, piAi: {...}, codex: {...} }`.
 */
export function loadLocalCredentials(cwd: string = process.cwd()): AgentRuntimeConfig | undefined {
  const filePath = localCredentialsPath(cwd);
  if (!existsSync(filePath)) return undefined;
  try {
    const raw = JSON.parse(readFileSync(filePath, "utf-8")) as unknown;
    const normalized = normalizeAgentRuntimeConfig(raw);
    return normalized;
  } catch (error) {
    log.warn(`Failed to read local credentials at ${filePath}: ${String(error)}`);
    return undefined;
  }
}

/**
 * Persist credentials to `<cwd>/.kuzushi/credentials.json` and best-effort add
 * the file to `<cwd>/.gitignore` so it isn't accidentally committed.
 *
 * Returns the absolute path the file was written to.
 */
export function persistLocalCredentials(
  creds: AgentRuntimeConfig,
  cwd: string = process.cwd(),
): string {
  const filePath = localCredentialsPath(cwd);
  const targetDir = path.dirname(filePath);
  if (!existsSync(targetDir)) {
    mkdirSync(targetDir, { recursive: true });
  }

  const existing = loadLocalCredentials(cwd) ?? {};
  // Deep merge each backend slot so writing claude doesn't wipe piAi, and
  // each slot's apiKey/authToken/baseUrl merge field-wise rather than replacing the
  // whole object.
  const merged: AgentRuntimeConfig = {
    claude: { ...(existing.claude ?? {}), ...(creds.claude ?? {}) },
    piAi: { ...(existing.piAi ?? {}), ...(creds.piAi ?? {}) },
    codex: { ...(existing.codex ?? {}), ...(creds.codex ?? {}) },
  };
  if (!merged.claude || Object.keys(merged.claude).length === 0) delete merged.claude;
  if (!merged.piAi || Object.keys(merged.piAi).length === 0) delete merged.piAi;
  if (!merged.codex || Object.keys(merged.codex).length === 0) delete merged.codex;
  writeFileSync(filePath, `${JSON.stringify(merged, null, 2)}\n`, {
    encoding: "utf-8",
    mode: 0o600,
  });

  // Best-effort .gitignore add. Skips silently when the cwd has no .gitignore
  // and isn't a git repo we recognize, to avoid creating noise.
  try {
    const gitignorePath = path.join(cwd, ".gitignore");
    const entry = ".kuzushi/credentials.json";
    let body = "";
    if (existsSync(gitignorePath)) {
      body = readFileSync(gitignorePath, "utf-8");
      const lines = body.split(/\r?\n/);
      if (
        lines.some((line) => line.trim() === entry || line.trim() === "/.kuzushi/credentials.json")
      ) {
        return filePath;
      }
      const trailingNewline = body.endsWith("\n") ? "" : "\n";
      body = `${body}${trailingNewline}${entry}\n`;
      writeFileSync(gitignorePath, body, "utf-8");
    } else if (existsSync(path.join(cwd, ".git"))) {
      // Has .git/ but no .gitignore yet — create one with just our entry.
      writeFileSync(gitignorePath, `${entry}\n`, "utf-8");
    }
  } catch (error) {
    log.warn(`Failed to update .gitignore at ${cwd}: ${String(error)}`);
  }

  return filePath;
}

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
  rejectLegacyAgentRuntimePath(key);

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

  const setter = TOP_LEVEL_CONFIG_SETTERS[key];
  if (!setter) {
    // Key is valid per the schema but not settable via `setConfigValue`
    // (only via config-file edits or env vars). The original ladder landed
    // here at its fall-through `throw` — preserved for behavior parity.
    throw new Error(`Unknown config key: ${key}`);
  }
  setter(config, raw);
  saveUpdatedConfigLayer(config, repoRoot);
}

type ConfigSetter = (config: WritableConfigLayer, raw: string) => void;

function setBool(field: string): ConfigSetter {
  return (config, raw) => {
    const parsed = parseFlexibleValue(raw);
    if (typeof parsed !== "boolean") {
      throw new Error(`${field} must be true or false`);
    }
    (config as Record<string, unknown>)[field] = parsed;
  };
}

function setPositiveInt(field: string): ConfigSetter {
  return (config, raw) => {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error(`${field} must be a positive number`);
    }
    (config as Record<string, unknown>)[field] = Math.floor(n);
  };
}

function setNonNegInt(field: string): ConfigSetter {
  return (config, raw) => {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0) {
      throw new Error(`${field} must be a non-negative number`);
    }
    (config as Record<string, unknown>)[field] = Math.floor(n);
  };
}

function setPositiveNumber(field: string): ConfigSetter {
  return (config, raw) => {
    const n = Number(raw);
    if (!Number.isFinite(n) || n <= 0) {
      throw new Error(`${field} must be a positive number`);
    }
    (config as Record<string, unknown>)[field] = n;
  };
}

function setOptionalString(field: string): ConfigSetter {
  return (config, raw) => {
    (config as Record<string, unknown>)[field] = raw.trim() || undefined;
  };
}

function setEnum(field: string, values: Set<string>): ConfigSetter {
  return (config, raw) => {
    const v = raw.trim();
    if (!values.has(v)) {
      throw new Error(`${field} must be one of: ${[...values].join(", ")}`);
    }
    (config as Record<string, unknown>)[field] = v;
  };
}

function setStringList(field: string): ConfigSetter {
  return (config, raw) => {
    (config as Record<string, unknown>)[field] = coerceStringArray(raw);
  };
}

/**
 * Handler map for top-level config keys that are settable via
 * `setConfigValue` (CLI `config set` + shell `/config set`). Each handler
 * validates `raw` and mutates `config` in place; the outer `setConfigValue`
 * calls `saveUpdatedConfigLayer` once after dispatch.
 *
 * Not every schema key needs a handler — some fields (e.g. `hooks`,
 * `monorepo`, `chainAnalysis`) are set by config-file edit or env var only.
 * A drift-proofing test asserts the map contains no orphan keys (every
 * handler key is a valid schema key), preventing typos.
 */
export const TOP_LEVEL_CONFIG_SETTERS: Record<string, ConfigSetter> = {
  // Core
  tasks: setStringList("tasks"),
  taskConfig: (config, raw) => {
    const parsed = parseFlexibleValue(raw);
    if (!isRecord(parsed)) {
      throw new Error("taskConfig must be an object");
    }
    config.taskConfig = coerceTaskConfigMap(parsed);
  },
  model: (config, raw) => {
    config.model = raw;
  },
  severity: setStringList("severity"),
  excludePatterns: setStringList("excludePatterns"),
  costBudgetUsd: setPositiveNumber("costBudgetUsd"),
  prioritizeFindings: setBool("prioritizeFindings"),
  scanMode: setEnum("scanMode", new Set(["sequential", "concurrent"])),

  // Agent runtime + bus
  agentRuntimeBackend: setEnum("agentRuntimeBackend", AGENT_RUNTIME_BACKENDS),
  agentRuntimeConfig: (config, raw) => {
    const parsed = parseFlexibleValue(raw);
    if (!isRecord(parsed)) {
      throw new Error("agentRuntimeConfig must be an object");
    }
    rejectLegacyAgentRuntimeConfig(parsed);
    config.agentRuntimeConfig = normalizeAgentRuntimeConfig(parsed);
  },
  auth: (config, raw) => {
    const v = String(raw).trim().toLowerCase();
    if (v === "" || v === "none" || v === "null") {
      delete (config as Partial<KuzushiConfig>).auth;
      return;
    }
    if (v !== "inherited") {
      throw new Error('auth must be "inherited" or unset');
    }
    config.auth = "inherited";
  },
  busBackend: setEnum("busBackend", BUS_BACKENDS),

  // Triage
  triageBatchSize: setPositiveInt("triageBatchSize"),
  triageConcurrency: setPositiveInt("triageConcurrency"),
  triageStrategy: setEnum("triageStrategy", new Set(["single", "multi-agent"])),
  triageSpecialistMaxTurns: (config, raw) => {
    // "null"/"unlimited"/"0" all map to null meaning "no turn cap"; any other
    // value must parse as a positive integer.
    if (raw === "null" || raw === "unlimited" || raw === "0") {
      config.triageSpecialistMaxTurns = null;
      return;
    }
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("triageSpecialistMaxTurns must be a positive number, 0, or 'unlimited'");
    }
    config.triageSpecialistMaxTurns = Math.floor(n);
  },
  triagePromptFile: setOptionalString("triagePromptFile"),

  // Verify
  verify: setBool("verify"),
  verifyMaxTurns: setPositiveInt("verifyMaxTurns"),
  verifyConcurrency: setPositiveInt("verifyConcurrency"),
  verifyBatchSize: setPositiveInt("verifyBatchSize"),
  verifyVerdicts: (config, raw) => {
    config.verifyVerdicts = coerceVerdictArray(raw);
  },
  verifyMinConfidence: (config, raw) => {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0 || n > 100) {
      throw new Error(
        "verifyMinConfidence must be a number between 0 and 1 (or 0-100 as a percentage)",
      );
    }
    config.verifyMinConfidence = n > 1 ? n / 100 : n;
  },
  verifyRefinementMaxIterations: setPositiveInt("verifyRefinementMaxIterations"),
  verifyReflectionInterval: setPositiveInt("verifyReflectionInterval"),
  verifyPromptFile: setOptionalString("verifyPromptFile"),

  // PoC harness
  pocHarness: setBool("pocHarness"),
  pocHarnessMaxTurns: setPositiveInt("pocHarnessMaxTurns"),
  pocHarnessConcurrency: setPositiveInt("pocHarnessConcurrency"),
  pocRefinementMaxIterations: setPositiveInt("pocRefinementMaxIterations"),
  pocReflectionInterval: setPositiveInt("pocReflectionInterval"),

  // Context, audit, retries
  enableContextGathering: setBool("enableContextGathering"),
  auditLog: setBool("auditLog"),
  maxTriageRetries: setNonNegInt("maxTriageRetries"),
  maxVerifyRetries: setNonNegInt("maxVerifyRetries"),
  maxPocHarnessRetries: setNonNegInt("maxPocHarnessRetries"),
  retryBackoffMs: setNonNegInt("retryBackoffMs"),
  retryBackoffMultiplier: setPositiveNumber("retryBackoffMultiplier"),

  // Output destinations
  reportOutput: setOptionalString("reportOutput"),
  sarifOutput: setOptionalString("sarifOutput"),
  jsonOutput: setOptionalString("jsonOutput"),
  csvOutput: setOptionalString("csvOutput"),
  jsonlOutput: setOptionalString("jsonlOutput"),

  // Confidence + trajectory
  confidenceCalibration: setBool("confidenceCalibration"),
  confidenceSignalWeights: (config, raw) => {
    const parsed = parseFlexibleValue(raw);
    if (!isRecord(parsed)) {
      throw new Error("confidenceSignalWeights must be an object");
    }
    config.confidenceSignalWeights = normalizeConfidenceSignalWeights(parsed);
  },
  trajectoryMemory: setBool("trajectoryMemory"),
  trajectoryMaxExemplars: setNonNegInt("trajectoryMaxExemplars"),

  // LLM rescore
  llmRescoreEnabled: setBool("llmRescoreEnabled"),
  llmRescoreThreshold: (config, raw) => {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0 || n > 10) {
      throw new Error("llmRescoreThreshold must be 0-10");
    }
    config.llmRescoreThreshold = n;
  },

  skipTriageForHighConfidenceAgentic: setBool("skipTriageForHighConfidenceAgentic"),
  ensembleModels: setStringList("ensembleModels"),

  // Crypto behavioral
  cryptoBehavioralTestEnabled: setBool("cryptoBehavioralTestEnabled"),
  cryptoBehavioralTimeoutMs: setPositiveInt("cryptoBehavioralTimeoutMs"),
  cryptoBehavioralMaxFindings: setPositiveInt("cryptoBehavioralMaxFindings"),
  cryptoBehavioralPerFindingBudgetUsd: setPositiveNumber("cryptoBehavioralPerFindingBudgetUsd"),

  // Quality gates
  qualityGates: (config, raw) => {
    const parsed = parseFlexibleValue(raw);
    if (!isRecord(parsed)) {
      throw new Error("qualityGates must be an object");
    }
    config.qualityGates = normalizeQualityGateConfig(parsed);
  },
};

/** One entry in a config patch: a dotted path and the parsed value to set, or `undefined` to unset. */
export interface ConfigPatchEntry {
  path: string;
  value: unknown;
}

/**
 * Apply a batch of changes to the writable config layer in one round-trip.
 *
 * The interactive config editor uses this to persist a diff of edits without
 * going through the per-key validator cascade in `setConfigValue`. Entries
 * use dotted paths (e.g. `"taskConfig.taint-analysis.tiMode"`) so only the
 * touched leaves are rewritten — the rest of the user's config file stays
 * untouched. The final `saveUpdatedConfigLayer` call still runs through
 * `validateConfigLayer` → `mergeConfigLayers` → `normalizeConfig`, so invalid
 * values surface the same way they do for `setConfigValue`.
 */
export function applyConfigPatch(entries: ConfigPatchEntry[], repoRoot?: string): void {
  if (entries.length === 0) return;
  const layer = loadWritableConfigLayer(repoRoot);
  for (const { path: dottedPath, value } of entries) {
    const parts = dottedPath.split(".");
    validatePathParts(parts);
    if (value === undefined) {
      unsetByPath(layer, parts);
      continue;
    }
    if (parts.length === 1) {
      (layer as Record<string, unknown>)[parts[0]] = value;
    } else {
      setByPath(layer, parts, value);
    }
  }
  saveUpdatedConfigLayer(layer, repoRoot);
}

/** Unset a config key (supports dotted paths). */
export function unsetConfigValue(key: string, repoRoot?: string): void {
  const config = loadWritableConfigLayer(repoRoot);
  rejectLegacyAgentRuntimePath(key);

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

        const normalizedLayer = normalizeAgentRuntimeConfig(value);
        if (!normalizedLayer) continue;
        const existing = merged.agentRuntimeConfig ?? {};
        // Deep-merge each backend slot so a project layer setting claude.baseUrl
        // doesn't wipe a global claude.apiKey/authToken.
        merged.agentRuntimeConfig = {
          claude: { ...(existing.claude ?? {}), ...(normalizedLayer.claude ?? {}) },
          piAi: { ...(existing.piAi ?? {}), ...(normalizedLayer.piAi ?? {}) },
          codex: { ...(existing.codex ?? {}), ...(normalizedLayer.codex ?? {}) },
        };
        if (
          !merged.agentRuntimeConfig.claude ||
          Object.keys(merged.agentRuntimeConfig.claude).length === 0
        ) {
          delete merged.agentRuntimeConfig.claude;
        }
        if (
          !merged.agentRuntimeConfig.piAi ||
          Object.keys(merged.agentRuntimeConfig.piAi).length === 0
        ) {
          delete merged.agentRuntimeConfig.piAi;
        }
        if (
          !merged.agentRuntimeConfig.codex ||
          Object.keys(merged.agentRuntimeConfig.codex).length === 0
        ) {
          delete merged.agentRuntimeConfig.codex;
        }
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
  // For reads, walk up from `repoRoot` (or cwd) to find the nearest
  // ancestor's `.kuzushi/config.json`. Operators reasonably expect
  // `kuzushi shell` from `<repo>/sub/dir/` to honor `<repo>/.kuzushi/config.json`
  // — without this, only cwd-rooted configs are loaded and the operator's
  // per-repo config is silently ignored.
  const readRoot = findProjectConfigRoot(repoRoot ?? process.cwd()) ?? repoRoot;
  return {
    globalRaw: readConfigFile(configPath(), [CONFIG_DIR]),
    projectRaw: readRoot ? readConfigFile(projectConfigPath(readRoot), [readRoot]) : {},
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

function rejectLegacyAgentRuntimePath(key: string): void {
  if (!/^agentRuntimeConfig\.(apiKey|authToken|baseUrl)$/.test(key)) return;
  const field = key.split(".").at(-1);
  throw new Error(
    `Legacy config key "${key}" was removed. Use "agentRuntimeConfig.claude.${field}" instead.`,
  );
}

function rejectLegacyAgentRuntimeConfig(value: Record<string, unknown>): void {
  if (!("apiKey" in value || "authToken" in value || "baseUrl" in value)) return;
  throw new Error(
    'Legacy flat agentRuntimeConfig was removed. Use {"claude":{"apiKey":"..."}} or another backend slot.',
  );
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
    const projectPath = projectConfigPath(repoRoot);
    log.warn(
      `Ignoring unsafe repo-local config keys from ${projectPath}: ${stripped.join(", ")}. ` +
        "Pass --trust-repo-config to opt in.",
    );
    // The log.warn above is invisible once Ink takes over the terminal.
    // For credential-bearing strips, surface a one-line stderr banner so the
    // operator knows their per-repo creds are being silently dropped.
    // Idempotent + opt-out via KUZUSHI_QUIET_CRED_BANNER=1.
    surfaceCredStripBanner(stripped, projectPath);
  }

  return isRecord(sanitized) ? (sanitized as WritableConfigLayer) : {};
}

let credStripBannerEmitted = false;
const CRED_BEARING_KEYS = new Set(["agentRuntimeConfig", "agentRuntimeBackend", "credentials"]);
function surfaceCredStripBanner(strippedKeys: string[], projectPath: string): void {
  if (credStripBannerEmitted) return;
  if (process.env.KUZUSHI_QUIET_CRED_BANNER) return;
  const credKeys = strippedKeys.filter((k) => {
    const head = k.split(".")[0] ?? "";
    return CRED_BEARING_KEYS.has(head);
  });
  if (credKeys.length === 0) return;
  credStripBannerEmitted = true;
  process.stderr.write(
    `[kuzushi] Detected creds in ${projectPath} (project config). These keys aren't honored from project config.json: ${credKeys.join(", ")}. ` +
      "Move them to .kuzushi/credentials.json or set ANTHROPIC_API_KEY in env. " +
      "Silence with KUZUSHI_QUIET_CRED_BANNER=1.\n",
  );
}

/** Test-only reset for the idempotent cred-strip banner. */
export function _resetCredStripBannerForTests(): void {
  credStripBannerEmitted = false;
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

function normalizeAgentRuntimeCredentials(value: unknown): AgentRuntimeCredentials | undefined {
  if (!isRecord(value)) return undefined;
  const apiKey = normalizeOptionalString(value["apiKey"]);
  const authToken = normalizeOptionalString(value["authToken"]);
  const baseUrl = normalizeOptionalString(value["baseUrl"]);
  if (!apiKey && !authToken && !baseUrl) return undefined;
  const out: AgentRuntimeCredentials = {};
  if (apiKey) out.apiKey = apiKey;
  if (authToken) out.authToken = authToken;
  if (baseUrl) out.baseUrl = baseUrl;
  return out;
}

function normalizeAgentRuntimeConfig(value: unknown): AgentRuntimeConfig | undefined {
  if (!isRecord(value)) return undefined;

  const claudeFromSlot = normalizeAgentRuntimeCredentials(value["claude"]);
  const piAiFromSlot = normalizeAgentRuntimeCredentials(value["piAi"]);
  const codexFromSlot = normalizeAgentRuntimeCredentials(value["codex"]);

  if (!claudeFromSlot && !piAiFromSlot && !codexFromSlot) return undefined;

  const out: AgentRuntimeConfig = {};
  if (claudeFromSlot) out.claude = claudeFromSlot;
  if (piAiFromSlot) out.piAi = piAiFromSlot;
  if (codexFromSlot) out.codex = codexFromSlot;
  return out;
}

export function resolveActiveCredentials(
  config: Pick<KuzushiConfig, "agentRuntimeBackend" | "agentRuntimeConfig">,
): AgentRuntimeCredentials {
  const backend = config.agentRuntimeBackend ?? "pi-ai";
  const slot = backendConfigSlot(backend);
  return config.agentRuntimeConfig?.[slot] ?? {};
}

/** Slot name for `agentRuntimeConfig` that matches a backend id. */
export function backendConfigSlot(
  backend: AgentRuntimeBackend | undefined,
): "claude" | "piAi" | "codex" {
  if (backend === "codex") return "codex";
  return (backend ?? "pi-ai") === "pi-ai" ? "piAi" : "claude";
}

/**
 * Env var name for a provider's API key. Matches pi-ai's env resolution
 * so setting via /auth mirrors what an operator would get by exporting.
 */
export function providerEnvVar(providerId: string): string | undefined {
  const map: Record<string, string> = {
    anthropic: "ANTHROPIC_API_KEY",
    openai: "OPENAI_API_KEY",
    google: "GOOGLE_API_KEY",
    mistral: "MISTRAL_API_KEY",
    groq: "GROQ_API_KEY",
    cerebras: "CEREBRAS_API_KEY",
    xai: "XAI_API_KEY",
    openrouter: "OPENROUTER_API_KEY",
  };
  return map[providerId];
}

export interface AmbientOauthResolution {
  /** The OAuth bearer token (raw `sk-ant-oat...` string). */
  token: string;
  /**
   * Human-readable description of where the token came from
   * (e.g. `env:ANTHROPIC_OAUTH_TOKEN`, `file:/home/.../.oauth_token`).
   * Surfaced in `kuzushi doctor` and the inherited-auth log line.
   */
  source: string;
}

/**
 * Walk a deterministic search path looking for an Anthropic OAuth bearer
 * token to use as the runtime credential. Resolution order:
 *
 *   1. `ANTHROPIC_API_KEY` env var if it has the OAuth shape (`sk-ant-oat`).
 *   2. `ANTHROPIC_OAUTH_TOKEN` env var.
 *   3. `ANTHROPIC_OAUTH_TOKEN_FILE` env var → file contents.
 *   4. `config.oauthTokenFile` → file contents.
 *   5. `~/.claude/remote/.oauth_token` (Claude Code remote sandbox).
 *   6. `~/.claude/.credentials.json` → `claudeAiOauth.accessToken`.
 *   7. macOS Keychain `Claude Code-credentials` → `claudeAiOauth.accessToken`.
 *
 * Used by inherited-auth mode so operators in a Claude Code child
 * session don't have to copy-paste a key. Returns `undefined` when no
 * token is discoverable; callers may then fall through to the existing
 * credential prompt or fail in `kuzushi doctor`.
 */
export function resolveAmbientOauthToken(
  config: Pick<KuzushiConfig, "oauthTokenFile">,
): AmbientOauthResolution | undefined {
  const envApi = process.env["ANTHROPIC_API_KEY"]?.trim();
  if (envApi?.startsWith("sk-ant-oat")) {
    return { token: envApi, source: "env:ANTHROPIC_API_KEY" };
  }

  const envOauth = process.env["ANTHROPIC_OAUTH_TOKEN"]?.trim();
  if (envOauth) {
    return { token: envOauth, source: "env:ANTHROPIC_OAUTH_TOKEN" };
  }

  const envFile = process.env["ANTHROPIC_OAUTH_TOKEN_FILE"]?.trim();
  if (envFile) {
    const tok = readOauthFile(envFile);
    if (tok) return { token: tok, source: `env:ANTHROPIC_OAUTH_TOKEN_FILE (${envFile})` };
  }

  if (config.oauthTokenFile) {
    const tok = readOauthFile(config.oauthTokenFile);
    if (tok) return { token: tok, source: `config:oauthTokenFile (${config.oauthTokenFile})` };
  }

  // Probe the current user's home plus any well-known fallbacks (e.g.
  // `/home/claude`, which Claude Code's remote sandbox mounts the
  // credential into independent of the running user). The fallback list
  // is overrideable via `KUZUSHI_OAUTH_WELL_KNOWN_HOMES` (colon-separated)
  // — set it to an empty string to disable, e.g. in tests.
  const homedirs = new Set<string>([os.homedir(), ...wellKnownOauthHomes()]);
  for (const home of homedirs) {
    const remotePath = path.join(home, ".claude", "remote", ".oauth_token");
    const remoteToken = tryReadFile(remotePath)?.trim();
    if (remoteToken?.startsWith("sk-ant-oat")) {
      return { token: remoteToken, source: `file:${remotePath}` };
    }
  }
  for (const home of homedirs) {
    const credsPath = path.join(home, ".claude", ".credentials.json");
    const credsRaw = tryReadFile(credsPath);
    if (credsRaw) {
      const parsed = parseCredentialsJson(credsRaw);
      if (parsed) return { token: parsed, source: `file:${credsPath}` };
    }
  }

  const keychainToken = readClaudeCodeKeychainOauthToken();
  if (keychainToken) {
    return { token: keychainToken, source: "macOS Keychain:Claude Code-credentials" };
  }

  return undefined;
}

/**
 * Read a file that contains either a raw OAuth token or a Claude Code
 * `.credentials.json` document. Trims surrounding whitespace.
 */
function readOauthFile(filePath: string): string | undefined {
  const raw = tryReadFile(filePath);
  if (!raw) return undefined;
  if (raw.trim().startsWith("{")) {
    const parsed = parseCredentialsJson(raw);
    if (parsed) return parsed;
  }
  return raw.trim() || undefined;
}

function parseCredentialsJson(raw: string): string | undefined {
  try {
    const j = JSON.parse(raw) as Record<string, unknown>;
    const oauth = j["claudeAiOauth"];
    if (oauth && typeof oauth === "object") {
      const tok = (oauth as Record<string, unknown>)["accessToken"];
      if (typeof tok === "string" && tok.trim()) return tok.trim();
    }
    const flat = j["accessToken"];
    if (typeof flat === "string" && flat.trim()) return flat.trim();
  } catch {
    // fall through
  }
  return undefined;
}

function readClaudeCodeKeychainOauthToken(): string | undefined {
  if (process.env["KUZUSHI_OAUTH_DISABLE_KEYCHAIN"] === "1") return undefined;
  if (process.platform !== "darwin") return undefined;
  try {
    const raw = execFileSync(
      "security",
      ["find-generic-password", "-s", "Claude Code-credentials", "-w"],
      {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      },
    );
    return parseCredentialsJson(raw) ?? (raw.trim() || undefined);
  } catch {
    return undefined;
  }
}

function tryReadFile(filePath: string): string | undefined {
  try {
    return readFileSync(filePath, "utf8");
  } catch {
    return undefined;
  }
}

/**
 * True when the host process is a Claude Code subagent that manages its
 * own auth via the parent's session (file-descriptor or proxy). Setting
 * `ANTHROPIC_API_KEY` in this state is actively harmful: the spawned
 * `claude` CLI treats the env var as a fresh session with its own cache
 * — costing ~12× per spawn vs. inheriting the host-managed cache (see
 * field-test issue #20). Detection signals are env vars set
 * unconditionally by the Claude Code remote runner.
 */
export function isClaudeCodeHostManagedAuth(): boolean {
  if (process.env["CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST"]) return true;
  if (process.env["CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR"]) return true;
  return false;
}

/**
 * Default fallback home directories to probe for ambient OAuth tokens.
 * `KUZUSHI_OAUTH_WELL_KNOWN_HOMES` overrides this (colon-separated, set
 * to "" to disable entirely — useful in tests).
 */
function wellKnownOauthHomes(): string[] {
  const override = process.env["KUZUSHI_OAUTH_WELL_KNOWN_HOMES"];
  if (override !== undefined) {
    return override
      .split(":")
      .map((s) => s.trim())
      .filter(Boolean);
  }
  return ["/home/claude"];
}

/**
 * Env var name for a provider's base URL override.
 */
export function providerBaseUrlEnvVar(providerId: string): string | undefined {
  const map: Record<string, string> = {
    anthropic: "ANTHROPIC_BASE_URL",
    openai: "OPENAI_BASE_URL",
    google: "GOOGLE_BASE_URL",
  };
  return map[providerId];
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
    } catch (error) {
      throw new Error(`Invalid JSON value: ${trimmed.slice(0, 80)} (${toErrorMessage(error)})`);
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

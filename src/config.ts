import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import type { KuzushiConfig, Verdict } from "./types.js";
import type { ScannerConfig } from "./scanners/types.js";
import { isRecord } from "./utils.js";
import { augurRoot } from "@kuzushi/augur";

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
  "claude-sdk",
  "pi-ai",
  "acp",
]);
const DEFAULT_AUGUR_PATH = process.env["AUGUR_PATH"]?.trim() || augurRoot;

/** Hard defaults — the bottom of the precedence stack. */
export const DEFAULTS: KuzushiConfig = {
  model: "claude-sonnet-4-20250514",
  triageMaxTurns: 10,
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
  triageConcurrency: 1,
  scanMode: "sequential",
  agentRuntimeBackend: "claude-sdk",
  enabledTasks: [],
  scanners: ["semgrep"],
  severity: ["ERROR", "WARNING"],
  excludePatterns: [
    "test", "tests", "spec", "vendor",
    "node_modules", "__tests__", "*.min.js", "*.min.css",
  ],
  scannerConfig: {
    semgrep: { configFlag: "auto" },
    agentic: { model: "claude-sonnet-4-20250514", maxFindings: 20 },
    codeql: {},
    augur: {
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
    },
  },
};

const VALID_TOP_LEVEL_KEYS = new Set<string>([
  ...Object.keys(DEFAULTS),
  "triageModel",
  "verifyModel",
  "pocHarnessModel",
]);

/** Load config from ~/.kuzushi/config.json + optional <repo>/.kuzushi/config.json. */
export function loadConfig(repoRoot?: string): KuzushiConfig {
  const globalRaw = readConfigFile(CONFIG_PATH);
  const projectRaw = repoRoot
    ? readConfigFile(projectConfigPath(repoRoot))
    : {};

  const merged = mergeConfigLayers(DEFAULTS, globalRaw, projectRaw);
  return normalizeConfig(merged);
}

/** Save config. If repoRoot is provided, writes project config. */
export function saveConfig(config: KuzushiConfig, repoRoot?: string): void {
  const targetPath = repoRoot ? projectConfigPath(repoRoot) : CONFIG_PATH;
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
  const config = loadConfig(repoRoot);

  if (key.includes(".")) {
    setByPath(config, key.split("."), parseFlexibleValue(raw));
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (!VALID_TOP_LEVEL_KEYS.has(key)) {
    throw new Error(`Unknown config key: ${key}. Valid keys: ${[...VALID_TOP_LEVEL_KEYS].join(", ")}`);
  }

  if (key === "scanners") {
    config.scanners = coerceStringArray(raw);
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "enabledTasks") {
    config.enabledTasks = coerceStringArray(raw);
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "scannerConfig") {
    const parsed = parseFlexibleValue(raw);
    if (!isRecord(parsed)) {
      throw new Error("scannerConfig must be an object");
    }
    config.scannerConfig = coerceScannerConfigMap(parsed);
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "triageConcurrency") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("triageConcurrency must be a positive number");
    }
    config.triageConcurrency = Math.floor(n);
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "triageMaxTurns") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("triageMaxTurns must be a positive number");
    }
    config.triageMaxTurns = Math.floor(n);
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "verify") {
    const parsed = parseFlexibleValue(raw);
    if (typeof parsed !== "boolean") {
      throw new Error("verify must be true or false");
    }
    config.verify = parsed;
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "verifyMaxTurns") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("verifyMaxTurns must be a positive number");
    }
    config.verifyMaxTurns = Math.floor(n);
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "verifyConcurrency") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("verifyConcurrency must be a positive number");
    }
    config.verifyConcurrency = Math.floor(n);
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "verifyVerdicts") {
    config.verifyVerdicts = coerceVerdictArray(raw);
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "verifyMinConfidence") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0 || n > 1) {
      throw new Error("verifyMinConfidence must be a number between 0 and 1");
    }
    config.verifyMinConfidence = n;
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "pocHarness") {
    const parsed = parseFlexibleValue(raw);
    if (typeof parsed !== "boolean") {
      throw new Error("pocHarness must be true or false");
    }
    config.pocHarness = parsed;
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "pocHarnessMaxTurns") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("pocHarnessMaxTurns must be a positive number");
    }
    config.pocHarnessMaxTurns = Math.floor(n);
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "pocHarnessConcurrency") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 1) {
      throw new Error("pocHarnessConcurrency must be a positive number");
    }
    config.pocHarnessConcurrency = Math.floor(n);
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "enableContextGathering") {
    const parsed = parseFlexibleValue(raw);
    if (typeof parsed !== "boolean") {
      throw new Error("enableContextGathering must be true or false");
    }
    config.enableContextGathering = parsed;
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "auditLog") {
    const parsed = parseFlexibleValue(raw);
    if (typeof parsed !== "boolean") {
      throw new Error("auditLog must be true or false");
    }
    config.auditLog = parsed;
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "reportOutput") {
    config.reportOutput = raw.trim() || undefined;
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "sarifOutput") {
    config.sarifOutput = raw.trim() || undefined;
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "maxTriageRetries") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0) {
      throw new Error("maxTriageRetries must be a non-negative number");
    }
    config.maxTriageRetries = Math.floor(n);
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "maxVerifyRetries") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0) {
      throw new Error("maxVerifyRetries must be a non-negative number");
    }
    config.maxVerifyRetries = Math.floor(n);
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "maxPocHarnessRetries") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0) {
      throw new Error("maxPocHarnessRetries must be a non-negative number");
    }
    config.maxPocHarnessRetries = Math.floor(n);
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "retryBackoffMs") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0) {
      throw new Error("retryBackoffMs must be a non-negative number");
    }
    config.retryBackoffMs = Math.floor(n);
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "retryBackoffMultiplier") {
    const n = Number(raw);
    if (!Number.isFinite(n) || n <= 0) {
      throw new Error("retryBackoffMultiplier must be a positive number");
    }
    config.retryBackoffMultiplier = n;
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "scanMode") {
    const mode = raw.trim();
    if (mode !== "sequential" && mode !== "concurrent") {
      throw new Error("scanMode must be one of: sequential, concurrent");
    }
    config.scanMode = mode;
    saveConfig(normalizeConfig(config), repoRoot);
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
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "busBackend") {
    const backend = raw.trim();
    if (!BUS_BACKENDS.has(backend)) {
      throw new Error(`busBackend must be one of: ${[...BUS_BACKENDS].join(", ")}`);
    }
    config.busBackend = backend as KuzushiConfig["busBackend"];
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "severity") {
    config.severity = coerceStringArray(raw);
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "excludePatterns") {
    config.excludePatterns = coerceStringArray(raw);
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "model") {
    config.model = raw;
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "triageModel") {
    config.triageModel = raw.trim() || undefined;
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "verifyModel") {
    config.verifyModel = raw.trim() || undefined;
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (key === "pocHarnessModel") {
    config.pocHarnessModel = raw.trim() || undefined;
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  throw new Error(`Unknown config key: ${key}`);
}

/** Unset a config key (supports dotted paths). */
export function unsetConfigValue(key: string, repoRoot?: string): void {
  const config = loadConfig(repoRoot);

  if (key.includes(".")) {
    unsetByPath(config, key.split("."));
    saveConfig(normalizeConfig(config), repoRoot);
    return;
  }

  if (!VALID_TOP_LEVEL_KEYS.has(key)) {
    throw new Error(`Unknown config key: ${key}. Valid keys: ${[...VALID_TOP_LEVEL_KEYS].join(", ")}`);
  }

  if (key in DEFAULTS) {
    if (key === "model") config.model = DEFAULTS.model;
    else if (key === "triageMaxTurns") config.triageMaxTurns = DEFAULTS.triageMaxTurns;
    else if (key === "verify") config.verify = DEFAULTS.verify;
    else if (key === "verifyMaxTurns") config.verifyMaxTurns = DEFAULTS.verifyMaxTurns;
    else if (key === "verifyConcurrency") config.verifyConcurrency = DEFAULTS.verifyConcurrency;
    else if (key === "verifyVerdicts") config.verifyVerdicts = [...(DEFAULTS.verifyVerdicts ?? ["tp"])];
    else if (key === "verifyMinConfidence") config.verifyMinConfidence = DEFAULTS.verifyMinConfidence;
    else if (key === "pocHarness") config.pocHarness = DEFAULTS.pocHarness;
    else if (key === "pocHarnessMaxTurns") config.pocHarnessMaxTurns = DEFAULTS.pocHarnessMaxTurns;
    else if (key === "pocHarnessConcurrency") {
      config.pocHarnessConcurrency = DEFAULTS.pocHarnessConcurrency;
    }
    else if (key === "enableContextGathering") {
      config.enableContextGathering = DEFAULTS.enableContextGathering;
    } else if (key === "auditLog") config.auditLog = DEFAULTS.auditLog;
    else if (key === "reportOutput") config.reportOutput = DEFAULTS.reportOutput;
    else if (key === "sarifOutput") config.sarifOutput = DEFAULTS.sarifOutput;
    else if (key === "maxTriageRetries") config.maxTriageRetries = DEFAULTS.maxTriageRetries;
    else if (key === "maxVerifyRetries") config.maxVerifyRetries = DEFAULTS.maxVerifyRetries;
    else if (key === "maxPocHarnessRetries") {
      config.maxPocHarnessRetries = DEFAULTS.maxPocHarnessRetries;
    }
    else if (key === "retryBackoffMs") config.retryBackoffMs = DEFAULTS.retryBackoffMs;
    else if (key === "retryBackoffMultiplier") {
      config.retryBackoffMultiplier = DEFAULTS.retryBackoffMultiplier;
    }
    else if (key === "busBackend") config.busBackend = DEFAULTS.busBackend;
    else if (key === "triageConcurrency") config.triageConcurrency = DEFAULTS.triageConcurrency;
    else if (key === "scanMode") config.scanMode = DEFAULTS.scanMode;
    else if (key === "agentRuntimeBackend") config.agentRuntimeBackend = DEFAULTS.agentRuntimeBackend;
    else if (key === "enabledTasks") config.enabledTasks = [...(DEFAULTS.enabledTasks ?? [])];
    else if (key === "scanners") config.scanners = [...DEFAULTS.scanners];
    else if (key === "severity") config.severity = [...DEFAULTS.severity];
    else if (key === "excludePatterns") config.excludePatterns = [...DEFAULTS.excludePatterns];
    else if (key === "scannerConfig") config.scannerConfig = cloneScannerConfig(DEFAULTS.scannerConfig);
  } else if (key === "triageModel") {
    config.triageModel = undefined;
  } else if (key === "verifyModel") {
    config.verifyModel = undefined;
  } else if (key === "pocHarnessModel") {
    config.pocHarnessModel = undefined;
  }

  saveConfig(normalizeConfig(config), repoRoot);
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
  const triageConcurrency = normalizePositiveInt(config.triageConcurrency, DEFAULTS.triageConcurrency);
  const triageMaxTurns = normalizePositiveInt(config.triageMaxTurns, DEFAULTS.triageMaxTurns);
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
    triageConcurrency,
    triageMaxTurns,
    scanMode,
    agentRuntimeBackend,
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
    scannerConfig: { ...DEFAULTS.scannerConfig },
  };

  for (const layer of layers) {
    if (!isRecord(layer)) continue;

    if (typeof layer["model"] === "string") {
      merged.model = layer["model"];
    }

    if (typeof layer["triageModel"] === "string") {
      merged.triageModel = layer["triageModel"];
    }

    if (typeof layer["triageMaxTurns"] === "number" && Number.isFinite(layer["triageMaxTurns"])) {
      merged.triageMaxTurns = layer["triageMaxTurns"];
    }

    if (typeof layer["verify"] === "boolean") {
      merged.verify = layer["verify"];
    }

    if (typeof layer["verifyModel"] === "string") {
      merged.verifyModel = layer["verifyModel"];
    }

    if (typeof layer["verifyMaxTurns"] === "number" && Number.isFinite(layer["verifyMaxTurns"])) {
      merged.verifyMaxTurns = layer["verifyMaxTurns"];
    }

    if (typeof layer["verifyConcurrency"] === "number" && Number.isFinite(layer["verifyConcurrency"])) {
      merged.verifyConcurrency = layer["verifyConcurrency"];
    }

    if (Array.isArray(layer["verifyVerdicts"])) {
      const verdicts = normalizeVerdictArray(layer["verifyVerdicts"]);
      if (verdicts.length > 0) {
        merged.verifyVerdicts = verdicts;
      }
    }

    if (
      typeof layer["verifyMinConfidence"] === "number"
      && Number.isFinite(layer["verifyMinConfidence"])
    ) {
      merged.verifyMinConfidence = layer["verifyMinConfidence"];
    }

    if (typeof layer["pocHarness"] === "boolean") {
      merged.pocHarness = layer["pocHarness"];
    }

    if (typeof layer["pocHarnessModel"] === "string") {
      merged.pocHarnessModel = layer["pocHarnessModel"];
    }

    if (
      typeof layer["pocHarnessMaxTurns"] === "number"
      && Number.isFinite(layer["pocHarnessMaxTurns"])
    ) {
      merged.pocHarnessMaxTurns = layer["pocHarnessMaxTurns"];
    }

    if (
      typeof layer["pocHarnessConcurrency"] === "number"
      && Number.isFinite(layer["pocHarnessConcurrency"])
    ) {
      merged.pocHarnessConcurrency = layer["pocHarnessConcurrency"];
    }

    if (typeof layer["enableContextGathering"] === "boolean") {
      merged.enableContextGathering = layer["enableContextGathering"];
    }

    if (typeof layer["auditLog"] === "boolean") {
      merged.auditLog = layer["auditLog"];
    }

    if (typeof layer["reportOutput"] === "string") {
      merged.reportOutput = layer["reportOutput"];
    }

    if (typeof layer["sarifOutput"] === "string") {
      merged.sarifOutput = layer["sarifOutput"];
    }

    if (
      typeof layer["maxTriageRetries"] === "number"
      && Number.isFinite(layer["maxTriageRetries"])
    ) {
      merged.maxTriageRetries = layer["maxTriageRetries"];
    }

    if (
      typeof layer["maxVerifyRetries"] === "number"
      && Number.isFinite(layer["maxVerifyRetries"])
    ) {
      merged.maxVerifyRetries = layer["maxVerifyRetries"];
    }

    if (
      typeof layer["maxPocHarnessRetries"] === "number"
      && Number.isFinite(layer["maxPocHarnessRetries"])
    ) {
      merged.maxPocHarnessRetries = layer["maxPocHarnessRetries"];
    }

    if (
      typeof layer["retryBackoffMs"] === "number"
      && Number.isFinite(layer["retryBackoffMs"])
    ) {
      merged.retryBackoffMs = layer["retryBackoffMs"];
    }

    if (
      typeof layer["retryBackoffMultiplier"] === "number"
      && Number.isFinite(layer["retryBackoffMultiplier"])
    ) {
      merged.retryBackoffMultiplier = layer["retryBackoffMultiplier"];
    }

    if (typeof layer["busBackend"] === "string") {
      merged.busBackend = layer["busBackend"] as KuzushiConfig["busBackend"];
    }

    if (typeof layer["triageConcurrency"] === "number" && Number.isFinite(layer["triageConcurrency"])) {
      merged.triageConcurrency = layer["triageConcurrency"];
    }

    if (typeof layer["scanMode"] === "string") {
      merged.scanMode = layer["scanMode"] as KuzushiConfig["scanMode"];
    }

    if (typeof layer["agentRuntimeBackend"] === "string") {
      merged.agentRuntimeBackend = layer["agentRuntimeBackend"] as KuzushiConfig["agentRuntimeBackend"];
    }

    if (Array.isArray(layer["enabledTasks"])) {
      merged.enabledTasks = layer["enabledTasks"].map(String);
    }

    if (Array.isArray(layer["scanners"])) {
      merged.scanners = layer["scanners"].map(String);
    }

    if (Array.isArray(layer["severity"])) {
      merged.severity = layer["severity"].map(String);
    }

    if (Array.isArray(layer["excludePatterns"])) {
      merged.excludePatterns = layer["excludePatterns"].map(String);
    }

    if (isRecord(layer["scannerConfig"])) {
      merged.scannerConfig = {
        ...merged.scannerConfig,
        ...coerceScannerConfigMap(layer["scannerConfig"]),
      };
    }
  }

  return merged;
}

function readConfigFile(configFilePath: string): Record<string, unknown> {
  if (!existsSync(configFilePath)) return {};

  try {
    const parsed = JSON.parse(readFileSync(configFilePath, "utf-8"));
    return isRecord(parsed) ? parsed : {};
  } catch {
    return {};
  }
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

function parseFlexibleValue(raw: string): unknown {
  const trimmed = raw.trim();

  if (!trimmed) return "";
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    return JSON.parse(trimmed);
  }

  if (trimmed === "true") return true;
  if (trimmed === "false") return false;

  const num = Number(trimmed);
  if (!Number.isNaN(num) && trimmed !== "") return num;

  return raw;
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

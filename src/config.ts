import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import type { KuzushiConfig } from "./types.js";
import type { ScannerConfig } from "./scanners/types.js";

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
  "acp",
]);

/** Hard defaults — the bottom of the precedence stack. */
export const DEFAULTS: KuzushiConfig = {
  model: "claude-sonnet-4-20250514",
  triageMaxTurns: 10,
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
    "claude-adk": { model: "claude-sonnet-4-20250514", maxFindings: 20 },
  },
};

const VALID_TOP_LEVEL_KEYS = new Set<string>([
  ...Object.keys(DEFAULTS),
  "triageModel",
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
  const scanMode = normalizeScanMode(config.scanMode);
  const agentRuntimeBackend = normalizeAgentRuntimeBackend(config.agentRuntimeBackend);
  const triageModel = normalizeOptionalString(config.triageModel);
  const enabledTasks = normalizeStringArray(config.enabledTasks);

  return {
    ...config,
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

function normalizeStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((v) => String(v).trim()).filter(Boolean);
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object";
}

function cloneScannerConfig(value: Record<string, ScannerConfig>): Record<string, ScannerConfig> {
  const result: Record<string, ScannerConfig> = {};
  for (const [k, v] of Object.entries(value)) {
    result[k] = { ...v };
  }
  return result;
}

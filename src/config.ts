import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import type { KuzushiConfig } from "./types.js";

const CONFIG_DIR = path.join(os.homedir(), ".kuzushi");
const CONFIG_PATH = path.join(CONFIG_DIR, "config.json");

/** Hard defaults — the bottom of the precedence stack. */
export const DEFAULTS: KuzushiConfig = {
  model: "claude-sonnet-4-20250514",
  maxTokens: 1024,
  severity: ["ERROR", "WARNING"],
  excludePatterns: [
    "test", "tests", "spec", "vendor",
    "node_modules", "__tests__", "*.min.js", "*.min.css",
  ],
};

/** Valid top-level config keys. */
const VALID_KEYS = new Set<string>(Object.keys(DEFAULTS));

/** Load config from ~/.kuzushi/config.json, merged over defaults. */
export function loadConfig(): KuzushiConfig {
  if (!existsSync(CONFIG_PATH)) return { ...DEFAULTS };

  try {
    const raw = JSON.parse(readFileSync(CONFIG_PATH, "utf-8"));
    return {
      ...DEFAULTS,
      ...pick(raw, VALID_KEYS),
    };
  } catch {
    return { ...DEFAULTS };
  }
}

/** Save the full config to ~/.kuzushi/config.json. */
export function saveConfig(config: KuzushiConfig): void {
  if (!existsSync(CONFIG_DIR)) mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2) + "\n");
}

/** Get a single config value by key. */
export function getConfigValue(key: string): unknown {
  if (!VALID_KEYS.has(key)) return undefined;
  const config = loadConfig();
  return config[key as keyof KuzushiConfig];
}

/** Set a single config value by key. Parses JSON for arrays/numbers. */
export function setConfigValue(key: string, raw: string): void {
  if (!VALID_KEYS.has(key)) {
    throw new Error(`Unknown config key: ${key}. Valid keys: ${[...VALID_KEYS].join(", ")}`);
  }

  const config = loadConfig();
  const defaultVal = DEFAULTS[key as keyof KuzushiConfig];

  // Coerce the raw string to the right type based on the default value's type
  let coerced: string | number | string[];
  if (typeof defaultVal === "number") {
    const n = Number(raw);
    if (Number.isNaN(n)) throw new Error(`${key} must be a number`);
    coerced = n;
  } else if (Array.isArray(defaultVal)) {
    // Accept comma-separated or JSON array
    coerced = raw.startsWith("[") ? JSON.parse(raw) : raw.split(",").map((s) => s.trim());
  } else {
    coerced = raw;
  }

  assignConfigKey(config, key as keyof KuzushiConfig, coerced);
  saveConfig(config);
}

/** Unset a config key (revert to default). */
export function unsetConfigValue(key: string): void {
  if (!VALID_KEYS.has(key)) {
    throw new Error(`Unknown config key: ${key}. Valid keys: ${[...VALID_KEYS].join(", ")}`);
  }

  const config = loadConfig();
  assignConfigKey(config, key as keyof KuzushiConfig, DEFAULTS[key as keyof KuzushiConfig]);
  saveConfig(config);
}

/** Type-safe assignment to a config key. */
function assignConfigKey<K extends keyof KuzushiConfig>(
  config: KuzushiConfig,
  key: K,
  value: KuzushiConfig[K],
): void {
  config[key] = value;
}

/** Return the config file path. */
export function configPath(): string {
  return CONFIG_PATH;
}

function pick(obj: Record<string, unknown>, keys: Set<string>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const k of keys) {
    if (k in obj) result[k] = obj[k];
  }
  return result;
}

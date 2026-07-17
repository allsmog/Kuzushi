import type { BenchmarkScanConfig } from "./types.js";

const CONFIG_ARG_FLAGS = [
  ["mode", "--mode"],
  ["tasks", "--tasks"],
  ["failOn", "--fail-on"],
  ["budget", "--budget"],
] as const;
const CONFIG_KEYS: ReadonlySet<string> = new Set(CONFIG_ARG_FLAGS.map(([key]) => key));
const MODES = new Set(["standard", "whitebox-static"]);
const FAIL_LEVELS = new Set(["low", "medium", "high", "critical"]);
const MAX_CONFIG_VALUE_BYTES = 4_096;

export function parseScanConfig(value: unknown, source: string): BenchmarkScanConfig {
  if (!isRecord(value)) throw new Error(`${source} must be a JSON object`);
  rejectUnknownKeys(value, source);
  const fields = CONFIG_ARG_FLAGS.flatMap(([key]) => {
    const raw = value[key];
    return raw === undefined ? [] : [[key, configValue(key, raw, source)]];
  });
  return Object.fromEntries(fields) as BenchmarkScanConfig;
}

export function parseScanConfigArgument(raw: string | undefined): BenchmarkScanConfig {
  if (raw === undefined) throw new Error("--run requires an explicit --config JSON object");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Invalid --config JSON: ${errorMessage(error)}`);
  }
  return parseScanConfig(parsed, "--config");
}

export function scanConfigArgs(config: BenchmarkScanConfig): string[] {
  return CONFIG_ARG_FLAGS.flatMap(([key, flag]) => {
    const value = config[key];
    return value === undefined ? [] : [flag, value];
  });
}

export function canonicalScanConfig(config: BenchmarkScanConfig): string {
  const ordered = Object.fromEntries(
    CONFIG_ARG_FLAGS.flatMap(([key]) => (config[key] === undefined ? [] : [[key, config[key]]])),
  );
  return JSON.stringify(ordered);
}

function rejectUnknownKeys(value: Record<string, unknown>, source: string): void {
  const unknown = Object.keys(value).filter((key) => !CONFIG_KEYS.has(key));
  if (unknown.length > 0) {
    throw new Error(
      `${source} contains unsupported scan config keys: ${unknown.sort().join(", ")}`,
    );
  }
}

function configValue(key: keyof BenchmarkScanConfig, value: unknown, source: string): string {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    throw new Error(`${source}.${key} must be a nonempty, unpadded string`);
  }
  if (Buffer.byteLength(value) > MAX_CONFIG_VALUE_BYTES || /[\0\r\n]/u.test(value)) {
    throw new Error(`${source}.${key} is too large or contains a forbidden control character`);
  }
  assertEnumeratedValue(key, value, source);
  return value;
}

function assertEnumeratedValue(
  key: keyof BenchmarkScanConfig,
  value: string,
  source: string,
): void {
  if (key === "mode" && !MODES.has(value)) throw new Error(`${source}.mode is unsupported`);
  if (key === "failOn" && !FAIL_LEVELS.has(value)) {
    throw new Error(`${source}.failOn is unsupported`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

import path from "node:path";
import type { KuzushiConfig } from "../types.js";
import { CliUsageError } from "./errors.js";
import { parseCommaSeparatedList } from "./shared.js";

export interface ScanCommandOptions {
  scanners?: string;
  severity?: string;
  max?: number;
  model?: string;
  ensembleModels?: string;
  triageModel?: string;
  triageMaxTurns?: number;
  enableClassifier: boolean;
  classifierModel?: string;
  classifierThreshold?: number;
  verify: boolean;
  verifyModel?: string;
  verifyMaxTurns?: number;
  verifyConcurrency?: number;
  verifyRefinementMaxIterations?: number;
  verifyReflectionInterval?: number;
  verifyMinConfidence?: number;
  cryptoBehavioralTest: boolean;
  pocHarness: boolean;
  pocHarnessModel?: string;
  pocHarnessMaxTurns?: number;
  pocHarnessConcurrency?: number;
  pocRefinementMaxIterations?: number;
  pocReflectionInterval?: number;
  maxPocHarnessRetries?: number;
  maxTriageRetries?: number;
  maxVerifyRetries?: number;
  retryBackoffMs?: number;
  context: boolean;
  auditLog: boolean;
  output?: string;
  sarif?: string;
  json?: string;
  csv?: string;
  jsonl?: string;
  html?: string;
  agentRuntime?: string;
  apiKey?: string;
  baseUrl?: string;
  enableExternalTasks: boolean;
  enabledTasks?: string;
  qualityGate: boolean;
  failOnTp: boolean;
  fresh: boolean;
  dryRun: boolean;
  cache: boolean;
  resume?: string | boolean;
  db?: string;
  interactive: boolean;
}

export function applyScanCommandConfigOverrides(
  config: KuzushiConfig,
  opts: ScanCommandOptions,
): KuzushiConfig {
  if (opts.model) config.model = opts.model;
  if (opts.ensembleModels) config.ensembleModels = parseCommaSeparatedList(opts.ensembleModels);
  if (opts.triageModel) config.triageModel = opts.triageModel;
  if (opts.enableClassifier) config.enableClassifier = true;
  if (opts.classifierModel) config.classifierModel = opts.classifierModel;
  if (opts.verify) config.verify = true;
  if (opts.verifyModel) config.verifyModel = opts.verifyModel;
  if (opts.cryptoBehavioralTest) {
    config.cryptoBehavioralTestEnabled = true;
    config.enabledTasks = dedupeStrings([
      ...(config.enabledTasks ?? []),
      "crypto-behavioral-test",
    ]);
  }
  if (opts.pocHarness) config.pocHarness = true;
  if (opts.pocHarnessModel) config.pocHarnessModel = opts.pocHarnessModel;
  if (opts.context === false) config.enableContextGathering = false;
  if (opts.auditLog) config.auditLog = true;
  if (opts.output) config.reportOutput = path.resolve(opts.output);
  if (opts.sarif) config.sarifOutput = path.resolve(opts.sarif);
  if (opts.json) config.jsonOutput = path.resolve(opts.json);
  if (opts.csv) config.csvOutput = path.resolve(opts.csv);
  if (opts.jsonl) config.jsonlOutput = path.resolve(opts.jsonl);
  if (opts.html) config.htmlOutput = path.resolve(opts.html);
  if (opts.agentRuntime) {
    config.agentRuntimeBackend = opts.agentRuntime as typeof config.agentRuntimeBackend;
  }
  if (opts.enableExternalTasks) config.enableExternalTasks = true;

  if (opts.apiKey || opts.baseUrl) {
    const runtimeConfig = {
      ...(config.agentRuntimeConfig ?? {}),
    };

    if (opts.apiKey) {
      const apiKey = opts.apiKey.trim();
      runtimeConfig.apiKey = apiKey || undefined;
    }

    if (opts.baseUrl) {
      const baseUrl = opts.baseUrl.trim();
      runtimeConfig.baseUrl = baseUrl || undefined;
    }

    config.agentRuntimeConfig = runtimeConfig;
  }

  if (opts.enabledTasks) {
    config.enabledTasks = dedupeStrings([
      ...(config.enabledTasks ?? []),
      ...parseCommaSeparatedList(opts.enabledTasks),
    ]);
  }

  if (opts.qualityGate) {
    config.qualityGates = {
      failOnHighSeverityTP: true,
      failOnExploitable: true,
      ...(config.qualityGates ?? {}),
    };
  }

  if (opts.failOnTp) {
    config.qualityGates = {
      ...(config.qualityGates ?? {}),
      failOnHighSeverityTP: true,
    };
  }

  applyOptionalUnitInterval(config, "classifierThreshold", opts.classifierThreshold, "--classifier-threshold");
  applyOptionalUnitInterval(config, "verifyMinConfidence", opts.verifyMinConfidence, "--verify-min-confidence");
  applyOptionalPositiveInteger(config, "triageMaxTurns", opts.triageMaxTurns, "--triage-max-turns");
  applyOptionalPositiveInteger(config, "verifyMaxTurns", opts.verifyMaxTurns, "--verify-max-turns");
  applyOptionalPositiveInteger(config, "verifyConcurrency", opts.verifyConcurrency, "--verify-concurrency");
  applyOptionalPositiveInteger(
    config,
    "verifyRefinementMaxIterations",
    opts.verifyRefinementMaxIterations,
    "--verify-refinement-max-iterations",
  );
  applyOptionalPositiveInteger(
    config,
    "verifyReflectionInterval",
    opts.verifyReflectionInterval,
    "--verify-reflection-interval",
  );
  applyOptionalPositiveInteger(config, "pocHarnessMaxTurns", opts.pocHarnessMaxTurns, "--poc-harness-max-turns");
  applyOptionalPositiveInteger(config, "pocHarnessConcurrency", opts.pocHarnessConcurrency, "--poc-harness-concurrency");
  applyOptionalPositiveInteger(
    config,
    "pocRefinementMaxIterations",
    opts.pocRefinementMaxIterations,
    "--poc-refinement-max-iterations",
  );
  applyOptionalPositiveInteger(
    config,
    "pocReflectionInterval",
    opts.pocReflectionInterval,
    "--poc-reflection-interval",
  );
  applyOptionalNonNegativeInteger(config, "maxTriageRetries", opts.maxTriageRetries, "--max-triage-retries");
  applyOptionalNonNegativeInteger(config, "maxVerifyRetries", opts.maxVerifyRetries, "--max-verify-retries");
  applyOptionalNonNegativeInteger(
    config,
    "maxPocHarnessRetries",
    opts.maxPocHarnessRetries,
    "--max-poc-harness-retries",
  );
  applyOptionalNonNegativeInteger(config, "retryBackoffMs", opts.retryBackoffMs, "--retry-backoff-ms");

  if (config.pocHarness && config.verify !== true) {
    throw new CliUsageError("--poc-harness requires --verify.");
  }

  return config;
}

export function resolveScanSeverity(
  config: KuzushiConfig,
  opts: Pick<ScanCommandOptions, "severity">,
): string[] {
  return opts.severity
    ? opts.severity.split(",").map((level) => level.trim().toUpperCase()).filter(Boolean)
    : config.severity;
}

export function resolveScannerOverride(
  opts: Pick<ScanCommandOptions, "scanners">,
): string[] | undefined {
  return opts.scanners ? parseCommaSeparatedList(opts.scanners) : undefined;
}

function applyOptionalPositiveInteger<T extends keyof KuzushiConfig>(
  config: KuzushiConfig,
  key: T,
  value: number | undefined,
  flagName: string,
): void {
  if (value === undefined) {
    return;
  }
  config[key] = coercePositiveInteger(value, flagName) as KuzushiConfig[T];
}

function applyOptionalNonNegativeInteger<T extends keyof KuzushiConfig>(
  config: KuzushiConfig,
  key: T,
  value: number | undefined,
  flagName: string,
): void {
  if (value === undefined) {
    return;
  }
  config[key] = coerceNonNegativeInteger(value, flagName) as KuzushiConfig[T];
}

function applyOptionalUnitInterval<T extends keyof KuzushiConfig>(
  config: KuzushiConfig,
  key: T,
  value: number | undefined,
  flagName: string,
): void {
  if (value === undefined) {
    return;
  }
  config[key] = coerceUnitInterval(value, flagName) as KuzushiConfig[T];
}

function coercePositiveInteger(value: number, flagName: string): number {
  if (!Number.isFinite(value) || value < 1) {
    throw new CliUsageError(`${flagName} must be a positive integer.`);
  }
  return Math.floor(value);
}

function coerceNonNegativeInteger(value: number, flagName: string): number {
  if (!Number.isFinite(value) || value < 0) {
    throw new CliUsageError(`${flagName} must be a non-negative integer.`);
  }
  return Math.floor(value);
}

function coerceUnitInterval(value: number, flagName: string): number {
  if (!Number.isFinite(value) || value < 0 || value > 1) {
    throw new CliUsageError(`${flagName} must be a number between 0 and 1.`);
  }
  return value;
}

function dedupeStrings(values: Iterable<string>): string[] {
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

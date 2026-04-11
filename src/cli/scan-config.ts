import path from "node:path";
import type { KuzushiConfig } from "../types.js";
import { isValidPreset, SCAN_PRESETS } from "../config/presets.js";
import { CliUsageError } from "./errors.js";
import { parseCommaSeparatedList } from "./shared.js";

export interface ScanCommandOptions {
  preset?: string;
  scanners?: string;
  severity?: string;
  max?: number;
  model?: string;
  ensembleModels?: string;
  triageModel?: string;

  verify: boolean;
  verifyModel?: string;
  verifyMaxTurns?: number;
  verifyConcurrency?: number;
  verifyRefinementMaxIterations?: number;
  verifyReflectionInterval?: number;
  verifyMinConfidence?: number;
  verifyGate?: boolean;
  verifyGateModel?: string;
  cryptoBehavioralTest: boolean;
  dynamicAnalysis?: boolean;
  dynamicMaxCandidates?: number;
  dynamicMinScore?: number;
  codeGraph: boolean;
  multiStrategy: boolean;
  multiStrategyFull: boolean;
  multiStrategyBudget?: number;
  multiStrategyAutoRules: boolean;
  autoRuleGen: boolean;
  taintDiffBase?: string;
  taintDiffMode?: string;
  stream: boolean;
  streamPort?: number;
  githubPr: boolean;
  githubComment: boolean;
  autoPatch: boolean;
  autoPatchAfter?: string;
  patchVerifyDepth?: string;
  patchConcurrency?: number;
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
  agentRuntime?: string;
  apiKey?: string;
  baseUrl?: string;
  enableExternalTasks: boolean;
  trustRepoConfig?: boolean;
  enabledTasks?: string;
  qualityGate: boolean;
  failOnTp: boolean;
  moduleDiscovery: boolean;
  fresh: boolean;
  cache: boolean;
  resume?: string | boolean;
  db?: string;
  listModules?: boolean;
  modules?: string;
  moduleFilter?: string;
  modulePriority?: string;
  maxModules?: number;
  dryRun?: boolean;
}

export function applyScanCommandConfigOverrides(
  config: KuzushiConfig,
  opts: ScanCommandOptions,
): KuzushiConfig {
  // Apply preset before any other overrides so CLI flags take precedence.
  if (opts.preset) {
    if (!isValidPreset(opts.preset)) {
      throw new CliUsageError(`Unknown preset "${opts.preset}". Valid presets: safe, fast, standard, deep, reference`);
    }
    const preset = SCAN_PRESETS[opts.preset];
    // Deep-merge scannerConfig so presets can override individual scanner
    // settings without wiping out defaults for other scanners.
    if (preset.scannerConfig) {
      for (const [key, val] of Object.entries(preset.scannerConfig)) {
        config.scannerConfig[key] = { ...config.scannerConfig[key], ...val };
      }
      const { scannerConfig: _, ...rest } = preset;
      Object.assign(config, rest);
    } else {
      Object.assign(config, preset);
    }
  }

  if (opts.model) config.model = opts.model;
  if (opts.ensembleModels) config.ensembleModels = parseCommaSeparatedList(opts.ensembleModels);
  if (opts.triageModel) config.triageModel = opts.triageModel;
  if (opts.verify) config.verify = true;
  if (opts.verifyModel) config.verifyModel = opts.verifyModel;
  if (opts.cryptoBehavioralTest) {
    config.cryptoBehavioralTestEnabled = true;
    config.enabledTasks = dedupeStrings([
      ...(config.enabledTasks ?? []),
      "crypto-behavioral-test",
    ]);
    promoteTaskModeForExplicitTasks(config);
  }
  if (opts.dynamicAnalysis) config.dynamicAnalysisEnabled = true;
  if (opts.taintDiffBase) config.taintDiffBase = opts.taintDiffBase.trim() || undefined;
  if (opts.taintDiffMode) {
    config.taintDiffMode = coerceStringEnum(
      opts.taintDiffMode,
      ["delta", "baseline"],
      "--taint-diff-mode",
    ) as typeof config.taintDiffMode;
  }
  if (opts.codeGraph) {
    config.codeGraphEnabled = true;
    config.enabledTasks = dedupeStrings([
      ...(config.enabledTasks ?? []),
      "code-graph-build",
      "code-graph-enrich",
    ]);
    promoteTaskModeForExplicitTasks(config);
  }
  if (opts.multiStrategy) config.multiStrategyMode = "adaptive";
  if (opts.multiStrategyFull) config.multiStrategyMode = "full";
  if (opts.multiStrategyBudget != null) config.multiStrategyBudgetUsd = opts.multiStrategyBudget;
  if (opts.multiStrategyAutoRules) config.multiStrategyAutoRuleGeneration = true;
  if (opts.autoRuleGen) config.autoRuleGeneration = true;
  if (opts.stream) config.streamingEnabled = true;
  if (opts.streamPort != null) config.streamingPort = opts.streamPort;
  if (opts.githubPr) ((config as unknown) as Record<string, unknown>)["githubPr"] = true;
  if (opts.githubComment) ((config as unknown) as Record<string, unknown>)["githubComment"] = true;
  if (opts.autoPatch) config.autoPatchEnabled = true;
  if (opts.autoPatchAfter) config.autoPatchAfter = opts.autoPatchAfter as typeof config.autoPatchAfter;
  if (opts.patchVerifyDepth) config.patchVerifyDepth = opts.patchVerifyDepth as typeof config.patchVerifyDepth;
  if (opts.patchConcurrency != null) config.patchConcurrency = opts.patchConcurrency;
  if (opts.pocHarness) config.pocHarness = true;
  if (opts.pocHarnessModel) config.pocHarnessModel = opts.pocHarnessModel;
  if (opts.context === false) config.enableContextGathering = false;
  if (opts.auditLog) config.auditLog = true;
  if (opts.output) config.reportOutput = path.resolve(opts.output);
  if (opts.sarif) config.sarifOutput = path.resolve(opts.sarif);
  if (opts.json) config.jsonOutput = path.resolve(opts.json);
  if (opts.csv) config.csvOutput = path.resolve(opts.csv);
  if (opts.jsonl) config.jsonlOutput = path.resolve(opts.jsonl);
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
    promoteTaskModeForExplicitTasks(config);
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

  applyOptionalUnitInterval(config, "verifyMinConfidence", opts.verifyMinConfidence, "--verify-min-confidence");

  if (opts.verifyGate === false) config.verifyGateEnabled = false;
  if (opts.verifyGateModel) config.verifyGateModel = opts.verifyGateModel;

  applyOptionalPositiveInteger(config, "verifyMaxTurns", opts.verifyMaxTurns, "--verify-max-turns");
  applyOptionalPositiveInteger(config, "verifyConcurrency", opts.verifyConcurrency, "--verify-concurrency");
  applyOptionalPositiveInteger(config, "dynamicMaxCandidates", opts.dynamicMaxCandidates, "--dynamic-max-candidates");
  applyOptionalPositiveInteger(config, "dynamicMinScore", opts.dynamicMinScore, "--dynamic-min-score");
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

function promoteTaskModeForExplicitTasks(config: KuzushiConfig): void {
  if (config.taskMode === "scanners-only") {
    config.taskMode = "explicit";
  }
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

function coerceStringEnum(
  value: string,
  allowed: string[],
  flagName: string,
): string {
  const normalized = value.trim().toLowerCase();
  if (!allowed.includes(normalized)) {
    throw new CliUsageError(`${flagName} must be one of: ${allowed.join(", ")}.`);
  }
  return normalized;
}

function coerceNonNegativeInteger(value: number, flagName: string): number {
  if (!Number.isFinite(value) || value < 0) {
    throw new CliUsageError(`${flagName} must be a non-negative integer.`);
  }
  return Math.floor(value);
}

function coerceUnitInterval(value: number, flagName: string): number {
  if (!Number.isFinite(value) || value < 0 || value > 100) {
    throw new CliUsageError(`${flagName} must be a number between 0 and 1 (or 0-100 as a percentage).`);
  }
  if (value > 1) {
    return value / 100;
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

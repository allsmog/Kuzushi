import path from "node:path";
import { isValidPreset, SCAN_PRESETS } from "../config/presets.js";
import type { KuzushiConfig } from "../types.js";
import { CliUsageError } from "./errors.js";
import { parseCommaSeparatedList } from "./shared.js";

export interface ScanCommandOptions {
  preset?: string;
  tasks?: string;
  severity?: string;
  max?: number;
  model?: string;
  ensembleModels?: string;
  taskModels?: string[];

  verify: boolean;
  verifyMaxTurns?: number;
  verifyConcurrency?: number;
  verifyRefinementMaxIterations?: number;
  verifyReflectionInterval?: number;
  verifyMinConfidence?: number;
  verifyGate?: boolean;
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
  /**
   * Explicit opt-in for running LLM-generated PoC harnesses (via
   * `--dynamic-analysis` / `pocExecute`). Required in non-TTY contexts.
   */
  yes?: boolean;
}

export function applyScanCommandConfigOverrides(
  config: KuzushiConfig,
  opts: ScanCommandOptions,
): KuzushiConfig {
  // Apply preset before any other overrides so CLI flags take precedence.
  if (opts.preset) {
    if (!isValidPreset(opts.preset)) {
      throw new CliUsageError(
        `Unknown preset "${opts.preset}". Valid presets: safe, fast, standard, deep, reference`,
      );
    }
    const preset = SCAN_PRESETS[opts.preset];
    // Deep-merge taskConfig so presets can override individual task
    // settings without wiping out defaults for other tasks.
    if (preset.taskConfig) {
      for (const [key, val] of Object.entries(preset.taskConfig)) {
        config.taskConfig[key] = { ...config.taskConfig[key], ...val };
      }
      const { taskConfig: _, ...rest } = preset;
      Object.assign(config, rest);
    } else {
      Object.assign(config, preset);
    }
  }

  if (opts.model) config.model = opts.model;
  if (opts.ensembleModels) config.ensembleModels = parseCommaSeparatedList(opts.ensembleModels);
  applyTaskModelOverrides(config, opts.taskModels);
  if (opts.verify) config.verify = true;
  if (opts.cryptoBehavioralTest) {
    config.cryptoBehavioralTestEnabled = true;
    config.tasks = dedupeStrings([...(config.tasks ?? []), "crypto-behavioral-test"]);
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
    config.tasks = dedupeStrings([
      ...(config.tasks ?? []),
      "code-graph-build",
      "code-graph-enrich",
    ]);
  }
  if (opts.multiStrategy) config.multiStrategyMode = "adaptive";
  if (opts.multiStrategyFull) config.multiStrategyMode = "full";
  if (opts.multiStrategyBudget != null) config.multiStrategyBudgetUsd = opts.multiStrategyBudget;
  if (opts.multiStrategyAutoRules) config.multiStrategyAutoRuleGeneration = true;
  if (opts.autoRuleGen) config.autoRuleGeneration = true;
  if (opts.stream) config.streamingEnabled = true;
  if (opts.streamPort != null) config.streamingPort = opts.streamPort;
  if (opts.githubPr) (config as unknown as Record<string, unknown>)["githubPr"] = true;
  if (opts.githubComment) (config as unknown as Record<string, unknown>)["githubComment"] = true;
  if (opts.autoPatch) config.autoPatchEnabled = true;
  if (opts.autoPatchAfter)
    config.autoPatchAfter = opts.autoPatchAfter as typeof config.autoPatchAfter;
  if (opts.patchVerifyDepth)
    config.patchVerifyDepth = opts.patchVerifyDepth as typeof config.patchVerifyDepth;
  if (opts.patchConcurrency != null) config.patchConcurrency = opts.patchConcurrency;
  if (opts.pocHarness) config.pocHarness = true;
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

  if (opts.tasks) {
    config.tasks = dedupeStrings([...(config.tasks ?? []), ...parseCommaSeparatedList(opts.tasks)]);
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

  applyOptionalUnitInterval(
    config,
    "verifyMinConfidence",
    opts.verifyMinConfidence,
    "--verify-min-confidence",
  );

  if (opts.verifyGate === false) config.verifyGateEnabled = false;

  applyOptionalPositiveInteger(config, "verifyMaxTurns", opts.verifyMaxTurns, "--verify-max-turns");
  applyOptionalPositiveInteger(
    config,
    "verifyConcurrency",
    opts.verifyConcurrency,
    "--verify-concurrency",
  );
  applyOptionalPositiveInteger(
    config,
    "dynamicMaxCandidates",
    opts.dynamicMaxCandidates,
    "--dynamic-max-candidates",
  );
  applyOptionalPositiveInteger(
    config,
    "dynamicMinScore",
    opts.dynamicMinScore,
    "--dynamic-min-score",
  );
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
  applyOptionalPositiveInteger(
    config,
    "pocHarnessMaxTurns",
    opts.pocHarnessMaxTurns,
    "--poc-harness-max-turns",
  );
  applyOptionalPositiveInteger(
    config,
    "pocHarnessConcurrency",
    opts.pocHarnessConcurrency,
    "--poc-harness-concurrency",
  );
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
  applyOptionalNonNegativeInteger(
    config,
    "maxTriageRetries",
    opts.maxTriageRetries,
    "--max-triage-retries",
  );
  applyOptionalNonNegativeInteger(
    config,
    "maxVerifyRetries",
    opts.maxVerifyRetries,
    "--max-verify-retries",
  );
  applyOptionalNonNegativeInteger(
    config,
    "maxPocHarnessRetries",
    opts.maxPocHarnessRetries,
    "--max-poc-harness-retries",
  );
  applyOptionalNonNegativeInteger(
    config,
    "retryBackoffMs",
    opts.retryBackoffMs,
    "--retry-backoff-ms",
  );

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
    ? opts.severity
        .split(",")
        .map((level) => level.trim().toUpperCase())
        .filter(Boolean)
    : config.severity;
}

export function resolveScannerOverride(
  opts: Pick<ScanCommandOptions, "tasks">,
): string[] | undefined {
  return opts.tasks != null ? parseCommaSeparatedList(opts.tasks) : undefined;
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

function coerceStringEnum(value: string, allowed: string[], flagName: string): string {
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
    throw new CliUsageError(
      `${flagName} must be a number between 0 and 1 (or 0-100 as a percentage).`,
    );
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

function applyTaskModelOverrides(
  config: KuzushiConfig,
  rawAssignments: string[] | undefined,
): void {
  if (!rawAssignments || rawAssignments.length === 0) {
    return;
  }

  for (const assignment of rawAssignments.flatMap((value) => parseCommaSeparatedList(value))) {
    const equalsIndex = assignment.indexOf("=");
    if (equalsIndex <= 0 || equalsIndex === assignment.length - 1) {
      throw new CliUsageError(
        `--task-model must be in the form <taskId=model>; received "${assignment}".`,
      );
    }

    const taskId = assignment.slice(0, equalsIndex).trim();
    const model = assignment.slice(equalsIndex + 1).trim();
    if (!taskId || !model) {
      throw new CliUsageError(
        `--task-model must be in the form <taskId=model>; received "${assignment}".`,
      );
    }

    config.taskConfig[taskId] = {
      ...(config.taskConfig[taskId] ?? {}),
      model,
    };
  }
}

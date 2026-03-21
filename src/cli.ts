#!/usr/bin/env node

import { Command } from "commander";
import { mkdirSync, existsSync } from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { cleanup as cleanupHttpAgents } from "./http-agent.js";
import { registerShutdownHook, initiateShutdown } from "./lifecycle.js";
import { loadConfig, getConfigValue, setConfigValue, unsetConfigValue, configPath } from "./config.js";
import {
  createRun,
  defaultDbPath,
  getLatestResumableRun,
  getRun,
  initDb,
} from "./store.js";
import { createDefaultRegistry } from "./scanners/index.js";
import { createDefaultTaskRegistry } from "./agents/index.js";
import { configureAgentRuntime } from "./agent-runtime/index.js";
import { configureRateLimitRegistry } from "./scheduler/index.js";
import { parsePiAiModelSpec } from "./agent-runtime/model-spec.js";
import {
  createBus,
  registerAllWorkers,
  createEvent,
  generateRunId,
  type PipelineCompleteEvent,
  type PipelineErrorEvent,
} from "./bus/index.js";
import type { KuzushiConfig, ScanOpts } from "./types.js";
import { printQualityGateResult } from "./report.js";
import { inflightCache } from "./cache.js";
import {
  expandScannerSelections,
  resolveScannerConfig,
  TAINT_ANALYSIS_TASK_IDS,
  TAINT_ANALYSIS_CROSS_SERVICE_TASK_IDS,
} from "./capabilities.js";

const DEFAULT_AGENTIC_MODEL = "anthropic:claude-sonnet-4-6";

function resolveRepo(repoPath: string): { root: string; name: string } {
  const absPath = path.resolve(repoPath);
  try {
    const root = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd: absPath,
      encoding: "utf-8",
    }).trim();
    return { root, name: path.basename(root) };
  } catch {
    return { root: absPath, name: path.basename(absPath) };
  }
}

function parseScannersArg(raw: string): string[] {
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function maybeWarnPlaintextApiKeyStorage(key: string, value: string): void {
  let storesApiKey = key === "agentRuntimeConfig.apiKey";

  if (!storesApiKey && key === "agentRuntimeConfig") {
    try {
      const parsed = JSON.parse(value);
      storesApiKey = typeof parsed?.["apiKey"] === "string" && parsed["apiKey"].trim().length > 0;
    } catch {
      storesApiKey = false;
    }
  }

  if (!storesApiKey) {
    return;
  }

  console.warn(
    `Warning: ${key} stores API credentials in plaintext at ${configPath()}. `
    + "Prefer --api-key for one-off scans or ANTHROPIC_API_KEY from your shell/secret manager.",
  );
}

function maybeWarnPiAiApiKeyForModel(
  model: string | undefined,
  options: { anthropicApiKey?: string } = {},
): void {
  if (!model) {
    return;
  }

  let provider: string;
  try {
    provider = parsePiAiModelSpec(model).provider;
  } catch {
    return;
  }

  const envVars = requiredEnvVarsForProvider(provider);
  if (envVars.length === 0) {
    return;
  }

  const hasAny = envVars.some((name) => Boolean(process.env[name]))
    || (provider === "anthropic" && Boolean(options.anthropicApiKey));
  if (hasAny) {
    return;
  }

  console.warn(
    `Warning: model "${model}" uses provider "${provider}", `
    + `but none of [${envVars.join(", ")}] are set.`,
  );
}

function warnPiAiBackendApiKeys(
  models: string[],
  options: { anthropicApiKey?: string } = {},
): void {
  for (const model of models) {
    maybeWarnPiAiApiKeyForModel(model, options);
  }
}

function requiredEnvVarsForProvider(provider: string): string[] {
  if (provider === "anthropic") {
    return ["ANTHROPIC_API_KEY", "ANTHROPIC_OAUTH_TOKEN"];
  }

  if (provider === "openai") {
    return ["OPENAI_API_KEY"];
  }

  if (provider === "google") {
    return ["GEMINI_API_KEY", "GOOGLE_API_KEY"];
  }

  return [];
}

function resolveActivePiAiModels(
  config: KuzushiConfig,
  selectedScanners: string[],
  enabledTaskIds: string[],
): string[] {
  const models = new Set<string>();
  const scannerSet = new Set(selectedScanners);
  const enabledTaskSet = new Set(enabledTaskIds);

  const triageModel = config.triageModel ?? config.model;
  models.add(triageModel);

  if (config.verify === true) {
    models.add(config.verifyModel ?? triageModel);
  }

  if (config.pocHarness === true) {
    models.add(
      config.pocHarnessModel
      ?? config.verifyModel
      ?? triageModel,
    );
  }

  if (config.enableClassifier === true) {
    models.add(
      config.classifierModel
      ?? config.triageBatchModel
      ?? config.contextEnrichmentModel
      ?? config.model,
    );
  }

  for (const model of config.ensembleModels ?? []) {
    const trimmed = model.trim();
    if (trimmed) {
      models.add(trimmed);
    }
  }

  if (scannerSet.has("agentic")) {
    const model = asModel(resolveScannerConfig(config, "agentic")["model"]) ?? DEFAULT_AGENTIC_MODEL;
    models.add(model);
  }

  const usesTaintAnalysis = TAINT_ANALYSIS_TASK_IDS.some((id) => enabledTaskSet.has(id));
  const usesCrossService = TAINT_ANALYSIS_CROSS_SERVICE_TASK_IDS.some((id) => enabledTaskSet.has(id));
  if (usesTaintAnalysis || usesCrossService) {
    const taCfg = config.scannerConfig["taint-analysis"];
    const labelingModel = asModel(taCfg?.["labelingModel"]) ?? config.model;
    const extractionModel = asModel(taCfg?.["extractionModel"]) ?? labelingModel;
    models.add(labelingModel);
    models.add(extractionModel);

    if (usesCrossService) {
      const boundaryModel = asModel(taCfg?.["crossServiceBoundaryModel"]) ?? labelingModel;
      const stitchModel = asModel(taCfg?.["crossServiceStitchModel"]) ?? labelingModel;
      models.add(boundaryModel);
      models.add(stitchModel);
    }
  }

  // Merged agentic detection tasks + race-condition
  for (const taskId of ["secrets-crypto-detect", "code-config-detect", "race-condition-detect"]) {
    if (enabledTaskSet.has(taskId)) {
      const model = asModel(resolveScannerConfig(config, taskId)["model"]) ?? config.model;
      models.add(model);
    }
  }

  // Invariant analysis tasks
  if (enabledTaskSet.has("invariant-extract") || enabledTaskSet.has("invariant-check")) {
      const iaCfg = resolveScannerConfig(config, "invariant-analysis");
      models.add(asModel(iaCfg?.["extractionModel"]) ?? config.model);
      models.add(asModel(iaCfg?.["checkModel"]) ?? config.model);
    }

  // Threat modeling tasks
  if (enabledTaskSet.has("threat-model-stride") || enabledTaskSet.has("threat-model-pasta")) {
      const tmCfg = resolveScannerConfig(config, "threat-model");
      models.add(asModel(tmCfg?.["strideModel"]) ?? config.model);
      models.add(asModel(tmCfg?.["pastaModel"]) ?? config.model);
    }

  return [...models];
}

function validatePiAiProviderCredentials(
  models: string[],
  options: { anthropicApiKey?: string } = {},
): Array<{ provider: string; envVars: string[]; models: string[] }> {
  const missingByProvider = new Map<string, { envVars: string[]; models: Set<string> }>();

  for (const model of models) {
    let provider: string;
    try {
      provider = parsePiAiModelSpec(model).provider;
    } catch {
      continue;
    }

    const envVars = requiredEnvVarsForProvider(provider);
    if (envVars.length === 0) {
      continue;
    }

    const hasAny = envVars.some((name) => Boolean(process.env[name]))
      || (provider === "anthropic" && Boolean(options.anthropicApiKey));
    if (hasAny) {
      continue;
    }

    const entry = missingByProvider.get(provider) ?? { envVars, models: new Set<string>() };
    entry.models.add(model);
    missingByProvider.set(provider, entry);
  }

  return [...missingByProvider.entries()].map(([provider, entry]) => ({
    provider,
    envVars: entry.envVars,
    models: [...entry.models],
  }));
}

function asModel(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed || undefined;
}

const program = new Command();

program
  .name("kuzushi")
  .description("Kuzushi — Agentic SAST orchestration")
  .version("0.1.0");

// ── scan (default command) ────────────────────────────────────────────────

program
  .command("scan", { isDefault: true })
  .description("Scan a repository with configured scanners and triage findings with an agent")
  .argument("<repo>", "Path to the repository to scan")
  .option("--scanners <names>", "Scanners to run (comma-separated scanner ids)")
  .option("--severity <levels>", "Severity filter (comma-separated)")
  .option("--max <n>", "Max findings to triage", parseInt)
  .option("--model <model>", "Model to use for scanners")
  .option("--ensemble-models <models>", "Run eligible agentic detection tasks across multiple models (comma-separated)")
  .option("--triage-model <model>", "Override model used by triage agent")
  .option("--triage-max-turns <n>", "Override triage agent max turn budget", parseInt)
  .option("--enable-classifier", "Enable the cheap pre-triage classifier funnel", false)
  .option("--classifier-model <model>", "Override model used by the pre-triage classifier")
  .option("--classifier-threshold <n>", "Minimum classifier confidence required to keep a finding", parseFloat)
  .option("--verify", "Enable post-triage exploitability verification", false)
  .option("--verify-model <model>", "Override model used by verification agent")
  .option("--verify-max-turns <n>", "Override verification agent max turn budget", parseInt)
  .option("--verify-concurrency <n>", "Override verification concurrency", parseInt)
  .option("--verify-refinement-max-iterations <n>", "Maximum verification refinement attempts", parseInt)
  .option("--verify-reflection-interval <n>", "Inject verification reflection every N failed attempts", parseInt)
  .option("--verify-min-confidence <n>", "Minimum triage confidence required for verification", parseFloat)
  .option("--poc-harness", "Enable post-verification PoC harness generation", false)
  .option("--poc-harness-model <model>", "Override model used by PoC harness generator")
  .option("--poc-harness-max-turns <n>", "Override PoC harness agent max turn budget", parseInt)
  .option("--poc-harness-concurrency <n>", "Override PoC harness generation concurrency", parseInt)
  .option("--poc-refinement-max-iterations <n>", "Maximum PoC refinement attempts when execution feedback is enabled", parseInt)
  .option("--poc-reflection-interval <n>", "Inject PoC reflection every N failed attempts", parseInt)
  .option("--max-poc-harness-retries <n>", "Retries for PoC harness generation failures", parseInt)
  .option("--max-triage-retries <n>", "Retries for triage agent failures", parseInt)
  .option("--max-verify-retries <n>", "Retries for verification agent failures", parseInt)
  .option("--retry-backoff-ms <n>", "Initial retry backoff in milliseconds", parseInt)
  .option("--no-context", "Disable pre-scan repository context gathering")
  .option("--audit-log", "Persist per-run audit logs to .kuzushi/runs/<runId>/", false)
  .option("--output <path>", "Write markdown report to this path")
  .option("--sarif <path>", "Write SARIF v2.1.0 report to this path")
  .option("--json <path>", "Write JSON report to this path")
  .option("--csv <path>", "Write CSV report to this path")
  .option("--jsonl <path>", "Write JSONL report to this path")
  .option("--agent-runtime <backend>", "Agent runtime backend (pi-ai|acp)")
  .option("--api-key <key>", "Override ANTHROPIC_API_KEY for this run")
  .option("--base-url <url>", "Override ANTHROPIC_BASE_URL for this run")
  .option("--enabled-tasks <ids>", "Additional AgentTask IDs to enable (comma-separated)")
  .option("--enable-external-tasks", "Enable loading of external tasks from config", false)
  .option("--quality-gate", "Enable quality gates (fail CI on threshold violations)", false)
  .option("--fail-on-tp", "Shorthand: fail if any high/critical severity true positive is found", false)
  .option("--fresh", "Clear prior results before scanning", false)
  .option("--no-cache", "Disable inflight request deduplication and LLM result caching")
  .option("--resume [runId]", "Resume a previous run (optionally by run id)")
  .option("--db <path>", "SQLite database path (default: <repo>/.kuzushi/findings.sqlite3)")
  .action(async (repoPath: string, opts: {
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
    enabledTasks?: string;
    qualityGate: boolean;
    failOnTp: boolean;
    fresh: boolean;
    cache: boolean;
    resume?: string | boolean;
    db?: string;
  }) => {
    const scanPath = path.resolve(repoPath);
    const { root: repoRoot, name: repoName } = resolveRepo(repoPath);

    // Load config with optional project-level overlay, then apply CLI overrides.
    const config = loadConfig(repoRoot);
    if (opts.model) config.model = opts.model;
    if (opts.ensembleModels) config.ensembleModels = parseScannersArg(opts.ensembleModels);
    if (opts.triageModel) config.triageModel = opts.triageModel;
    if (opts.enableClassifier) config.enableClassifier = true;
    if (opts.classifierModel) config.classifierModel = opts.classifierModel;
    if (opts.verify) config.verify = true;
    if (opts.verifyModel) config.verifyModel = opts.verifyModel;
    if (opts.pocHarness) config.pocHarness = true;
    if (opts.pocHarnessModel) config.pocHarnessModel = opts.pocHarnessModel;
    if (opts.classifierThreshold !== undefined) {
      if (!Number.isFinite(opts.classifierThreshold) || opts.classifierThreshold < 0 || opts.classifierThreshold > 1) {
        console.error("Error: --classifier-threshold must be a number between 0 and 1.");
        process.exit(1);
      }
      config.classifierThreshold = opts.classifierThreshold;
    }
    if (opts.verifyMinConfidence !== undefined) {
      if (!Number.isFinite(opts.verifyMinConfidence) || opts.verifyMinConfidence < 0 || opts.verifyMinConfidence > 1) {
        console.error("Error: --verify-min-confidence must be a number between 0 and 1.");
        process.exit(1);
      }
      config.verifyMinConfidence = opts.verifyMinConfidence;
    }
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
    if (opts.enableExternalTasks) config.enableExternalTasks = true;
    if (opts.enabledTasks) {
      config.enabledTasks = [
        ...(config.enabledTasks ?? []),
        ...parseScannersArg(opts.enabledTasks),
      ];
    }

    // Quality gate CLI overrides
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
    if (opts.triageMaxTurns !== undefined) {
      if (!Number.isFinite(opts.triageMaxTurns) || opts.triageMaxTurns < 1) {
        console.error("Error: --triage-max-turns must be a positive integer.");
        process.exit(1);
      }
      config.triageMaxTurns = Math.floor(opts.triageMaxTurns);
    }

    if (opts.verifyMaxTurns !== undefined) {
      if (!Number.isFinite(opts.verifyMaxTurns) || opts.verifyMaxTurns < 1) {
        console.error("Error: --verify-max-turns must be a positive integer.");
        process.exit(1);
      }
      config.verifyMaxTurns = Math.floor(opts.verifyMaxTurns);
    }

    if (opts.verifyConcurrency !== undefined) {
      if (!Number.isFinite(opts.verifyConcurrency) || opts.verifyConcurrency < 1) {
        console.error("Error: --verify-concurrency must be a positive integer.");
        process.exit(1);
      }
      config.verifyConcurrency = Math.floor(opts.verifyConcurrency);
    }

    if (opts.verifyRefinementMaxIterations !== undefined) {
      if (!Number.isFinite(opts.verifyRefinementMaxIterations) || opts.verifyRefinementMaxIterations < 1) {
        console.error("Error: --verify-refinement-max-iterations must be a positive integer.");
        process.exit(1);
      }
      config.verifyRefinementMaxIterations = Math.floor(opts.verifyRefinementMaxIterations);
    }

    if (opts.verifyReflectionInterval !== undefined) {
      if (!Number.isFinite(opts.verifyReflectionInterval) || opts.verifyReflectionInterval < 1) {
        console.error("Error: --verify-reflection-interval must be a positive integer.");
        process.exit(1);
      }
      config.verifyReflectionInterval = Math.floor(opts.verifyReflectionInterval);
    }

    if (opts.pocHarnessMaxTurns !== undefined) {
      if (!Number.isFinite(opts.pocHarnessMaxTurns) || opts.pocHarnessMaxTurns < 1) {
        console.error("Error: --poc-harness-max-turns must be a positive integer.");
        process.exit(1);
      }
      config.pocHarnessMaxTurns = Math.floor(opts.pocHarnessMaxTurns);
    }

    if (opts.pocHarnessConcurrency !== undefined) {
      if (!Number.isFinite(opts.pocHarnessConcurrency) || opts.pocHarnessConcurrency < 1) {
        console.error("Error: --poc-harness-concurrency must be a positive integer.");
        process.exit(1);
      }
      config.pocHarnessConcurrency = Math.floor(opts.pocHarnessConcurrency);
    }

    if (opts.pocRefinementMaxIterations !== undefined) {
      if (!Number.isFinite(opts.pocRefinementMaxIterations) || opts.pocRefinementMaxIterations < 1) {
        console.error("Error: --poc-refinement-max-iterations must be a positive integer.");
        process.exit(1);
      }
      config.pocRefinementMaxIterations = Math.floor(opts.pocRefinementMaxIterations);
    }

    if (opts.pocReflectionInterval !== undefined) {
      if (!Number.isFinite(opts.pocReflectionInterval) || opts.pocReflectionInterval < 1) {
        console.error("Error: --poc-reflection-interval must be a positive integer.");
        process.exit(1);
      }
      config.pocReflectionInterval = Math.floor(opts.pocReflectionInterval);
    }

    if (config.pocHarness && config.verify !== true) {
      console.error("Error: --poc-harness requires --verify.");
      process.exit(1);
    }

    if (opts.maxTriageRetries !== undefined) {
      if (!Number.isFinite(opts.maxTriageRetries) || opts.maxTriageRetries < 0) {
        console.error("Error: --max-triage-retries must be a non-negative integer.");
        process.exit(1);
      }
      config.maxTriageRetries = Math.floor(opts.maxTriageRetries);
    }

    if (opts.maxVerifyRetries !== undefined) {
      if (!Number.isFinite(opts.maxVerifyRetries) || opts.maxVerifyRetries < 0) {
        console.error("Error: --max-verify-retries must be a non-negative integer.");
        process.exit(1);
      }
      config.maxVerifyRetries = Math.floor(opts.maxVerifyRetries);
    }

    if (opts.maxPocHarnessRetries !== undefined) {
      if (!Number.isFinite(opts.maxPocHarnessRetries) || opts.maxPocHarnessRetries < 0) {
        console.error("Error: --max-poc-harness-retries must be a non-negative integer.");
        process.exit(1);
      }
      config.maxPocHarnessRetries = Math.floor(opts.maxPocHarnessRetries);
    }

    if (opts.retryBackoffMs !== undefined) {
      if (!Number.isFinite(opts.retryBackoffMs) || opts.retryBackoffMs < 0) {
        console.error("Error: --retry-backoff-ms must be a non-negative integer.");
        process.exit(1);
      }
      config.retryBackoffMs = Math.floor(opts.retryBackoffMs);
    }

    const severity = opts.severity
      ? opts.severity.split(",").map((s) => s.trim().toUpperCase())
      : config.severity;

    let scannersOverride = opts.scanners
      ? parseScannersArg(opts.scanners)
      : undefined;

    // Auto-expand scanner aliases that map to AgentTask DAGs.
    // This must run on the effective scanner list whether from CLI or config file.
    const effectiveScanners = scannersOverride ?? [...config.scanners];
    const { pluginScanners, enabledTasks: aliasExpandedTasks } = expandScannerSelections(effectiveScanners, config);
    if (aliasExpandedTasks.length > 0) {
      config.enabledTasks = [...(config.enabledTasks ?? []), ...aliasExpandedTasks];
    }
    if (scannersOverride) {
      scannersOverride = pluginScanners;
    } else {
      config.scanners = pluginScanners;
    }

    const scanOpts: ScanOpts = {
      severity,
      maxFindings: opts.max,
      excludePatterns: config.excludePatterns,
      scanners: scannersOverride,
      fresh: opts.fresh,
    };

    const registry = createDefaultRegistry();
    try {
      scanOpts.scanners = registry.resolveEnabled(scanOpts, config);
    } catch (err) {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    }

    const runtimeBackend = config.agentRuntimeBackend ?? "pi-ai";
    if (runtimeBackend === "pi-ai") {
      const activeModels = resolveActivePiAiModels(
        config,
        scanOpts.scanners ?? [],
        config.enabledTasks ?? [],
      );

      const missingCredentials = validatePiAiProviderCredentials(
        activeModels,
        {
          anthropicApiKey: config.agentRuntimeConfig?.apiKey,
        },
      );

      if (missingCredentials.length > 0) {
        console.error("Error: missing API credentials for selected model provider(s):");
        for (const entry of missingCredentials) {
          console.error(
            `  - ${entry.provider}: set one of [${entry.envVars.join(", ")}] `
            + `(used by: ${entry.models.join(", ")})`,
          );
        }
        if (missingCredentials.some((entry) => entry.provider === "anthropic")) {
          console.error(
            "Tip: for Anthropic models, you can also set agentRuntimeConfig.apiKey "
            + "or pass --api-key for this run.",
          );
        }
        process.exit(1);
      }

      warnPiAiBackendApiKeys(activeModels, {
        anthropicApiKey: config.agentRuntimeConfig?.apiKey,
      });
    }

    try {
      configureAgentRuntime(config);
    } catch (err) {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    }

    // Configure rate limit registry with triage concurrency as the initial seed.
    configureRateLimitRegistry(config.triageConcurrency);

    // Disable LLM result cache when --fresh or --no-cache is passed.
    if (opts.fresh || opts.cache === false) {
      inflightCache.enabled = false;
      inflightCache.invalidate();
    }

    // Set up DB.
    const dbPath = opts.db ?? defaultDbPath(repoRoot);
    const dbDir = path.dirname(dbPath);
    if (!existsSync(dbDir)) mkdirSync(dbDir, { recursive: true });

    const repoId = path.resolve(repoRoot);

    const db = initDb(dbPath);
    let bus: ReturnType<typeof createBus> | undefined;
    try {
      bus = createBus(config);
      const taskRegistry = await createDefaultTaskRegistry(registry, config, repoRoot);
      await registerAllWorkers(bus, { registry, taskRegistry, db, config });
    } catch (err) {
      db.close();
      console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    }

    // Register shutdown hooks for bus draining and DB close.
    registerShutdownHook("bus-drain", async () => {
      if (bus) {
        try { await bus.close(); } catch { /* best-effort */ }
      }
    }, 1);
    registerShutdownHook("db-close", async () => {
      try { db.close(); } catch { /* best-effort */ }
    }, 2);

    let resumeRunId: string | undefined;
    if (opts.resume !== undefined) {
      if (opts.resume === true) {
        const latest = getLatestResumableRun(db, repoId) ?? getLatestResumableRun(db, repoName);
        if (!latest) {
          console.error(`Error: no resumable runs found for repo "${repoId}".`);
          process.exit(1);
        }
        resumeRunId = latest.runId;
      } else if (typeof opts.resume === "string" && opts.resume.trim().length > 0) {
        resumeRunId = opts.resume.trim();
      }

      if (!resumeRunId) {
        console.error("Error: --resume received an invalid run id.");
        process.exit(1);
      }

      const run = getRun(db, resumeRunId);
      if (!run) {
        console.error(`Error: run "${resumeRunId}" was not found.`);
        process.exit(1);
      }

      if (run.repo !== repoId && run.repo !== repoName) {
        console.error(
          `Error: run "${resumeRunId}" belongs to repo "${run.repo}", not "${repoId}".`,
        );
        process.exit(1);
      }

      if (run.status === "complete") {
        console.error(`Error: run "${resumeRunId}" is already complete and cannot be resumed.`);
        process.exit(1);
      }
    }

    const runId = resumeRunId ?? generateRunId();
    if (!resumeRunId) {
      createRun(db, runId, repoId, config, scanOpts);
    }

    const context = {
      runId,
      repoRoot,
      scanPath,
      repoName,
      dbPath,
    };

    const pipelineComplete = bus!
      .waitFor<PipelineCompleteEvent>(
        "pipeline:complete",
        (event) => event.meta.runId === runId,
      )
      .then((event) => ({ kind: "complete" as const, event }));

    const pipelineError = bus!
      .waitFor<PipelineErrorEvent>(
        "pipeline:error",
        (event) => event.meta.runId === runId && event.payload.fatal,
      )
      .then((event) => ({ kind: "error" as const, event }));

    try {
      await bus!.publish(
        createEvent("pipeline:start", runId, {
          context,
          config,
          scanOpts,
          resumeRunId,
        }),
      );

      const outcome = await Promise.race([pipelineComplete, pipelineError]);
      if (outcome.kind === "error") {
        const { error: errMsg, errorCategory } = outcome.event.payload;
        console.error(`Error: ${errMsg}`);
        if (errorCategory === "auth") {
          console.error("Hint: Check your API key or credentials.");
        } else if (errorCategory === "rate_limit") {
          console.error("Hint: Reduce concurrency or wait before retrying.");
        } else if (errorCategory === "budget") {
          console.error("Hint: Increase your cost budget or use a cheaper model.");
        }
        process.exitCode = 1;
      } else if (outcome.kind === "complete") {
        const { stats } = outcome.event.payload;
        if (stats.qualityGateResult) {
          printQualityGateResult(stats.qualityGateResult);
        }
        if (stats.deadLetterCount && stats.deadLetterCount > 0) {
          console.error(
            `\n${stats.deadLetterCount} finding(s) failed all triage retries. Run \`kuzushi explain <fingerprint>\` for details.`,
          );
        }
      }
    } finally {
      try {
        await bus!.close();
      } finally {
        db.close();
      }
    }
  });

// ── compare-runs ──────────────────────────────────────────────────────────

function fmt(n: number | undefined): string {
  return n != null ? (n * 100).toFixed(1) + "%" : "n/a";
}

function delta(a: number | undefined, b: number | undefined): string {
  if (a == null || b == null) return "n/a";
  const d = (b - a) * 100;
  return (d >= 0 ? "+" : "") + d.toFixed(1) + "pp";
}

program
  .command("compare-runs <id1> <id2>")
  .description("Compare metrics and assertions between two pipeline runs")
  .option("-r, --repo <path>", "Repository path", ".")
  .action(async (id1: string, id2: string, options: { repo: string }) => {
    const { root } = resolveRepo(options.repo);
    const dbPath = defaultDbPath(root);
    const db = initDb(dbPath);
    try {
      const run1 = getRun(db, id1);
      const run2 = getRun(db, id2);
      if (!run1 || !run2) {
        console.error(`Run not found: ${!run1 ? id1 : id2}`);
        process.exit(1);
      }
      // Parse metrics
      const metrics1 = run1.metricsJson ? JSON.parse(run1.metricsJson) : null;
      const metrics2 = run2.metricsJson ? JSON.parse(run2.metricsJson) : null;

      // Print comparison
      console.log("Pipeline Run Comparison");
      console.log("=".repeat(60));
      console.log(`Run 1: ${id1} (${run1.status})`);
      console.log(`Run 2: ${id2} (${run2.status})`);
      console.log(`Prompt hash: ${run1.promptHash ?? "n/a"} vs ${run2.promptHash ?? "n/a"}`);
      if (run1.promptHash && run2.promptHash && run1.promptHash !== run2.promptHash) {
        console.log("  Warning: Prompt templates changed between runs");
      }
      console.log("");

      if (metrics1 && metrics2) {
        console.log("Metrics Comparison:");
        console.log(`  TP Rate: ${fmt(metrics1.tpRate)} -> ${fmt(metrics2.tpRate)} (${delta(metrics1.tpRate, metrics2.tpRate)})`);
        console.log(`  FP Rate: ${fmt(metrics1.fpRate)} -> ${fmt(metrics2.fpRate)} (${delta(metrics1.fpRate, metrics2.fpRate)})`);
        console.log(`  Avg Confidence: ${fmt(metrics1.averageConfidence)} -> ${fmt(metrics2.averageConfidence)} (${delta(metrics1.averageConfidence, metrics2.averageConfidence)})`);
        console.log(`  Total Cost: $${metrics1.costBreakdown?.total?.toFixed(4) ?? "?"} -> $${metrics2.costBreakdown?.total?.toFixed(4) ?? "?"}`);
      }

      // Compare assertions
      const assertions1 = run1.assertionsJson ? JSON.parse(run1.assertionsJson) : null;
      const assertions2 = run2.assertionsJson ? JSON.parse(run2.assertionsJson) : null;
      if (assertions1 || assertions2) {
        console.log("\nAssertion Comparison:");
        if (assertions1?.totalAssertions != null && assertions2?.totalAssertions != null) {
          console.log(`  Pass rate: ${assertions1.passedAssertions}/${assertions1.totalAssertions} -> ${assertions2.passedAssertions}/${assertions2.totalAssertions}`);
          console.log(`  Avg quality: ${fmt(assertions1.averageQualityScore)} -> ${fmt(assertions2.averageQualityScore)}`);
        } else {
          console.log(`  Run 1: ${assertions1 ? JSON.stringify(assertions1) : "n/a"}`);
          console.log(`  Run 2: ${assertions2 ? JSON.stringify(assertions2) : "n/a"}`);
        }
      }

      // Flag regressions
      if (metrics1 && metrics2) {
        const regressions: string[] = [];
        if (metrics2.tpRate < metrics1.tpRate * 0.9) regressions.push("TP rate dropped >10%");
        if (metrics2.fpRate > metrics1.fpRate * 1.1) regressions.push("FP rate increased >10%");
        if (metrics2.averageConfidence < metrics1.averageConfidence * 0.9) regressions.push("Average confidence dropped >10%");
        if (regressions.length > 0) {
          console.log("\nREGRESSIONS DETECTED:");
          for (const r of regressions) console.log(`  - ${r}`);
        } else {
          console.log("\nNo regressions detected");
        }
      }
    } finally {
      db.close();
    }
  });

// ── config get/set/unset ──────────────────────────────────────────────────

const configCmd = program
  .command("config")
  .description("Manage Kuzushi configuration");

configCmd
  .command("get")
  .description("Get a config value")
  .argument("[key]", "Config key (omit to show all)")
  .action((key?: string) => {
    if (!key) {
      const config = loadConfig();
      console.log(JSON.stringify(config, null, 2));
      return;
    }
    const value = getConfigValue(key);
    if (value === undefined) {
      console.error(`Unknown config key: ${key}`);
      process.exit(1);
    }
    console.log(typeof value === "string" ? value : JSON.stringify(value));
  });

configCmd
  .command("set")
  .description("Set a config value")
  .argument("<key>", "Config key")
  .argument("<value>", "Value to set")
  .action((key: string, value: string) => {
    try {
      setConfigValue(key, value);
      console.log(`${key} = ${JSON.stringify(getConfigValue(key))}`);
      maybeWarnPlaintextApiKeyStorage(key, value);
    } catch (err) {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  });

configCmd
  .command("unset")
  .description("Reset a config key to its default")
  .argument("<key>", "Config key")
  .action((key: string) => {
    try {
      unsetConfigValue(key);
      console.log(`${key} reset to default: ${JSON.stringify(getConfigValue(key))}`);
    } catch (err) {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  });

configCmd
  .command("path")
  .description("Print config file path")
  .action(() => {
    console.log(configPath());
  });

// ── task list/info/validate ────────────────────────────────────────────────

const taskCmd = program
  .command("task")
  .description("Manage and inspect pipeline tasks");

taskCmd
  .command("list")
  .description("List all registered tasks with their metadata")
  .option("-r, --repo <path>", "Repository path", ".")
  .option("--filter <outputKind>", "Filter by output kind (findings|threat-model|verdict|report|custom)")
  .action(async (opts: { repo: string; filter?: string }) => {
    const { root } = resolveRepo(opts.repo);
    const config = loadConfig(root);
    const registry = createDefaultRegistry();
    const taskRegistry = await createDefaultTaskRegistry(registry, config, root);

    let tasks = taskRegistry.list();
    if (opts.filter) {
      tasks = tasks.filter((t) => t.outputKind === opts.filter);
    }

    if (tasks.length === 0) {
      console.log("No tasks registered.");
      return;
    }

    // Show DAG stages
    const allIds = tasks.map((t) => t.id);
    let stages: string[][] = [];
    try {
      stages = taskRegistry.resolveOrder(allIds);
    } catch {
      // DAG resolution may fail if not all deps are in the list
    }

    console.log(`Registered tasks: ${tasks.length}\n`);

    for (const task of tasks) {
      const deps = task.dependsOn.length > 0 ? task.dependsOn.join(", ") : "none";
      const version = task.manifest?.version ?? "-";
      console.log(`  ${task.id}`);
      console.log(`    Name:       ${task.displayName}`);
      console.log(`    Output:     ${task.outputKind}`);
      console.log(`    Depends on: ${deps}`);
      console.log(`    Version:    ${version}`);
      console.log();
    }

    if (stages.length > 0) {
      console.log("DAG execution stages:");
      for (let i = 0; i < stages.length; i++) {
        console.log(`  Stage ${i}: ${stages[i].join(", ")}`);
      }
    }
  });

taskCmd
  .command("info")
  .description("Show detailed information about a task")
  .argument("<id>", "Task ID")
  .option("-r, --repo <path>", "Repository path", ".")
  .action(async (id: string, opts: { repo: string }) => {
    const { root } = resolveRepo(opts.repo);
    const config = loadConfig(root);
    const registry = createDefaultRegistry();
    const taskRegistry = await createDefaultTaskRegistry(registry, config, root);

    if (!taskRegistry.has(id)) {
      console.error(`Task "${id}" not found.`);
      process.exit(1);
    }

    const task = taskRegistry.get(id);
    const manifest = taskRegistry.getManifest(id);

    console.log(`Task: ${task.id}`);
    console.log(`  Display Name: ${task.displayName}`);
    console.log(`  Output Kind:  ${task.outputKind}`);
    console.log(`  Depends On:   ${task.dependsOn.length > 0 ? task.dependsOn.join(", ") : "none"}`);
    console.log(`  Has Condition: ${task.condition ? "yes" : "no"}`);
    console.log(`  Prompt Mode:  ${task.promptMode ?? "full"}`);

    if (manifest) {
      console.log(`\n  Manifest:`);
      console.log(`    Version:     ${manifest.version}`);
      console.log(`    Description: ${manifest.description}`);
      if (manifest.author) console.log(`    Author:      ${manifest.author}`);
      if (manifest.license) console.log(`    License:     ${manifest.license}`);
      if (manifest.requires) {
        if (manifest.requires.env?.length) {
          console.log(`    Requires env: ${manifest.requires.env.join(", ")}`);
        }
        if (manifest.requires.bins?.length) {
          console.log(`    Requires bins: ${manifest.requires.bins.join(", ")}`);
        }
        if (manifest.requires.nodeVersion) {
          console.log(`    Node version: ${manifest.requires.nodeVersion}`);
        }
      }
      if (manifest.config) {
        console.log(`    Config schema:`);
        for (const [key, entry] of Object.entries(manifest.config)) {
          const defaultVal = entry.default !== undefined ? ` (default: ${JSON.stringify(entry.default)})` : "";
          console.log(`      ${key}: ${entry.type}${defaultVal} — ${entry.description}`);
        }
      }
    }
  });

taskCmd
  .command("validate")
  .description("Validate an external task file and its manifest")
  .argument("<path>", "Path to task file")
  .action(async (filePath: string) => {
    const { parseTaskSpecifier, loadExternalTask } = await import("./agents/task-loader.js");
    const { loadManifestForTaskFile, checkRequirements } = await import("./agents/task-manifest.js");

    const absPath = path.resolve(filePath);

    // Validate manifest if present
    const manifestResult = loadManifestForTaskFile(absPath);
    if (manifestResult) {
      if (!manifestResult.valid) {
        console.error("Manifest validation failed:");
        for (const err of manifestResult.errors ?? []) {
          console.error(`  - ${err}`);
        }
        process.exit(1);
      }
      console.log(`Manifest: valid (${manifestResult.manifest!.id} v${manifestResult.manifest!.version})`);

      // Check requirements
      const reqCheck = checkRequirements(manifestResult.manifest!);
      if (!reqCheck.satisfied) {
        console.warn("Requirements not fully satisfied:");
        if (reqCheck.missing.env.length > 0) {
          console.warn(`  Missing env: ${reqCheck.missing.env.join(", ")}`);
        }
        if (reqCheck.missing.bins.length > 0) {
          console.warn(`  Missing bins: ${reqCheck.missing.bins.join(", ")}`);
        }
        if (reqCheck.missing.nodeVersion) {
          console.warn(`  Node version: ${reqCheck.missing.nodeVersion}`);
        }
      } else {
        console.log("Requirements: all satisfied");
      }
    } else {
      console.log("Manifest: not found (optional)");
    }

    // Validate the task module loads correctly
    try {
      const specifier = `file://${absPath}`;
      const spec = parseTaskSpecifier(specifier);
      await loadExternalTask(spec, path.dirname(absPath));
      console.log("Task module: valid");
    } catch (err) {
      console.error(`Task module validation failed: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    }
  });

// ── list-tasks (shorthand) ────────────────────────────────────────────────

program
  .command("list-tasks")
  .description("List all registered tasks (shorthand for 'task list')")
  .option("-r, --repo <path>", "Repository path", ".")
  .option("--filter <outputKind>", "Filter by output kind")
  .action(async (opts: { repo: string; filter?: string }) => {
    // Delegate to the task list command
    await taskCmd.commands.find((c) => c.name() === "list")!.parseAsync(
      ["list", ...(opts.filter ? ["--filter", opts.filter] : []), "-r", opts.repo],
      { from: "user" },
    );
  });

// Graceful shutdown via lifecycle coordinator.
// Hooks are registered with priority: bus drain (1), DB close (2), HTTP cleanup (3).
registerShutdownHook("http-cleanup", async () => {
  await Promise.resolve(cleanupHttpAgents());
}, 10);

process.on("SIGINT", () => void initiateShutdown(130));
process.on("SIGTERM", () => void initiateShutdown(143));
process.on("exit", cleanupHttpAgents);

program.parse();

#!/usr/bin/env node

import { Command } from "commander";
import { mkdirSync, existsSync } from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { cleanup as cleanupHttpAgents } from "./http-agent.js";
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

  // Agentic analysis tasks: crypto-misuse, auth-access, race-condition
  for (const taskId of ["crypto-misuse-detect", "auth-access-detect", "race-condition-detect"]) {
    if (enabledTaskSet.has(taskId)) {
      const cfgKey = taskId.replace("-detect", "");
      const model = asModel(resolveScannerConfig(config, cfgKey)["model"]) ?? config.model;
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
  .option("--triage-model <model>", "Override model used by triage agent")
  .option("--triage-max-turns <n>", "Override triage agent max turn budget", parseInt)
  .option("--verify", "Enable post-triage exploitability verification", false)
  .option("--verify-model <model>", "Override model used by verification agent")
  .option("--verify-max-turns <n>", "Override verification agent max turn budget", parseInt)
  .option("--verify-concurrency <n>", "Override verification concurrency", parseInt)
  .option("--verify-min-confidence <n>", "Minimum triage confidence required for verification", parseFloat)
  .option("--poc-harness", "Enable post-verification PoC harness generation", false)
  .option("--poc-harness-model <model>", "Override model used by PoC harness generator")
  .option("--poc-harness-max-turns <n>", "Override PoC harness agent max turn budget", parseInt)
  .option("--poc-harness-concurrency <n>", "Override PoC harness generation concurrency", parseInt)
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
    triageModel?: string;
    triageMaxTurns?: number;
    verify: boolean;
    verifyModel?: string;
    verifyMaxTurns?: number;
    verifyConcurrency?: number;
    verifyMinConfidence?: number;
    pocHarness: boolean;
    pocHarnessModel?: string;
    pocHarnessMaxTurns?: number;
    pocHarnessConcurrency?: number;
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
    if (opts.triageModel) config.triageModel = opts.triageModel;
    if (opts.verify) config.verify = true;
    if (opts.verifyModel) config.verifyModel = opts.verifyModel;
    if (opts.pocHarness) config.pocHarness = true;
    if (opts.pocHarnessModel) config.pocHarnessModel = opts.pocHarnessModel;
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
        console.error(`Error: ${outcome.event.payload.error}`);
        process.exitCode = 1;
      } else if (outcome.kind === "complete") {
        const qgResult = outcome.event.payload.stats.qualityGateResult;
        if (qgResult) {
          printQualityGateResult(qgResult);
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

// Graceful shutdown: destroy cached HTTP agents and undici dispatcher.
async function shutdown(code = 0): Promise<void> {
  await Promise.resolve(cleanupHttpAgents());
  process.exit(code);
}
process.on("SIGINT", () => void shutdown(130));
process.on("SIGTERM", () => void shutdown(143));
process.on("exit", cleanupHttpAgents);

program.parse();

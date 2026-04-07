import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { createDefaultTaskRegistry } from "../../agents/index.js";
import { configureAgentRuntime } from "../../agent-runtime/index.js";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import {
  createBus,
  createEvent,
  generateRunId,
  registerAllWorkers,
  type PipelineCompleteEvent,
  type PipelineErrorEvent,
  type PipelineStats,
} from "../../bus/index.js";
import { inflightCache } from "../../cache.js";
import { expandScannerSelections } from "../../capabilities.js";
import { loadConfig } from "../../config.js";
import {
  formatConfigValidationIssue,
  hasConfigValidationErrors,
  validateKuzushiConfig,
} from "../../config/validation.js";
import { registerShutdownHook } from "../../lifecycle.js";
import { createDefaultRegistry } from "../../scanners/index.js";
import { configureRateLimitRegistry } from "../../scheduler/index.js";
import {
  createRun,
  defaultDbPath,
  deleteFindingsForRepo,
  getLatestResumableRun,
  getRun,
  initDb,
  markStaleRunsAborted,
} from "../../store.js";
import { looksLikeMonorepo } from "../../discovery/module-discovery.js";
import type { KuzushiConfig, ScanOpts } from "../../types.js";
import { printQualityGateResult } from "../../report.js";
import { CliCommandError, CliConfigError, CliUsageError } from "../errors.js";
import { warnPiAiBackendApiKeys, resolveActivePiAiModels, validatePiAiProviderCredentials } from "../pi-ai.js";
import {
  applyScanCommandConfigOverrides,
  resolveScanSeverity,
  resolveScannerOverride,
  type ScanCommandOptions,
} from "../scan-config.js";
import { isShutdownCapableRuntime, resolveRepo } from "../shared.js";

export interface PreparedScanExecution {
  config: KuzushiConfig;
  scanOpts: ScanOpts;
}

export interface PipelineParams {
  repoRoot: string;
  scanPath: string;
  repoName: string;
  config: KuzushiConfig;
  scanOpts: ScanOpts;
  opts: ScanCommandOptions;
  dbPath?: string;
  runRepoId?: string;
  reportMode?: "full" | "suppress";
  runtime?: AgentRuntime;
  manageCache?: boolean;
}

export interface PipelineResult {
  runId: string;
  status: "complete" | "error";
  stats?: PipelineStats;
}

export type MonorepoExecutionReason =
  | "manual-modules"
  | "list-modules"
  | "cli-opt-out"
  | "config-modules"
  | "config-monorepo"
  | "auto-detected"
  | "single-root";

export interface MonorepoExecutionDecision {
  useMonorepo: boolean;
  reason: MonorepoExecutionReason;
}

export async function runScanCommand(repoPath: string, opts: ScanCommandOptions): Promise<void> {
  const scanPath = path.resolve(repoPath);
  const { root: repoRoot, name: repoName } = resolveRepo(repoPath);
  const modeConfig = applyScanCommandConfigOverrides(
    loadConfig(repoRoot, { trustProjectConfig: opts.trustRepoConfig === true }),
    opts,
  );
  const monorepoDecision = await resolveMonorepoExecution({
    repoRoot,
    scanPath,
    config: modeConfig,
    opts,
  });

  if (monorepoDecision.useMonorepo) {
    const { runMonorepoScan } = await import("./monorepo-scan.js");
    await runMonorepoScan(repoPath, opts);
    return;
  }

  if (opts.moduleFilter) {
    throw new CliUsageError("--module-filter can only be used when module discovery or manual modules are active.");
  }

  const { config, scanOpts } = prepareScanExecution(repoRoot, opts);

  await runPipeline({
    repoRoot,
    scanPath,
    repoName,
    config,
    scanOpts,
    opts,
  });
}

export async function resolveMonorepoExecution(params: {
  repoRoot: string;
  scanPath: string;
  config: KuzushiConfig;
  opts: Pick<ScanCommandOptions, "listModules" | "moduleDiscovery" | "modules">;
}): Promise<MonorepoExecutionDecision> {
  const { repoRoot, scanPath, config, opts } = params;

  if (opts.modules) {
    return { useMonorepo: true, reason: "manual-modules" };
  }

  if (opts.listModules) {
    return { useMonorepo: true, reason: "list-modules" };
  }

  if (opts.moduleDiscovery === false) {
    return { useMonorepo: false, reason: "cli-opt-out" };
  }

  const targetIsRepoRoot = path.resolve(scanPath) === path.resolve(repoRoot);
  if ((config.monorepo?.modules?.length ?? 0) > 0) {
    return {
      useMonorepo: targetIsRepoRoot,
      reason: targetIsRepoRoot ? "config-modules" : "single-root",
    };
  }

  if (config.monorepo?.mode === "off") {
    return { useMonorepo: false, reason: "single-root" };
  }

  if (!targetIsRepoRoot) {
    return { useMonorepo: false, reason: "single-root" };
  }

  if (config.monorepo) {
    return { useMonorepo: true, reason: "config-monorepo" };
  }

  return await looksLikeMonorepo(scanPath)
    ? { useMonorepo: true, reason: "auto-detected" }
    : { useMonorepo: false, reason: "single-root" };
}

export function prepareScanExecution(repoRoot: string, opts: ScanCommandOptions): PreparedScanExecution {
  const config = applyScanCommandConfigOverrides(
    loadConfig(repoRoot, { trustProjectConfig: opts.trustRepoConfig === true }),
    opts,
  );
  reportConfigValidationIssues(validateKuzushiConfig(config));

  const severity = resolveScanSeverity(config, opts);
  let scannersOverride = resolveScannerOverride(opts);

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
  } catch (error) {
    throw new CliUsageError(error instanceof Error ? error.message : String(error));
  }

  return { config, scanOpts };
}

export function createPipelineRuntime(config: KuzushiConfig, scanOpts: ScanOpts): AgentRuntime {
  const activeModels = resolveActivePiAiModels(
    config,
    scanOpts.scanners ?? [],
    config.enabledTasks ?? [],
  );

  const isClaudeRuntime = (config.agentRuntimeBackend ?? "claude") === "claude";
  if (!isClaudeRuntime) {
    const missingCredentials = validatePiAiProviderCredentials(activeModels, {
      anthropicApiKey: config.agentRuntimeConfig?.apiKey,
    });

    if (missingCredentials.length > 0) {
      const details = missingCredentials.map(
        (entry) => `  - ${entry.provider}: set one of [${entry.envVars.join(", ")}] (used by: ${entry.models.join(", ")})`,
      );
      if (missingCredentials.some((entry) => entry.provider === "anthropic")) {
        details.push(
          "Tip: for Anthropic models, you can also set agentRuntimeConfig.apiKey or pass --api-key for this run.",
        );
      }
      throw new CliConfigError("missing API credentials for selected model provider(s):", { details });
    }
  }

  warnPiAiBackendApiKeys(activeModels, {
    anthropicApiKey: config.agentRuntimeConfig?.apiKey,
  });

  configureRateLimitRegistry(config.triageConcurrency);

  try {
    return configureAgentRuntime(config);
  } catch (error) {
    throw new CliConfigError(error instanceof Error ? error.message : String(error));
  }
}

export function applyPipelineCacheOptions(opts: Pick<ScanCommandOptions, "fresh" | "cache">): void {
  if (opts.fresh || opts.cache === false) {
    inflightCache.enabled = false;
    inflightCache.invalidate();
  }
}

export async function runPipeline(params: PipelineParams): Promise<PipelineResult> {
  const {
    repoRoot,
    scanPath,
    repoName,
    config,
    scanOpts,
    opts,
    runtime: runtimeOverride,
  } = params;
  const reportMode = params.reportMode ?? "full";
  const manageCache = params.manageCache ?? true;

  if (manageCache) {
    applyPipelineCacheOptions(opts);
  }

  const runtime = runtimeOverride ?? createPipelineRuntime(config, scanOpts);
  const ownsRuntime = runtimeOverride == null;
  const dbPath = params.dbPath ?? defaultDbPath(repoRoot);
  const dbDir = path.dirname(dbPath);
  if (!existsSync(dbDir)) {
    mkdirSync(dbDir, { recursive: true });
  }

  const runRepoId = params.runRepoId ?? path.resolve(repoRoot);
  const db = initDb(dbPath);
  let bus: ReturnType<typeof createBus> | undefined;

  if (opts.fresh) {
    try {
      deleteFindingsForRepo(db, repoName);
    } catch (error) {
      db.close();
      throw new CliCommandError(error instanceof Error ? error.message : String(error));
    }
  }

  try {
    const registry = createDefaultRegistry();
    bus = createBus(config);
    const taskRegistry = await createDefaultTaskRegistry(registry, config, repoRoot);
    await registerAllWorkers(bus, { registry, taskRegistry, db, config, runtime });
  } catch (error) {
    db.close();
    if (ownsRuntime && isShutdownCapableRuntime(runtime)) {
      try { await runtime.shutdown(); } catch { /* best-effort */ }
    }
    throw new CliCommandError(error instanceof Error ? error.message : String(error));
  }

  registerShutdownHook("bus-drain", async () => {
    if (bus) {
      try { await bus.close(); } catch { /* best-effort */ }
    }
  }, 1);
  registerShutdownHook("db-close", async () => {
    try { db.close(); } catch { /* best-effort */ }
  }, 2);
  if (ownsRuntime) {
    registerShutdownHook("agent-runtime-shutdown", async () => {
      if (isShutdownCapableRuntime(runtime)) {
        try { await runtime.shutdown(); } catch { /* best-effort */ }
      }
    }, 3);
  }

  let streamingCleanup: (() => Promise<void>) | undefined;
  if (reportMode === "full" && config.streamingEnabled) {
    const { startStreamingServer } = await import("../../streaming.js");
    const streaming = startStreamingServer(bus, config.streamingPort ?? 0);
    streamingCleanup = streaming.close;
    registerShutdownHook("streaming-server", async () => {
      if (streamingCleanup) {
        try { await streamingCleanup(); } catch { /* best-effort */ }
      }
    }, 0);
  }

  const resumeRunId = resolveResumeRunId(db, runRepoId, repoName, opts.resume);
  const runId = resumeRunId ?? generateRunId();

  if (!resumeRunId) {
    markStaleRunsAborted(db, runRepoId);
    createRun(db, runId, runRepoId, config, scanOpts);
  }

  const context = {
    runId,
    repoRoot,
    scanPath,
    repoName,
    dbPath,
    reportMode,
  };

  const pipelineComplete = bus
    .waitFor<PipelineCompleteEvent>(
      "pipeline:complete",
      (event) => event.meta.runId === runId,
    )
    .then((event) => ({ kind: "complete" as const, event }));

  const pipelineError = bus
    .waitFor<PipelineErrorEvent>(
      "pipeline:error",
      (event) => event.meta.runId === runId && event.payload.fatal,
    )
    .then((event) => ({ kind: "error" as const, event }));

  if (reportMode === "full") {
    printScanPlan(config);
  }

  try {
    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts,
        resumeRunId,
      }),
    );

    const outcome = await Promise.race([pipelineComplete, pipelineError]);
    if (outcome.kind === "error") {
      printPipelineError(outcome.event.payload.error, outcome.event.payload.errorCategory);
      process.exitCode = 1;
      return {
        runId,
        status: "error",
      };
    }

    if (reportMode === "full") {
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

    return {
      runId,
      status: "complete",
      stats: outcome.event.payload.stats,
    };
  } finally {
    try {
      await bus.close();
    } finally {
      try {
        if (streamingCleanup) {
          await streamingCleanup();
        }
      } finally {
        try {
          if (ownsRuntime && isShutdownCapableRuntime(runtime)) {
            await runtime.shutdown();
          }
        } finally {
          db.close();
        }
      }
    }
  }
}

function printScanPlan(config: KuzushiConfig): void {
  const tasks = config.enabledTasks ?? [];
  const taskSummary = tasks.length === 0
    ? "none (scanners only)"
    : tasks.length === 1 && tasks[0] === "*"
      ? "all"
      : `${tasks.length} (${tasks.slice(0, 3).join(", ")}${tasks.length > 3 ? ", ..." : ""})`;
  const scanners = config.scanners?.join(", ") ?? "semgrep";
  const dynamic = config.enableDynamicTaskSelection ? "on" : "off";
  console.error("\nScan plan:");
  console.error(`  Scanners:  ${scanners}`);
  console.error(`  Tasks:     ${taskSummary}`);
  console.error(`  Dynamic:   ${dynamic}\n`);
}

function resolveResumeRunId(
  db: ReturnType<typeof initDb>,
  repoId: string,
  repoName: string,
  resume: string | boolean | undefined,
): string | undefined {
  if (resume === undefined) {
    return undefined;
  }

  let resumeRunId: string | undefined;
  if (resume === true) {
    const latest = getLatestResumableRun(db, repoId) ?? getLatestResumableRun(db, repoName);
    if (!latest) {
      throw new CliUsageError(`no resumable runs found for repo "${repoId}".`);
    }
    resumeRunId = latest.runId;
  } else if (typeof resume === "string" && resume.trim().length > 0) {
    resumeRunId = resume.trim();
  }

  if (!resumeRunId) {
    throw new CliUsageError("--resume received an invalid run id.");
  }

  const run = getRun(db, resumeRunId);
  if (!run) {
    throw new CliUsageError(`run "${resumeRunId}" was not found.`);
  }

  if (run.repo !== repoId && run.repo !== repoName) {
    throw new CliUsageError(`run "${resumeRunId}" belongs to repo "${run.repo}", not "${repoId}".`);
  }

  if (run.status === "complete") {
    throw new CliUsageError(`run "${resumeRunId}" is already complete and cannot be resumed.`);
  }

  return resumeRunId;
}

function reportConfigValidationIssues(issues: ReturnType<typeof validateKuzushiConfig>): void {
  const warnings = issues.filter((issue) => issue.severity === "warning");
  const errors = issues.filter((issue) => issue.severity === "error");

  for (const issue of warnings) {
    console.warn(`Warning: ${formatConfigValidationIssue(issue)}`);
  }

  if (!hasConfigValidationErrors(issues)) {
    return;
  }

  throw new CliConfigError("Configuration validation failed:", {
    details: errors.map((issue) => `  - ${formatConfigValidationIssue(issue)}`),
  });
}

function printPipelineError(errorMessage: string, errorCategory?: string): void {
  console.error(`Error: ${errorMessage}`);
  if (errorCategory === "auth") {
    console.error("Hint: Check your API key or credentials.");
  } else if (errorCategory === "rate_limit") {
    console.error("Hint: Reduce concurrency or wait before retrying.");
  } else if (errorCategory === "budget") {
    console.error("Hint: Increase your cost budget or use a cheaper model.");
  }
}

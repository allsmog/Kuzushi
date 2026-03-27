import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { registerShutdownHook } from "../../lifecycle.js";
import { loadConfig } from "../../config.js";
import {
  formatConfigValidationIssue,
  hasConfigValidationErrors,
  validateKuzushiConfig,
} from "../../config/validation.js";
import {
  createRun,
  deleteFindingsForRepo,
  defaultDbPath,
  getLatestResumableRun,
  getRun,
  initDb,
} from "../../store.js";
import { createDefaultRegistry } from "../../scanners/index.js";
import { createDefaultTaskRegistry } from "../../agents/index.js";
import { configureAgentRuntime } from "../../agent-runtime/index.js";
import { configureRateLimitRegistry } from "../../scheduler/index.js";
import {
  createBus,
  registerAllWorkers,
  createEvent,
  generateRunId,
  type PipelineCompleteEvent,
  type PipelineErrorEvent,
} from "../../bus/index.js";
import type { ScanOpts } from "../../types.js";
import { printQualityGateResult } from "../../report.js";
import { inflightCache } from "../../cache.js";
import { expandScannerSelections } from "../../capabilities.js";
import { CliCommandError, CliConfigError, CliUsageError } from "../errors.js";
import {
  applyScanCommandConfigOverrides,
  resolveScanSeverity,
  resolveScannerOverride,
  type ScanCommandOptions,
} from "../scan-config.js";
import { warnPiAiBackendApiKeys, resolveActivePiAiModels, validatePiAiProviderCredentials } from "../pi-ai.js";
import { isShutdownCapableRuntime, resolveRepo } from "../shared.js";

export async function runScanCommand(repoPath: string, opts: ScanCommandOptions): Promise<void> {
  const scanPath = path.resolve(repoPath);
  const { root: repoRoot, name: repoName } = resolveRepo(repoPath);

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

  const runtimeBackend = config.agentRuntimeBackend ?? "pi-ai";
  if (runtimeBackend === "pi-ai") {
    const activeModels = resolveActivePiAiModels(
      config,
      scanOpts.scanners ?? [],
      config.enabledTasks ?? [],
    );

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

    warnPiAiBackendApiKeys(activeModels, {
      anthropicApiKey: config.agentRuntimeConfig?.apiKey,
    });
  }

  let runtime;
  try {
    runtime = configureAgentRuntime(config);
  } catch (error) {
    throw new CliConfigError(error instanceof Error ? error.message : String(error));
  }

  configureRateLimitRegistry(config.triageConcurrency);

  if (opts.fresh || opts.cache === false) {
    inflightCache.enabled = false;
    inflightCache.invalidate();
  }

  const dbPath = opts.db ?? defaultDbPath(repoRoot);
  const dbDir = path.dirname(dbPath);
  if (!existsSync(dbDir)) mkdirSync(dbDir, { recursive: true });

  const repoId = path.resolve(repoRoot);
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
    bus = createBus(config);
    const taskRegistry = await createDefaultTaskRegistry(registry, config, repoRoot);
    await registerAllWorkers(bus, { registry, taskRegistry, db, config, runtime });
  } catch (error) {
    db.close();
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
  registerShutdownHook("agent-runtime-shutdown", async () => {
    if (isShutdownCapableRuntime(runtime)) {
      try { await runtime.shutdown(); } catch { /* best-effort */ }
    }
  }, 3);

  // Start streaming server if enabled
  let streamingCleanup: (() => Promise<void>) | undefined;
  if (config.streamingEnabled) {
    const { startStreamingServer } = await import("../../streaming.js");
    const streaming = startStreamingServer(bus, config.streamingPort ?? 0);
    streamingCleanup = streaming.close;
    registerShutdownHook("streaming-server", async () => {
      if (streamingCleanup) {
        try { await streamingCleanup(); } catch { /* best-effort */ }
      }
    }, 0);
  }

  const resumeRunId = resolveResumeRunId(db, repoId, repoName, opts.resume);
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
    } else {
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
      await bus.close();
    } finally {
      try {
        if (isShutdownCapableRuntime(runtime)) {
          await runtime.shutdown();
        }
      } finally {
        db.close();
      }
    }
  }
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

import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { configureAgentRuntime } from "../../agent-runtime/index.js";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import { createDefaultTaskRegistry } from "../../agents/index.js";
import {
  createBus,
  createEvent,
  generateRunId,
  type PipelineCompleteEvent,
  type PipelineErrorEvent,
  type PipelineStats,
  registerAllWorkers,
} from "../../bus/index.js";
import { resolveInitialTaskPlan } from "../../bus/orchestrator/task-policy.js";
import { inflightCache } from "../../cache.js";
import { expandTaskSelections } from "../../capabilities.js";
import {
  formatConfigValidationIssue,
  hasConfigValidationErrors,
  validateKuzushiConfig,
} from "../../config/validation.js";
import { loadConfig, resolveActiveCredentials } from "../../config.js";
import { looksLikeMonorepo } from "../../discovery/repo-discovery.js";
import { registerShutdownHook } from "../../lifecycle.js";
import { getGlobalLogLevel } from "../../logger.js";
import { printQualityGateResult } from "../../report.js";
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
import type { KuzushiConfig, ScanOpts } from "../../types.js";
import { configureTerminalOutput, resetTerminalOutput } from "../../ui/output.js";
import type { UIStore } from "../../ui/state.js";
import { CliCommandError, CliConfigError, CliUsageError } from "../errors.js";
import {
  resolveActivePiAiModels,
  validatePiAiProviderCredentials,
  warnPiAiBackendApiKeys,
} from "../pi-ai.js";
import {
  applyScanCommandConfigOverrides,
  resolveScannerOverride,
  resolveScanSeverity,
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
  postProcessMode?: "full" | "scan-only";
  dbPath?: string;
  runRepoId?: string;
  reportMode?: "full" | "suppress";
  runtime?: AgentRuntime;
  manageCache?: boolean;
  seedTaskOutputs?: Map<string, unknown>;
  /** Shared monorepo context injected into per-module pipeline state. */
  monorepoContext?: import("../../monorepo/types.js").MonorepoSharedContext;
  /** Optional UI store for Ink-based terminal rendering. */
  uiStore?: UIStore;
  /** Optional abort signal for shell-origin tool execution. */
  signal?: AbortSignal;
  /** Optional mode to restore after pipeline/report/review completion. */
  returnModeOnComplete?: import("../../ui/state.js").UIMode;
}

export interface PipelineResult {
  runId: string;
  status: "complete" | "error";
  stats?: PipelineStats;
  aborted?: boolean;
  error?: string;
}

export interface ScanPlanSummary {
  taskIds: string[];
  resolvedTaskIds: string[];
  dynamicSelectionActive: boolean;
  taskSummary: string;
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
  // Initialize the renderer before preflight so one session owns the entire run.
  // `--ci` swaps the Ink app for the machine-readable stream formatter.
  const { createUIRenderer } = await import("../../ui/render.js");
  const renderer = await createUIRenderer({ ci: Boolean(opts.ci) });
  const { store: uiStore, cleanup: cleanupUI } = renderer;
  configureTerminalOutput({
    store: uiStore,
    verbose: getGlobalLogLevel() === "debug",
    quiet: true,
  });

  const scanPath = path.resolve(repoPath);
  const { root: repoRoot, name: repoName } = resolveRepo(repoPath);
  uiStore.update({ repoName });

  // Interactive setup flow (skip for --resume)
  if (!opts.resume && process.stdout.isTTY) {
    const { isFirstRun, runSetupWizard, runConfigConfirmation } = await import("../../ui/setup.js");

    if (isFirstRun(repoRoot)) {
      // First-time user: show setup wizard
      const outcome = await runSetupWizard(uiStore, repoName, repoRoot);
      if (outcome.action === "cancel") {
        resetTerminalOutput();
        cleanupUI();
        return;
      }
      // Apply wizard selections as CLI overrides
      if (outcome.preset && !opts.preset) {
        opts.preset = outcome.preset;
      }
      if (outcome.model && !opts.model) {
        opts.model = outcome.model;
      }
    } else {
      // Returning user: show config confirmation
      const resolvedConfig = loadConfig(repoRoot, {
        trustProjectConfig: opts.trustRepoConfig === true,
      });
      const outcome = await runConfigConfirmation(
        uiStore,
        {
          model: resolvedConfig.model,
          tasks: resolvedConfig.tasks,
          severity: resolvedConfig.severity,
          concurrency: resolvedConfig.triageConcurrency,
          verify: resolvedConfig.verify,
          pocHarness: resolvedConfig.pocHarness,
          budget: resolvedConfig.costBudgetUsd,
        },
        repoName,
        repoRoot,
      );
      if (outcome.action === "cancel") {
        resetTerminalOutput();
        cleanupUI();
        return;
      }
    }
  }

  // Operator context intake — if persisted context or threat model exists, offer review
  if (!opts.resume && process.stdout.isTTY) {
    const { loadOperatorScanContext } = await import("../../operator-context.js");
    const { loadPersistentThreatModel } = await import("../../threat-model-renderer.js");
    const { runContextIntake, runThreatModelEditor } = await import("../../ui/setup.js");

    const existingContext = loadOperatorScanContext(repoRoot);
    if (existingContext) {
      const intakeOutcome = await runContextIntake(uiStore, existingContext, repoName, repoRoot);
      if (intakeOutcome.action === "cancel") {
        resetTerminalOutput();
        cleanupUI();
        return;
      }
    }

    const existingThreatModel = loadPersistentThreatModel(repoRoot);
    if (existingThreatModel) {
      const tmOutcome = await runThreatModelEditor(
        uiStore,
        existingThreatModel,
        repoName,
        repoRoot,
      );
      if (tmOutcome.action === "cancel") {
        resetTerminalOutput();
        cleanupUI();
        return;
      }
    }
  }

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
    resetTerminalOutput();
    cleanupUI();
    const { runMonorepoScan } = await import("./monorepo-scan.js");
    await runMonorepoScan(repoPath, opts);
    return;
  }

  if (opts.moduleFilter) {
    resetTerminalOutput();
    cleanupUI();
    throw new CliUsageError(
      "--module-filter can only be used when module discovery or manual modules are active.",
    );
  }

  const { config, scanOpts } = prepareScanExecution(repoRoot, opts);

  // Interactive credential prompt for the Claude backend when no credentials are detected.
  const isClaudeBackend = (config.agentRuntimeBackend ?? "claude") === "claude";
  if (isClaudeBackend && !opts.resume && process.stdout.isTTY) {
    const { hasAnthropicCredentials, runCredentialPrompt } = await import("../../ui/setup.js");
    const claudeSlotKey = config.agentRuntimeConfig?.claude?.apiKey;
    if (!hasAnthropicCredentials(claudeSlotKey)) {
      const credOutcome = await runCredentialPrompt(uiStore);
      if (credOutcome.action === "cancel") {
        resetTerminalOutput();
        cleanupUI();
        return;
      }

      const choice = credOutcome.choice;
      if (choice.kind === "api-key") {
        const existing = config.agentRuntimeConfig ?? {};
        config.agentRuntimeConfig = {
          ...existing,
          claude: {
            ...(existing.claude ?? {}),
            apiKey: choice.value,
            ...(choice.baseUrl ? { baseUrl: choice.baseUrl } : {}),
          },
        };
        process.env["ANTHROPIC_API_KEY"] = choice.value;
        if (choice.baseUrl) process.env["ANTHROPIC_BASE_URL"] = choice.baseUrl;
      } else if (choice.kind === "oauth-token") {
        process.env["ANTHROPIC_OAUTH_TOKEN"] = choice.value;
        if (choice.baseUrl) {
          const existing = config.agentRuntimeConfig ?? {};
          config.agentRuntimeConfig = {
            ...existing,
            claude: { ...(existing.claude ?? {}), baseUrl: choice.baseUrl },
          };
          process.env["ANTHROPIC_BASE_URL"] = choice.baseUrl;
        }
      }
      // "inherited" — no changes needed, subprocess will use parent env
    }
  }

  if (opts.dryRun) {
    resetTerminalOutput();
    cleanupUI();
    const { taskIds, taskSummary, dynamicSelectionActive } = getScanPlanSummary(config, scanOpts);
    console.log("\nDry run — no scan will be executed.");
    console.log(`  Target:    ${scanPath}`);
    console.log(`  Tasks:     ${taskIds.join(", ") || "none"}`);
    console.log(`  Expanded:  ${taskSummary}`);
    console.log(`  Dynamic:   ${dynamicSelectionActive ? "on" : "off"}`);
    console.log(`  Model:     ${config.model}`);
    console.log(`  Severity:  ${scanOpts.severity?.join(", ") || "all"}\n`);
    return;
  }

  try {
    await runPipeline({
      repoRoot,
      scanPath,
      repoName,
      config,
      scanOpts,
      opts,
      uiStore,
    });
  } finally {
    // Let the UI render one final frame before unmounting
    await new Promise((resolve) => setTimeout(resolve, 100));
    resetTerminalOutput();
    cleanupUI();
  }
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

  return (await looksLikeMonorepo(scanPath))
    ? { useMonorepo: true, reason: "auto-detected" }
    : { useMonorepo: false, reason: "single-root" };
}

export function prepareScanExecution(
  repoRoot: string,
  opts: ScanCommandOptions,
): PreparedScanExecution {
  const config = applyScanCommandConfigOverrides(
    loadConfig(repoRoot, { trustProjectConfig: opts.trustRepoConfig === true }),
    opts,
  );
  reportConfigValidationIssues(validateKuzushiConfig(config));

  const severity = resolveScanSeverity(config, opts);
  const taskOverride = resolveScannerOverride(opts);
  const requestedTasks = taskOverride ?? [...config.tasks];
  const expandedTasks = expandTaskSelections(requestedTasks, config);
  if (taskOverride) {
    config.tasks = expandedTasks;
  } else {
    config.tasks = expandedTasks;
  }

  const scanOpts: ScanOpts = {
    severity,
    maxFindings: opts.max,
    excludePatterns: config.excludePatterns,
    tasks: taskOverride ?? expandedTasks,
    fresh: opts.fresh,
  };

  return { config, scanOpts };
}

export function createPipelineRuntime(config: KuzushiConfig, scanOpts: ScanOpts): AgentRuntime {
  const activeModels = resolveActivePiAiModels(config, scanOpts.tasks ?? [], config.tasks ?? []);

  const isClaudeRuntime = (config.agentRuntimeBackend ?? "claude") === "claude";
  if (!isClaudeRuntime) {
    const missingCredentials = validatePiAiProviderCredentials(activeModels, {
      anthropicApiKey: resolveActiveCredentials(config).apiKey,
    });

    if (missingCredentials.length > 0) {
      const details = missingCredentials.map(
        (entry) =>
          `  - ${entry.provider}: set one of [${entry.envVars.join(", ")}] (used by: ${entry.models.join(", ")})`,
      );
      if (missingCredentials.some((entry) => entry.provider === "anthropic")) {
        details.push(
          "Tip: for Anthropic models, you can also set agentRuntimeConfig.apiKey or pass --api-key for this run.",
        );
      }
      throw new CliConfigError("missing API credentials for selected model provider(s):", {
        details,
      });
    }
  }

  if (!isClaudeRuntime) {
    warnPiAiBackendApiKeys(activeModels, {
      anthropicApiKey: resolveActiveCredentials(config).apiKey,
    });
  }

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
  const { repoRoot, scanPath, repoName, config, scanOpts, opts, runtime: runtimeOverride } = params;
  const reportMode = params.reportMode ?? "full";
  const manageCache = params.manageCache ?? true;

  if (manageCache) {
    applyPipelineCacheOptions(opts);
  }

  const runtime = runtimeOverride ?? createPipelineRuntime(config, scanOpts);
  const ownsRuntime = runtimeOverride == null;
  const dbPath = params.dbPath ?? resolveDbPath(repoRoot, scanPath);
  const dbDir = path.dirname(dbPath);
  if (!existsSync(dbDir)) {
    mkdirSync(dbDir, { recursive: true });
  }

  const runRepoId = params.runRepoId ?? path.resolve(repoRoot);
  const db = initDb(dbPath);
  let bus: ReturnType<typeof createBus> | undefined;
  let taskRegistry: Awaited<ReturnType<typeof createDefaultTaskRegistry>> | undefined;
  const shutdownHookDisposers: Array<() => void> = [];

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
    taskRegistry = await createDefaultTaskRegistry(config, repoRoot);
    await registerAllWorkers(bus, { taskRegistry, db, config, runtime, uiStore: params.uiStore });
  } catch (error) {
    db.close();
    if (ownsRuntime && isShutdownCapableRuntime(runtime)) {
      try {
        await runtime.shutdown();
      } catch {
        /* best-effort */
      }
    }
    throw new CliCommandError(error instanceof Error ? error.message : String(error));
  }

  shutdownHookDisposers.push(
    registerShutdownHook(
      "bus-drain",
      async () => {
        if (bus) {
          try {
            await bus.close();
          } catch {
            /* best-effort */
          }
        }
      },
      1,
    ),
  );
  shutdownHookDisposers.push(
    registerShutdownHook(
      "db-close",
      async () => {
        try {
          db.close();
        } catch {
          /* best-effort */
        }
      },
      2,
    ),
  );
  if (ownsRuntime) {
    shutdownHookDisposers.push(
      registerShutdownHook(
        "agent-runtime-shutdown",
        async () => {
          if (isShutdownCapableRuntime(runtime)) {
            try {
              await runtime.shutdown();
            } catch {
              /* best-effort */
            }
          }
        },
        3,
      ),
    );
  }

  let streamingCleanup: (() => Promise<void>) | undefined;
  if (reportMode === "full" && config.streamingEnabled) {
    const { startStreamingServer } = await import("../../streaming.js");
    const streaming = startStreamingServer(bus, config.streamingPort ?? 0);
    streamingCleanup = streaming.close;
    shutdownHookDisposers.push(
      registerShutdownHook(
        "streaming-server",
        async () => {
          if (streamingCleanup) {
            try {
              await streamingCleanup();
            } catch {
              /* best-effort */
            }
          }
        },
        0,
      ),
    );
  }

  const resumeRunId = resolveResumeRunId(db, runRepoId, repoName, opts.resume, scanPath);
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
    postProcessMode: params.postProcessMode ?? "full",
    reportMode,
  };

  const pipelineComplete = bus
    .waitFor<PipelineCompleteEvent>("pipeline:complete", (event) => event.meta.runId === runId)
    .then((event) => ({ kind: "complete" as const, event }));

  const pipelineError = bus
    .waitFor<PipelineErrorEvent>(
      "pipeline:error",
      (event) => event.meta.runId === runId && event.payload.fatal,
    )
    .then((event) => ({ kind: "error" as const, event }));
  const pipelineAbort = params.signal
    ? new Promise<{ kind: "aborted" }>((resolve) => {
        const signal = params.signal!;
        if (signal.aborted) {
          resolve({ kind: "aborted" });
          return;
        }
        signal.addEventListener("abort", () => resolve({ kind: "aborted" }), { once: true });
      })
    : undefined;

  if (reportMode === "full" && !params.uiStore) {
    printScanPlan(config, scanOpts, taskRegistry);
  }

  try {
    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts,
        resumeRunId,
        seedTaskOutputs: params.seedTaskOutputs,
        monorepoContext: params.monorepoContext,
      }),
    );

    const outcome = await Promise.race([
      pipelineComplete,
      pipelineError,
      ...(pipelineAbort ? [pipelineAbort] : []),
    ]);
    if (outcome.kind === "aborted") {
      if (params.uiStore) {
        params.uiStore.addNotice({
          level: "warning",
          message: "Pipeline cancelled",
          detail: "Stopped by shell request.",
          source: "pipeline",
        });
        if (params.returnModeOnComplete) {
          params.uiStore.setMode(params.returnModeOnComplete);
        }
      }
      return {
        runId,
        status: "error",
        aborted: true,
      };
    }
    if (outcome.kind === "error") {
      if (params.uiStore) {
        params.uiStore.addNotice({
          level: "error",
          message: "Pipeline failed",
          detail: outcome.event.payload.error,
          source: "pipeline",
        });
        if (params.returnModeOnComplete) {
          params.uiStore.setMode(params.returnModeOnComplete);
        }
      } else {
        printPipelineError(outcome.event.payload.error, outcome.event.payload.errorCategory);
      }
      if (!params.returnModeOnComplete) {
        process.exitCode = 1;
      }
      return {
        runId,
        status: "error",
        error: outcome.event.payload.error,
      };
    }

    if (reportMode === "full") {
      const { stats } = outcome.event.payload;
      if (stats.qualityGateResult) {
        if (params.uiStore) {
          params.uiStore.update({ qualityGate: stats.qualityGateResult });
        } else {
          printQualityGateResult(stats.qualityGateResult);
        }
      }
      if (stats.deadLetterCount && stats.deadLetterCount > 0) {
        console.error(
          `\n${stats.deadLetterCount} finding(s) failed all triage retries. Run \`kuzushi explain <fingerprint>\` for details.`,
        );
      }
    }

    // Interactive review: offer to review needs_review findings
    if (process.stdout.isTTY && reportMode === "full") {
      try {
        const { runInteractiveReview } = await import("../../ui/review.js");
        const reviewResult = await runInteractiveReview(
          db,
          repoName,
          params.uiStore,
          params.returnModeOnComplete ?? "summary",
        );
        if (reviewResult && reviewResult.reviewed > 0) {
          if (params.uiStore) {
            params.uiStore.addNotice({
              level: "success",
              message: "Review complete",
              detail: `${reviewResult.tp} tp · ${reviewResult.fp} fp · ${reviewResult.byDesign} by_design · ${reviewResult.skipped} skipped`,
              source: "review",
            });
            params.uiStore.setMode(params.returnModeOnComplete ?? "summary");
          } else {
            console.log(
              `\n  Review complete: ${reviewResult.tp} tp, ${reviewResult.fp} fp, ${reviewResult.byDesign} by_design, ${reviewResult.skipped} skipped`,
            );
          }
        }
      } catch {
        // Review is best-effort — don't fail the pipeline
      }
    }

    if (params.uiStore && params.returnModeOnComplete) {
      params.uiStore.setMode(params.returnModeOnComplete);
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
          try {
            db.close();
          } finally {
            for (const dispose of shutdownHookDisposers.reverse()) {
              try {
                dispose();
              } catch {
                /* best-effort */
              }
            }
          }
        }
      }
    }
  }
}

export function getScanPlanSummary(
  config: KuzushiConfig,
  scanOpts: ScanOpts,
  taskRegistry?: Awaited<ReturnType<typeof createDefaultTaskRegistry>>,
): ScanPlanSummary {
  const taskIds = scanOpts.tasks ?? config.tasks ?? ["semgrep"];
  const taskPlan = taskRegistry ? resolveInitialTaskPlan(taskRegistry, taskIds, config) : undefined;
  const resolvedTaskIds = taskPlan
    ? taskPlan.enabledTaskIds.filter((id) => !taskIds.includes(id))
    : [];
  return {
    taskIds,
    resolvedTaskIds,
    dynamicSelectionActive: taskPlan?.dynamicSelectionActive ?? false,
    taskSummary:
      resolvedTaskIds.length === 0
        ? "none"
        : `${resolvedTaskIds.length} (${resolvedTaskIds.slice(0, 4).join(", ")}${resolvedTaskIds.length > 4 ? ", ..." : ""})`,
  };
}

function printScanPlan(
  config: KuzushiConfig,
  scanOpts: ScanOpts,
  taskRegistry?: Awaited<ReturnType<typeof createDefaultTaskRegistry>>,
): void {
  const { taskIds, dynamicSelectionActive, taskSummary } = getScanPlanSummary(
    config,
    scanOpts,
    taskRegistry,
  );
  const tasks = taskIds.join(", ") || "none";
  console.error("\nScan plan:");
  console.error(`  Tasks:     ${tasks}`);
  console.error(`  Expanded:  ${taskSummary}`);
  console.error(`  Dynamic:   ${dynamicSelectionActive ? "on" : "off"}\n`);
}

function resolveResumeRunId(
  db: ReturnType<typeof initDb>,
  repoId: string,
  repoName: string,
  resume: string | boolean | undefined,
  scanPath?: string,
): string | undefined {
  if (resume === undefined) {
    return undefined;
  }

  let resumeRunId: string | undefined;
  if (resume === true) {
    const latest =
      getLatestResumableRun(db, repoId) ??
      getLatestResumableRun(db, repoName) ??
      (scanPath ? getLatestResumableRun(db, scanPath) : undefined);
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

  // Accept the run if its repo matches the git root, the repo name, or the
  // scan target path (for subdirectory scans within a monorepo).
  const knownIds = new Set([repoId, repoName]);
  if (scanPath) knownIds.add(path.resolve(scanPath));
  if (!knownIds.has(run.repo)) {
    throw new CliUsageError(`run "${resumeRunId}" belongs to repo "${run.repo}", not "${repoId}".`);
  }

  if (run.status === "complete") {
    throw new CliUsageError(`run "${resumeRunId}" is already complete and cannot be resumed.`);
  }

  return resumeRunId;
}

/**
 * Resolve the DB path, checking both the git root and the scan target.
 *
 * When scanning a subdirectory of a monorepo the git root (`repoRoot`) may
 * differ from the scan target (`scanPath`).  The DB could live at either
 * location depending on how previous scans were invoked.  We prefer an
 * existing DB at the scan target, then the git root, then default to the git
 * root for new databases.
 */
function resolveDbPath(repoRoot: string, scanPath: string): string {
  const gitRootDb = defaultDbPath(repoRoot);

  // When scan target is the git root there's nothing else to check.
  if (path.resolve(scanPath) === path.resolve(repoRoot)) {
    return gitRootDb;
  }

  const scanTargetDb = defaultDbPath(scanPath);

  // Prefer an existing DB at the scan target (more specific).
  if (existsSync(scanTargetDb)) {
    return scanTargetDb;
  }

  // Fall back to git root (shared monorepo DB).
  return gitRootDb;
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

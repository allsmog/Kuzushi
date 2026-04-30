import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { configureAgentRuntime } from "../../agent-runtime/index.js";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import { createDefaultDagRegistry } from "../../agents/index.js";
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
import { wireRunAbort } from "../../bus/run-abort.js";
import { unregisterRunSignal } from "../../bus/run-signals.js";
import { inflightCache } from "../../cache.js";
import { expandTaskSelections } from "../../capabilities.js";
import {
  formatConfigValidationIssue,
  hasConfigValidationErrors,
  validateKuzushiConfig,
} from "../../config/validation.js";
import { loadConfig, resolveActiveCredentials } from "../../config.js";
import type { ReportMode } from "../../contracts.js";
import { registerShutdownHook } from "../../lifecycle.js";
import { printQualityGateResult } from "../../report.js";
import { configureRateLimitRegistry } from "../../scheduler/index.js";
import type { PipelineRunOrigin } from "../../store.js";
import {
  createRun,
  defaultDbPath,
  deleteFindingsForRepo,
  getLatestResumableRun,
  getRun,
  hasRunCheckpoint,
  initDb,
  markStaleRunsAborted,
  updateRunStatus,
} from "../../store.js";
import type { KuzushiConfig, ScanOpts } from "../../types.js";
import type { UIMode, UIStore } from "../../ui/state.js";
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
import { isShutdownCapableRuntime } from "../shared.js";

export interface PreparedScanExecution {
  config: KuzushiConfig;
  scanOpts: ScanOpts;
}

export interface PipelineParams {
  repoRoot: string;
  scanPath: string;
  repoName: string;
  gitRoot?: string;
  config: KuzushiConfig;
  scanOpts: ScanOpts;
  opts: ScanCommandOptions;
  postProcessMode?: "full" | "scan-only";
  dbPath?: string;
  runRepoId?: string;
  reportMode?: ReportMode;
  runtime?: AgentRuntime;
  manageCache?: boolean;
  seedTaskOutputs?: Map<string, unknown>;
  monorepoContext?: import("../../monorepo/types.js").MonorepoSharedContext;
  uiStore?: UIStore;
  signal?: AbortSignal;
  returnModeOnComplete?: UIMode;
  origin?: PipelineRunOrigin;
  /** Shell-embedded single-task run — see {@link RunContext.inline}. */
  inline?: boolean;
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
  config.tasks = expandedTasks;

  // --diff-base: scope all detectors to files changed since <ref>.
  // Resolves to absolute paths so the scanners' `scanPaths` array is
  // unambiguous regardless of cwd. Field-test issue #51.
  let scanPaths: string[] | undefined;
  if (opts.diffBase) {
    try {
      const { execFileSync } = require("node:child_process") as typeof import("node:child_process");
      const path = require("node:path") as typeof import("node:path");
      const out = execFileSync("git", ["diff", "--name-only", `${opts.diffBase}..HEAD`], {
        cwd: repoRoot,
        encoding: "utf8",
      });
      const changed = out
        .split("\n")
        .map((line: string) => line.trim())
        .filter(Boolean);
      if (changed.length === 0) {
        const { getLogger } = require("../../logger.js") as typeof import("../../logger.js");
        getLogger("scan").warn(
          `--diff-base ${opts.diffBase}: no files changed since ref. Falling back to full-tree scan.`,
        );
      } else {
        scanPaths = changed.map((f: string) => path.join(repoRoot, f));
      }
    } catch (err) {
      const { getLogger } = require("../../logger.js") as typeof import("../../logger.js");
      getLogger("scan").warn(
        `--diff-base ${opts.diffBase}: git diff failed (${
          err instanceof Error ? err.message : String(err)
        }). Falling back to full-tree scan.`,
      );
    }
  }

  const scanOpts: ScanOpts = {
    severity,
    maxFindings: opts.max,
    maxRawFindings: opts.maxRawFindings,
    excludePatterns: config.excludePatterns,
    tasks: taskOverride ?? expandedTasks,
    fresh: opts.fresh,
    diffBase: opts.diffBase,
    scanPaths,
  };

  return { config, scanOpts };
}

export function createPipelineRuntime(config: KuzushiConfig, scanOpts: ScanOpts): AgentRuntime {
  const activeModels = resolveActivePiAiModels(config, scanOpts.tasks ?? [], config.tasks ?? []);

  const isClaudeRuntime = (config.agentRuntimeBackend ?? "pi-ai") === "claude";
  if (!isClaudeRuntime) {
    const activeCredentials = resolveActiveCredentials(config);
    const missingCredentials = validatePiAiProviderCredentials(activeModels, {
      anthropicApiKey: activeCredentials.apiKey,
      anthropicAuthToken: activeCredentials.authToken,
    });

    if (missingCredentials.length > 0) {
      const details = missingCredentials.map(
        (entry) =>
          `  - ${entry.provider}: set one of [${entry.envVars.join(", ")}] (used by: ${entry.models.join(", ")})`,
      );
      if (missingCredentials.some((entry) => entry.provider === "anthropic")) {
        details.push(
          "Tip: for Anthropic models, you can also set agentRuntimeConfig.<backend>.apiKey, agentRuntimeConfig.<backend>.authToken, or pass --api-key / --auth-token for this run.",
        );
      }
      throw new CliConfigError("missing API credentials for selected model provider(s):", {
        details,
      });
    }
  }

  if (!isClaudeRuntime) {
    const activeCredentials = resolveActiveCredentials(config);
    warnPiAiBackendApiKeys(activeModels, {
      anthropicApiKey: activeCredentials.apiKey,
      anthropicAuthToken: activeCredentials.authToken,
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
  const dbPath = params.dbPath ?? resolveDbPath(repoRoot, scanPath, params.gitRoot);
  const dbDir = path.dirname(dbPath);
  if (!existsSync(dbDir)) {
    mkdirSync(dbDir, { recursive: true, mode: 0o700 });
  }

  const runRepoId = params.runRepoId ?? path.resolve(repoRoot);
  const db = initDb(dbPath);
  let bus: ReturnType<typeof createBus> | undefined;
  let dagRegistry: Awaited<ReturnType<typeof createDefaultDagRegistry>> | undefined;
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
    // Honor `kuzushi scan --exclude codeql,...` symmetrically with the
    // shell command (#40). Comma-split, trim, drop empty entries.
    const excludeBuiltinModules = opts.exclude
      ?.split(",")
      .map((m: string) => m.trim())
      .filter(Boolean);
    dagRegistry = await createDefaultDagRegistry(config, repoRoot, { excludeBuiltinModules });
    await registerAllWorkers(bus, { dagRegistry, db, config, runtime, uiStore: params.uiStore });
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
    createRun(db, runId, runRepoId, config, scanOpts, params.origin);
  }

  // Partial-summary flush: when SIGTERM/SIGINT/timeout tears the process
  // down mid-run, write a `summary.partial.json` to the run dir with
  // whatever counters are in SQLite at the moment. Without this a killed
  // scan leaves no on-disk artifact summarising progress, even though
  // the findings table is populated. (Field-test issue #25.)
  // Priority 0 — runs BEFORE bus-drain (1) and db-close (2) so we can
  // still query SQLite. Skipped on resumed runs to avoid clobbering a
  // good summary.json from the original run.
  if (!resumeRunId) {
    const runDir = path.join(repoRoot, ".kuzushi", "runs", runId);
    shutdownHookDisposers.push(
      registerShutdownHook(
        "partial-summary-flush",
        async () => {
          try {
            const { existsSync, mkdirSync, writeFileSync } = await import("node:fs");
            // Skip if a real summary.json already landed (clean exit).
            if (existsSync(path.join(runDir, "summary.json"))) return;
            mkdirSync(runDir, { recursive: true });
            const partialPath = path.join(runDir, "summary.partial.json");
            const summary = {
              runId,
              repoName,
              abortedAt: new Date().toISOString(),
              note: "Process exited before pipeline:complete fired. Findings table in .kuzushi/findings.sqlite3 has whatever raw scanner output got pre-persisted.",
            };
            writeFileSync(partialPath, `${JSON.stringify(summary, null, 2)}\n`);
            console.error(`[shutdown] Wrote partial summary to ${partialPath}`);
          } catch {
            /* best-effort — partial-summary write failure must not block shutdown */
          }
        },
        0,
      ),
    );
  }

  const context = {
    runId,
    repoRoot,
    scanPath,
    repoName,
    dbPath,
    postProcessMode: params.postProcessMode ?? "full",
    reportMode,
    ...(params.gitRoot ? { gitRoot: params.gitRoot } : {}),
    ...(params.inline ? { inline: true } : {}),
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

  // Publish a per-run AbortSignal under this runId so bus workers
  // (scan-worker, etc.) can populate `DagRunContext.signal`. `wireRunAbort`
  // chains the caller's signal (Ctrl+C) and any fatal `pipeline:error`
  // event for this run into a single controller — the latter is the
  // fail-fast path that prevents the dispatchers from churning through
  // queued findings after the run state has already been torn down.
  wireRunAbort(bus, runId, params.signal);

  if (reportMode === "full" && !params.uiStore) {
    printScanPlan(config, scanOpts, dagRegistry);
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
      const status = hasRunCheckpoint(db, runId) ? "interrupted" : "aborted";
      updateRunStatus(db, runId, status);
      if (params.uiStore) {
        if (shouldShowPipelineNotice(params.uiStore, params.returnModeOnComplete)) {
          params.uiStore.addNotice({
            level: "warning",
            message: "Pipeline cancelled",
            detail: "Stopped by shell request.",
            source: "pipeline",
          });
        }
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
        if (params.returnModeOnComplete !== "shell") {
          params.uiStore.addNotice({
            level: "error",
            message: "Pipeline failed",
            detail: outcome.event.payload.error,
            source: "pipeline",
          });
        }
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
          `\n${stats.deadLetterCount} finding(s) failed all triage retries. Re-run with \`--resume\` after fixing the blocker, or use \`--review-findings\` to inspect completed findings.`,
        );
      }
      // Field-test issue #15a: when ≥1 scanner/detector task failed,
      // exit non-zero so CI / shell scripts notice. Previously kuzushi
      // reported `summary: $0.00 · 48s` exit 0 even when 100% of LLM
      // detectors failed. Skip when KUZUSHI_TOLERATE_TASK_FAILURES=1
      // for operators who want partial-success behavior preserved.
      const failedTasks = stats.failedTasks ?? [];
      if (
        failedTasks.length > 0 &&
        process.env["KUZUSHI_TOLERATE_TASK_FAILURES"] !== "1" &&
        process.exitCode !== 1
      ) {
        console.error(
          `\n${failedTasks.length} task(s) failed during scanning: ${failedTasks.join(", ")}. ` +
            `Set KUZUSHI_TOLERATE_TASK_FAILURES=1 to keep exit 0 on partial-failure runs.`,
        );
        process.exitCode = 1;
      }
    }

    if (
      process.stdout.isTTY &&
      reportMode === "full" &&
      params.opts.reviewFindings === true &&
      !params.inline
    ) {
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
        /* best-effort */
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
    unregisterRunSignal(runId);
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

function shouldShowPipelineNotice(uiStore: UIStore, returnModeOnComplete?: UIMode): boolean {
  return returnModeOnComplete !== "shell" && !uiStore.getState().shell;
}

export const __scanPipelineInternals = {
  shouldShowPipelineNotice,
};

export function getScanPlanSummary(
  config: KuzushiConfig,
  scanOpts: ScanOpts,
  dagRegistry?: Awaited<ReturnType<typeof createDefaultDagRegistry>>,
): ScanPlanSummary {
  const taskIds = scanOpts.tasks ?? config.tasks ?? ["semgrep"];
  const taskPlan = dagRegistry
    ? resolveInitialTaskPlan(dagRegistry, taskIds, config, {
        disabledTasks: scanOpts.disabledTasks,
      })
    : undefined;
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
  dagRegistry?: Awaited<ReturnType<typeof createDefaultDagRegistry>>,
): void {
  const { taskIds, dynamicSelectionActive, taskSummary } = getScanPlanSummary(
    config,
    scanOpts,
    dagRegistry,
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

  const knownIds = new Set([repoId, repoName]);
  if (scanPath) knownIds.add(path.resolve(scanPath));
  if (!knownIds.has(run.repo)) {
    throw new CliUsageError(`run "${resumeRunId}" belongs to repo "${run.repo}", not "${repoId}".`);
  }

  if (run.status === "complete") {
    throw new CliUsageError(
      `run "${resumeRunId}" is already complete. Use replay or rerun instead of resume.`,
    );
  }

  if (run.status === "error" || run.status === "aborted") {
    throw new CliUsageError(
      `run "${resumeRunId}" ended as ${run.status} and has no resumable checkpoint.`,
    );
  }

  if (!hasRunCheckpoint(db, resumeRunId)) {
    throw new CliUsageError(
      `run "${resumeRunId}" has no checkpoint. Re-run without --resume to start fresh.`,
    );
  }

  return resumeRunId;
}

function resolveDbPath(repoRoot: string, scanPath: string, gitRoot?: string): string {
  const targetDb = defaultDbPath(repoRoot);
  if (existsSync(targetDb)) {
    return targetDb;
  }

  if (scanPath) {
    const scanTargetDb = defaultDbPath(scanPath);
    if (existsSync(scanTargetDb)) {
      return scanTargetDb;
    }
  }

  if (gitRoot && path.resolve(gitRoot) !== path.resolve(repoRoot)) {
    const gitRootDb = defaultDbPath(gitRoot);
    if (existsSync(gitRootDb)) {
      return gitRootDb;
    }
  }

  return targetDb;
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

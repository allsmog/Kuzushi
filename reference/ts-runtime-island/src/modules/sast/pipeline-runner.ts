import type { KuzushiConfig } from "../../types.js";
import { toErrorMessage } from "../../utils.js";
import type { ExecutionContext, ToolResult } from "../types.js";
export function mergeTaskConfig(
  config: KuzushiConfig,
  overrides?: Record<string, Record<string, unknown>>,
): KuzushiConfig {
  if (!overrides || Object.keys(overrides).length === 0) {
    return config;
  }

  return {
    ...config,
    taskConfig: Object.entries(overrides).reduce<Record<string, Record<string, unknown>>>(
      (acc, [taskId, taskConfig]) => {
        acc[taskId] = {
          ...(config.taskConfig[taskId] ?? {}),
          ...Object.fromEntries(
            Object.entries(taskConfig).filter(([, value]) => value !== undefined),
          ),
        };
        return acc;
      },
      { ...config.taskConfig },
    ),
  };
}

function normalizeResumeInput(value: unknown): string | boolean | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value === "boolean") return value ? true : undefined;
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  if (trimmed === "true" || trimmed === "latest") return true;
  if (trimmed === "false") return undefined;
  return trimmed;
}

/**
 * M5: resolve the canonical post-persistence scan_findings count for a run.
 * Returns null when the workspace handle isn't reachable or the count query
 * fails (e.g. fresh DB without the v108 scan_findings table). Callers fall
 * back to `result.stats.totalFindings` in that case.
 */
function resolveCanonicalFindingCount(ctx: ExecutionContext, runId: string): number | null {
  if (!runId) return null;
  const workspace = ctx.workspace as { rawDb?: () => unknown } | undefined;
  const rawDb = workspace?.rawDb?.();
  if (!rawDb || typeof (rawDb as { prepare?: unknown }).prepare !== "function") {
    return null;
  }
  try {
    const stmt = (
      rawDb as { prepare: (sql: string) => { get: (param: string) => unknown } }
    ).prepare("SELECT COUNT(*) AS n FROM scan_findings WHERE run_id = ?");
    const row = stmt.get(runId) as { n?: number } | undefined;
    if (typeof row?.n === "number") return row.n;
  } catch {
    // Table missing on fresh DBs / older schemas — fall back to the in-memory stat.
  }
  return null;
}

function normalizeStringArrayInput(value: unknown): string[] | undefined {
  if (value == null) return undefined;
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === "string" && item.trim() !== "");
  }
  if (typeof value === "string") {
    const parsed = value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    return parsed.length > 0 ? parsed : undefined;
  }
  return undefined;
}

export async function executeSastPipeline(
  input: unknown,
  ctx: ExecutionContext,
  options?: {
    summaryLabel?: string;
    tasks?: string[];
    taskConfig?: Record<string, Record<string, unknown>>;
    configOverrides?: Partial<KuzushiConfig>;
    postProcessMode?: "full" | "scan-only";
    /** Shell-embedded single-task run — see RunContext.inline. */
    inline?: boolean;
  },
): Promise<ToolResult> {
  const params = input as Record<string, unknown>;
  const target = (params.target as string) ?? ctx.target;
  if (!target) {
    return {
      ok: false,
      output: `${options?.summaryLabel ?? "sast:scan"} requires a target (repo path).`,
    };
  }

  const { runPipeline } = await import("../../cli/commands/scan-pipeline.js");
  const { resolveRepo } = await import("../../cli/shared.js");
  const { resolveScanSeverity } = await import("../../cli/scan-config.js");
  const { configureTerminalOutput, resetTerminalOutput } = await import("../../ui/output.js");
  const { summarizePipelineResult } = await import("./pipeline-summary.js");
  const path = await import("node:path");

  const taskConfigMerged = mergeTaskConfig(ctx.config, options?.taskConfig);
  const mergedConfig = options?.configOverrides
    ? { ...taskConfigMerged, ...options.configOverrides }
    : taskConfigMerged;
  const scanPath = path.default.resolve(target);
  const { root: repoRoot, name: repoName } = resolveRepo(target);
  const requestedTasks = normalizeStringArrayInput(params.tasks);
  const taskMode: "auto" | "manual" = params.taskMode === "manual" ? "manual" : "auto";
  const taskModeExplicit = typeof params.taskMode === "string";
  const manualTasks = taskMode === "manual" || (!taskModeExplicit && requestedTasks?.length);
  const taskIds = options?.tasks ?? (manualTasks ? (requestedTasks ?? []) : undefined);
  const disabledTasks = normalizeStringArrayInput(params.disabledTasks);

  const config = taskIds
    ? { ...mergedConfig, tasks: [] as string[], enableDynamicTaskSelection: false }
    : mergedConfig;
  const severityOpt = Array.isArray(params.severity)
    ? (params.severity as string[]).join(",")
    : undefined;
  const severity = resolveScanSeverity(config, { severity: severityOpt });

  const scanOpts = {
    severity,
    excludePatterns: config.excludePatterns ?? [],
    fresh: false,
    tasks: taskIds,
    taskMode,
    disabledTasks,
  };

  const opts = {
    preset: (params.preset as string) ?? "standard",
    verify: (params.verify as boolean) ?? false,
    autoPatch: (params.autoPatch as boolean) ?? false,
    cryptoBehavioralTest: false,
    codeGraph: false,
    multiStrategy: false,
    multiStrategyFull: false,
    multiStrategyAutoRules: false,
    autoRuleGen: false,
    stream: false,
    githubPr: false,
    githubComment: false,
    auditLog: false,
    qualityGate: false,
    failOnTp: false,
    moduleDiscovery: true,
    fresh: false,
    pocHarness: false,
    context: true,
    tasks: taskIds?.join(","),
    resume: normalizeResumeInput(params.resume),
  };

  const uiStoreInternal = ctx.uiStore as import("../../ui/state.js").UIStore | undefined;

  if (uiStoreInternal) {
    uiStoreInternal.update({ repoName });
    configureTerminalOutput({ store: uiStoreInternal, quiet: true });
  }

  try {
    const result = await runPipeline({
      repoRoot,
      scanPath,
      repoName,
      config,
      scanOpts,
      opts: opts as import("../../cli/scan-config.js").ScanCommandOptions,
      runtime: ctx.runtime,
      reportMode: uiStoreInternal ? "full" : "suppress",
      manageCache: false,
      uiStore: uiStoreInternal,
      signal: ctx.signal,
      returnModeOnComplete: options?.inline
        ? undefined
        : uiStoreInternal?.getState().shell
          ? "shell"
          : undefined,
      postProcessMode: options?.postProcessMode ?? "full",
      seedTaskOutputs: ctx.seedTaskOutputs,
      ...(options?.inline ? { inline: true } : {}),
      origin: {
        moduleId: ctx.tool?.moduleId,
        toolName: ctx.tool?.name,
        resumeLabel: options?.summaryLabel ?? ctx.tool?.displayName ?? "Scan",
      },
    });

    const label = options?.summaryLabel ?? "Scan";
    // M5: prefer the DB-resolved scan_findings count over the in-memory stat
    // so operators see one canonical number across summary, sub-step, and
    // /findings views. Falls through to result.stats.totalFindings when the
    // workspace handle is unavailable (e.g. headless run modes).
    const canonicalFindingCount = resolveCanonicalFindingCount(ctx, result.runId);
    const summary = summarizePipelineResult({
      result,
      repoName,
      label,
      postProcessMode: options?.postProcessMode ?? "full",
      ...(canonicalFindingCount !== null ? { canonicalFindingCount } : {}),
    });

    return {
      ok: result.status === "complete",
      output: summary,
      data: {
        runId: result.runId,
        status: result.status,
        stats: result.stats
          ? canonicalFindingCount !== null
            ? { ...result.stats, totalFindings: canonicalFindingCount }
            : result.stats
          : null,
      },
      costUsd: result.stats?.totalCostUsd,
    };
  } catch (err) {
    const msg = toErrorMessage(err);
    if (msg.includes("Could not resolve authentication")) {
      return {
        ok: false,
        output: "Scan requires an API key. Set ANTHROPIC_API_KEY or use Claude Code OAuth.",
      };
    }
    return { ok: false, output: `Scan error: ${msg}` };
  } finally {
    if (ctx.uiStore) {
      resetTerminalOutput();
    }
  }
}

export async function runSingleTaskPipeline(
  taskIds: string[],
  input: unknown,
  ctx: ExecutionContext,
  extraOpts?: {
    summaryLabel?: string;
    taskConfig?: Record<string, Record<string, unknown>>;
    configOverrides?: Partial<KuzushiConfig>;
    /** Opt out of shell-inline rendering; defaults to true for single-task tools. */
    inline?: boolean;
  },
): Promise<ToolResult> {
  return executeSastPipeline(input, ctx, {
    summaryLabel: extraOpts?.summaryLabel,
    tasks: taskIds,
    ...(extraOpts?.taskConfig ? { taskConfig: extraOpts.taskConfig } : {}),
    ...(extraOpts?.configOverrides ? { configOverrides: extraOpts.configOverrides } : {}),
    postProcessMode: "scan-only",
    inline: extraOpts?.inline ?? true,
  });
}

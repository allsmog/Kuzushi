import type { KuzushiConfig } from "../../types.js";
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

export async function executeSastPipeline(
  input: unknown,
  ctx: ExecutionContext,
  options?: {
    summaryLabel?: string;
    tasks?: string[];
    taskConfig?: Record<string, Record<string, unknown>>;
    postProcessMode?: "full" | "scan-only";
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

  const mergedConfig = mergeTaskConfig(ctx.config, options?.taskConfig);
  const scanPath = path.default.resolve(target);
  const { root: repoRoot, name: repoName } = resolveRepo(target);
  const taskIds = options?.tasks ?? (params.tasks as string[] | undefined);

  const config =
    taskIds && taskIds.length > 0
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
      returnModeOnComplete: uiStoreInternal?.getState().shell ? "shell" : undefined,
      postProcessMode: options?.postProcessMode ?? "full",
      seedTaskOutputs: ctx.seedTaskOutputs,
    });

    const label = options?.summaryLabel ?? "Scan";
    const summary = summarizePipelineResult({
      result,
      repoName,
      label,
      postProcessMode: options?.postProcessMode ?? "full",
    });

    return {
      ok: result.status === "complete",
      output: summary,
      data: { runId: result.runId, status: result.status, stats: result.stats ?? null },
      costUsd: result.stats?.totalCostUsd,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
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
  },
): Promise<ToolResult> {
  return executeSastPipeline(input, ctx, {
    summaryLabel: extraOpts?.summaryLabel,
    tasks: taskIds,
    ...(extraOpts?.taskConfig ? { taskConfig: extraOpts.taskConfig } : {}),
    postProcessMode: "scan-only",
  });
}

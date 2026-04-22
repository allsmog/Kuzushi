/**
 * Shared helpers for the SAST module family.
 *
 * Everything in this file is infrastructure that 2+ sub-modules need:
 *   - `executeSastPipeline` / `runSingleTaskPipeline`: the pipeline runners
 *     that wrap `runPipeline` from src/cli/commands/scan.ts
 *   - `targetProperty` / `severityProperty`: shared JSONSchema fragments
 *   - `generateContextSnapshot` + friends: context-gathering DAG for `sast:context`
 *   - `formatContextSummary` + friends: rendering for the context summary view
 *   - Runtime shape helpers (`asRepoContext`, `asAppModel`, `asThreatModel`)
 *
 * This module exists to enable the SAST family to be split into per-capability
 * sub-modules (`semgrep`, `codeql`, `taint-iris`, `triage`, `verify`, `patch`,
 * `threat-hunt`, `context`, `findings`) while sharing this infra. Phase 1 of
 * that split extracts the helpers; Phase 2 creates the sub-modules.
 */

import type { KuzushiConfig } from "../../types.js";
import type { ToolExecutionContext, ToolResult } from "../types.js";

// ---------------------------------------------------------------------------
// Pipeline runners
// ---------------------------------------------------------------------------

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
  ctx: ToolExecutionContext,
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

  // Single-task dispatch (e.g. `/threat-hunt run .`, `/context build`) must
  // not merge with the ambient `config.tasks` baseline from
  // ~/.kuzushi/config.json — operators expect "run ONLY this" semantics.
  //
  // Two independent leaks close here when the caller pinned a task list:
  //   1. config.tasks baseline — defaults to ["semgrep"], would run semgrep
  //      alongside the pinned task.
  //   2. enableDynamicTaskSelection — defaults to true, injects
  //      "task-selector" (task-policy.ts:42-55), an LLM chooser that adds
  //      extra detectors (e.g. secrets-crypto-detect) it judges relevant.
  //
  // The full-DAG path (`kuzushi scan` / `/use sast; run`) passes
  // taskIds=undefined and keeps both features on.
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
    enableExternalTasks: false,
    qualityGate: false,
    failOnTp: false,
    moduleDiscovery: true,
    fresh: false,
    pocHarness: false,
    context: true,
    tasks: taskIds?.join(","),
  };

  // The public `HostUiHandle` narrows `UIStore` to `getState()/update()`.
  // Internal SAST infra still needs the concrete `UIStore` shape to pass
  // through to `runPipeline` / `configureTerminalOutput`; cast at the
  // boundary. Third parties outside `src/modules/` stay on the narrow type.
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
  ctx: ToolExecutionContext,
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

// ---------------------------------------------------------------------------
// Shared JSONSchema fragments
// ---------------------------------------------------------------------------

export const targetProperty = {
  type: "string",
  description: "Path to the repository to scan.",
} as const;

export const severityProperty = {
  type: "array",
  items: { type: "string", enum: ["critical", "high", "medium", "low"] },
  description: "Minimum severity levels to include.",
} as const;

// ---------------------------------------------------------------------------
// Context snapshot generation
// ---------------------------------------------------------------------------

export interface ContextGenOptions {
  enrichment: boolean;
  threatModel: boolean;
  scenarios: boolean;
  discovery: "auto" | "flat" | "modules";
}

/**
 * Human-friendly names for the internal task ids. The raw task id is
 * debug-grade ("threat-model-randori"); the operator-visible spinner should
 * describe the intent ("building threat model"). Unknown ids pass through.
 */
const STAGE_LABELS: Record<string, string> = {
  "context-gatherer": "scanning repo structure",
  "context-enricher": "enriching context",
  "threat-model-randori": "building threat model",
  "app-model-build": "building app model",
  "threat-scenario-build": "building threat scenarios",
};

function humanizeStage(taskName: string): string {
  return STAGE_LABELS[taskName] ?? taskName;
}

/**
 * Per-stage progress tracker — now a thin wrapper around `ctx.reportActivity`.
 *
 * Historically this overwrote `currentTool.name` with the humanized stage
 * label, which clobbered the actual tool name (`context:build`) and gave
 * operators a single frozen-looking line. It now publishes each stage as a
 * `task:activity` event so the shell's `ToolRunningStatus` renders the
 * stage in the rolling activity tail + phase strip while `currentTool.name`
 * stays pinned to the actual tool id.
 */
function createProgressTracker(ctx: ToolExecutionContext): {
  update: (name: string) => void;
  clear: () => void;
} {
  return {
    update(name: string) {
      ctx.reportActivity?.(name, { phase: name });
    },
    clear() {
      // no-op — `currentTool` is cleared by the shell when the tool returns
    },
  };
}

export async function generateContextSnapshot(
  target: string,
  ctx: ToolExecutionContext,
  opts: ContextGenOptions,
): Promise<import("../../ui/state.js").ContextSnapshot> {
  const path = await import("node:path");
  const { resolveRepo } = await import("../../cli/shared.js");

  const scanPath = path.default.resolve(target);
  const { root: repoRoot, name: repoName } = resolveRepo(target);

  if (opts.discovery !== "flat") {
    const { looksLikeMonorepo } = await import("../../discovery/repo-discovery.js");
    const isMonorepo = opts.discovery === "modules" || (await looksLikeMonorepo(repoRoot));
    if (isMonorepo) {
      return generateMonorepoSnapshot(target, ctx, opts, repoRoot, scanPath, repoName);
    }
  }

  const tracker = createProgressTracker(ctx);

  try {
    const result = await generateSingleProjectContext(
      scanPath,
      repoName,
      repoRoot,
      ctx,
      opts,
      (task) => tracker.update(humanizeStage(task)),
    );

    return {
      ...result,
      discovery: opts.discovery,
      options: {
        enrichment: opts.enrichment,
        threatModel: opts.threatModel,
        scenarios: opts.scenarios,
      },
    };
  } finally {
    tracker.clear();
  }
}

async function generateMonorepoSnapshot(
  target: string,
  ctx: ToolExecutionContext,
  opts: ContextGenOptions,
  repoRoot: string,
  scanPath: string,
  repoName: string,
): Promise<import("../../ui/state.js").ContextSnapshot> {
  const pathMod = await import("node:path");
  const { discoverRepoStructure } = await import("../../discovery/repo-discovery.js");

  const tracker = createProgressTracker(ctx);

  try {
    ctx.signal?.throwIfAborted();
    tracker.update("discovering modules");
    const discovery = await discoverRepoStructure(repoRoot, { maxModules: 15 });
    const discoveredModules = discovery.modules;

    if (discoveredModules.length === 0) {
      tracker.clear();
      return generateContextSnapshot(target, ctx, { ...opts, discovery: "flat" });
    }

    const modules: Record<
      string,
      Omit<import("../../ui/state.js").ContextSnapshot, "modules" | "discovery" | "options">
    > = {};
    const CONCURRENCY = 3;
    const total = discoveredModules.length;

    for (let i = 0; i < discoveredModules.length; i += CONCURRENCY) {
      ctx.signal?.throwIfAborted();
      const batch = discoveredModules.slice(i, i + CONCURRENCY);
      await Promise.all(
        batch.map(async (mod, batchIdx) => {
          const modulePath = pathMod.default.resolve(repoRoot, mod.path);
          const moduleRepoName = `${repoName}/${mod.path}`;
          const moduleIndex = i + batchIdx + 1;
          try {
            const moduleSnapshot = await generateSingleProjectContext(
              modulePath,
              moduleRepoName,
              repoRoot,
              ctx,
              opts,
              (task) =>
                tracker.update(`${mod.path} (${moduleIndex}/${total}) · ${humanizeStage(task)}`),
            );
            modules[mod.path] = moduleSnapshot;
          } catch (err) {
            // Skip individual module failures, but let AbortError bubble so
            // Ctrl+C stops the outer monorepo loop instead of continuing.
            if (ctx.signal?.aborted) throw err;
            if (err instanceof Error && err.name === "AbortError") throw err;
          }
        }),
      );
    }

    return {
      target: scanPath,
      timestamp: Date.now(),
      discovery: opts.discovery,
      options: {
        enrichment: opts.enrichment,
        threatModel: opts.threatModel,
        scenarios: opts.scenarios,
      },
      modules,
    };
  } finally {
    tracker.clear();
  }
}

async function generateSingleProjectContext(
  scanPath: string,
  repoName: string,
  repoRoot: string,
  ctx: ToolExecutionContext,
  opts: ContextGenOptions,
  updateProgress: (taskName: string) => void,
): Promise<Omit<import("../../ui/state.js").ContextSnapshot, "modules" | "discovery" | "options">> {
  const crypto = await import("node:crypto");

  const scanOpts = {
    severity: ["ERROR", "WARNING", "INFO"],
    excludePatterns: ctx.config.excludePatterns ?? [],
    fresh: false,
  };

  const upstreamOutputs = new Map<string, unknown>();
  const buildTaskContext = () => ({
    runId: crypto.randomUUID(),
    repoRoot,
    scanPath,
    projectRoot: repoRoot,
    workRoot: scanPath,
    repoName,
    config: ctx.config,
    runtime: ctx.runtime,
    bus: ctx.bus,
    upstreamOutputs,
    ...(ctx.signal ? { signal: ctx.signal } : {}),
  });

  // Helper: swallow non-abort errors ("optional" task failure semantics) but
  // let AbortError bubble up so Ctrl+C actually short-circuits the pipeline
  // instead of the catch quietly dropping the signal.
  const rethrowIfAborted = (err: unknown): void => {
    if (ctx.signal?.aborted) throw err;
    const name = err instanceof Error ? err.name : "";
    if (name === "AbortError") throw err;
  };

  ctx.signal?.throwIfAborted();
  updateProgress("context-gatherer");
  const { contextGathererTask } = await import("../../agents/tasks/context-gatherer.js");
  const gathererOutput = await contextGathererTask.run(scanOpts, buildTaskContext());
  upstreamOutputs.set("context-gatherer", gathererOutput);

  ctx.signal?.throwIfAborted();
  let enricherOutput: unknown;
  let threatModelOutput: unknown;
  const parallelTasks: Promise<void>[] = [];

  if (opts.enrichment) {
    parallelTasks.push(
      (async () => {
        updateProgress("context-enricher");
        try {
          const { contextEnricherTask } = await import("../../agents/tasks/context-enricher.js");
          enricherOutput = await contextEnricherTask.run(undefined, buildTaskContext());
          upstreamOutputs.set("context-enricher", enricherOutput);
        } catch (err) {
          rethrowIfAborted(err);
          /* optional */
        }
      })(),
    );
  }

  if (opts.threatModel) {
    parallelTasks.push(
      (async () => {
        updateProgress("threat-model-randori");
        try {
          const { threatModelRandoriTask } = await import(
            "../../agents/tasks/threat-modeling/randori.js"
          );
          threatModelOutput = await threatModelRandoriTask.run(scanOpts, buildTaskContext());
          upstreamOutputs.set("threat-model-randori", threatModelOutput);
        } catch (err) {
          rethrowIfAborted(err);
          /* optional */
        }
      })(),
    );
  }

  await Promise.all(parallelTasks);
  ctx.signal?.throwIfAborted();

  updateProgress("app-model-build");
  const { appModelBuildTask } = await import("../../agents/tasks/app-model-build.js");
  let appModel: unknown;
  try {
    appModel = await appModelBuildTask.run(scanOpts, buildTaskContext());
    upstreamOutputs.set("app-model-build", appModel);
  } catch (err) {
    rethrowIfAborted(err);
    /* optional */
  }

  let scenarioOutput: unknown;
  if (opts.scenarios && threatModelOutput && appModel) {
    ctx.signal?.throwIfAborted();
    updateProgress("threat-scenario-build");
    try {
      const { threatScenarioBuildTask } = await import(
        "../../agents/tasks/threat-scenario-build.js"
      );
      scenarioOutput = await threatScenarioBuildTask.run(undefined, buildTaskContext());
      upstreamOutputs.set("threat-scenario-build", scenarioOutput);
    } catch (err) {
      rethrowIfAborted(err);
      /* optional */
    }
  }

  const gatherer = gathererOutput as unknown as Record<string, unknown> | undefined;
  const tmOutput = threatModelOutput as unknown as Record<string, unknown> | undefined;
  const scOutput = scenarioOutput as unknown as Record<string, unknown> | undefined;

  return {
    target: scanPath,
    timestamp: Date.now(),
    repoContext: gatherer?.repoContext,
    fileIndex: gatherer?.fileIndex,
    enrichedContext: enricherOutput,
    appModel,
    threatModel: tmOutput?.document ?? tmOutput,
    scenarios: Array.isArray(scOutput?.scenarios) ? (scOutput.scenarios as unknown[]) : undefined,
  };
}

// ---------------------------------------------------------------------------
// Context summary formatting
// ---------------------------------------------------------------------------

export function formatContextSummary(
  snapshot: import("../../ui/state.js").ContextSnapshot,
  moduleFilter?: string,
): string {
  if (moduleFilter && snapshot.modules?.[moduleFilter]) {
    const mod = snapshot.modules[moduleFilter];
    return formatSingleContext(mod, `${snapshot.target}/${moduleFilter}`);
  }

  if (snapshot.modules && Object.keys(snapshot.modules).length > 0) {
    return formatMonorepoContext(snapshot);
  }

  return formatSingleContext(snapshot, snapshot.target);
}

function formatSingleContext(
  ctx: Pick<
    import("../../ui/state.js").ContextSnapshot,
    "repoContext" | "appModel" | "threatModel" | "scenarios" | "target" | "timestamp"
  >,
  label: string,
): string {
  const sections: string[][] = [];

  const headerLines = [`  Context: ${label}`];

  const rc = asRepoContext(ctx.repoContext);
  if (rc) {
    headerLines.push("");
    if (rc.languages.length) headerLines.push(`  Languages:   ${rc.languages.join(", ")}`);
    if (rc.frameworks.length) headerLines.push(`  Frameworks:  ${rc.frameworks.join(", ")}`);
    if (rc.authPatterns.length) headerLines.push(`  Auth:        ${rc.authPatterns.join(", ")}`);
    if (rc.ormOrDb.length) headerLines.push(`  Database:    ${rc.ormOrDb.join(", ")}`);
  }
  sections.push(headerLines);

  const am = asAppModel(ctx.appModel);
  if (am && am.routes.length > 0) {
    const routeLines = [`  Routes (${am.routes.length}):`];
    const shown = am.routes.slice(0, 8);
    for (const route of shown) {
      const annotations: string[] = [];
      if (route.authMechanisms?.length) annotations.push("auth");
      else annotations.push("public");
      if (route.middleware?.length) {
        const notable = route.middleware.filter(
          (m: string) => !["json", "urlencoded", "cors"].includes(m.toLowerCase()),
        );
        if (notable.length) annotations.push(...notable.slice(0, 2));
      }
      const method = (route.method ?? "?").toUpperCase().padEnd(7);
      routeLines.push(`    ${method} ${route.path ?? "?"}    ${annotations.join(", ")}`);
    }
    if (am.routes.length > 8) {
      routeLines.push(`    ...${am.routes.length - 8} more`);
    }
    sections.push(routeLines);
  }

  const tm = asThreatModel(ctx.threatModel);
  if (tm) {
    const tmLines = [`  Threat Model (STRIDE): ${tm.total} threats`];
    const bySev = tm.bySeverity;
    const sevParts: string[] = [];
    if (bySev.critical) sevParts.push(`${bySev.critical} critical`);
    if (bySev.high) sevParts.push(`${bySev.high} high`);
    if (bySev.medium) sevParts.push(`${bySev.medium} medium`);
    if (bySev.low) sevParts.push(`${bySev.low} low`);
    if (sevParts.length) tmLines.push(`    ${sevParts.join(" · ")}`);

    const topThreats = tm.threats
      .filter((t) => t.impact === "critical" || t.impact === "high")
      .slice(0, 3);
    for (const t of topThreats) {
      tmLines.push(`    ✗ ${t.title} (${t.impact})`);
    }
    sections.push(tmLines);
  }

  const statLines: string[] = [];
  if (am) {
    if (am.outboundClients.length) {
      statLines.push(
        `  Outbound Clients: ${am.outboundClients.map((c: { kind: string }) => c.kind).join(", ")}`,
      );
    }
    if (am.serviceBoundaries.length)
      statLines.push(`  Service Boundaries: ${am.serviceBoundaries.length}`);
    if (am.dataStores.length) statLines.push(`  Data Stores: ${am.dataStores.length}`);
  }
  if (statLines.length) sections.push(statLines);

  return sections
    .filter((s) => s.length > 0)
    .map((s) => s.join("\n"))
    .join("\n\n");
}

function formatMonorepoContext(snapshot: import("../../ui/state.js").ContextSnapshot): string {
  const modules = snapshot.modules ?? {};
  const moduleNames = Object.keys(modules);

  const lines = [`  Monorepo: ${snapshot.target} (${moduleNames.length} services)`];
  lines.push("");

  for (const name of moduleNames) {
    const mod = modules[name]!;
    const rc = asRepoContext(mod.repoContext);
    const am = asAppModel(mod.appModel);
    const tm = asThreatModel(mod.threatModel);
    const tech = rc ? [...rc.frameworks, ...rc.ormOrDb].slice(0, 3).join(", ") : "";
    const routes = am?.routes.length ?? 0;
    const threats = tm?.total ?? 0;

    const techStr = tech ? tech.padEnd(24) : "".padEnd(24);
    lines.push(`  ${name.padEnd(18)} ${techStr} ${routes} routes, ${threats} threats`);
  }

  let totalThreats = 0;
  const sevAccum: Record<string, number> = {};
  for (const mod of Object.values(modules)) {
    const tm = asThreatModel(mod.threatModel);
    if (tm) {
      totalThreats += tm.total;
      for (const [sev, count] of Object.entries(tm.bySeverity)) {
        sevAccum[sev] = (sevAccum[sev] ?? 0) + count;
      }
    }
  }
  if (totalThreats > 0) {
    const parts: string[] = [];
    if (sevAccum.critical) parts.push(`${sevAccum.critical} critical`);
    if (sevAccum.high) parts.push(`${sevAccum.high} high`);
    if (sevAccum.medium) parts.push(`${sevAccum.medium} medium`);
    lines.push("");
    lines.push(`  ${totalThreats} STRIDE threats total (${parts.join(", ")})`);
  }

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Runtime shape helpers for unknown-typed snapshot fields
// ---------------------------------------------------------------------------

interface RepoContextShape {
  languages: string[];
  frameworks: string[];
  authPatterns: string[];
  ormOrDb: string[];
  entryPoints: string[];
  sanitizationLibs: string[];
}

export function asRepoContext(raw: unknown): RepoContextShape | null {
  if (!raw || typeof raw !== "object") return null;
  const obj = raw as Record<string, unknown>;
  return {
    languages: asStringArray(obj.languages),
    frameworks: asStringArray(obj.frameworks),
    authPatterns: asStringArray(obj.authPatterns),
    ormOrDb: asStringArray(obj.ormOrDb),
    entryPoints: asStringArray(obj.entryPoints),
    sanitizationLibs: asStringArray(obj.sanitizationLibs),
  };
}

interface AppModelShape {
  routes: Array<{
    method?: string;
    path?: string;
    middleware?: string[];
    authMechanisms?: string[];
  }>;
  outboundClients: Array<{ kind: string }>;
  serviceBoundaries: unknown[];
  dataStores: unknown[];
  backgroundJobs: unknown[];
}

export function asAppModel(raw: unknown): AppModelShape | null {
  if (!raw || typeof raw !== "object") return null;
  const obj = raw as Record<string, unknown>;
  return {
    routes: Array.isArray(obj.routes) ? obj.routes : [],
    outboundClients: Array.isArray(obj.outboundClients) ? obj.outboundClients : [],
    serviceBoundaries: Array.isArray(obj.serviceBoundaries) ? obj.serviceBoundaries : [],
    dataStores: Array.isArray(obj.dataStores) ? obj.dataStores : [],
    backgroundJobs: Array.isArray(obj.backgroundJobs) ? obj.backgroundJobs : [],
  };
}

interface ThreatModelShape {
  total: number;
  bySeverity: Record<string, number>;
  threats: Array<{ title: string; impact: string }>;
}

export function asThreatModel(raw: unknown): ThreatModelShape | null {
  if (!raw || typeof raw !== "object") return null;
  const obj = raw as Record<string, unknown>;
  const summary = obj.summary as Record<string, unknown> | undefined;
  const threats = Array.isArray(obj.threats) ? obj.threats : [];
  return {
    total: typeof summary?.total === "number" ? summary.total : threats.length,
    bySeverity: (summary?.bySeverity as Record<string, number>) ?? {},
    threats: threats.map((t: Record<string, unknown>) => ({
      title: typeof t.title === "string" ? t.title : "Unknown",
      impact: typeof t.impact === "string" ? t.impact : "medium",
    })),
  };
}

function asStringArray(raw: unknown): string[] {
  return Array.isArray(raw) ? raw.filter((v): v is string => typeof v === "string") : [];
}

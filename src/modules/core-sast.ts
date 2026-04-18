/**
 * Core SAST module — wraps the existing Kuzushi pipeline as the built-in
 * "sast" CopilotModule.
 *
 * This is the bridge between the new module system and the existing
 * 40+ task pipeline. It exposes the pipeline's top-level operations
 * (scan, triage, verify, patch) as ModuleTools while keeping the
 * underlying DAG orchestrator, bus, and task registry intact.
 *
 * The pipeline mode (`kuzushi scan`) continues to work exactly as before —
 * this module just makes the same capabilities available to shell and run modes.
 */

import type { KuzushiConfig } from "../types.js";
import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "./types.js";

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

function mergeTaskConfig(
  config: KuzushiConfig,
  overrides?: Record<string, Record<string, unknown>>,
): KuzushiConfig {
  if (!overrides || Object.keys(overrides).length === 0) {
    return config;
  }

  return {
    ...config,
    taskConfig: Object.entries(overrides).reduce<Record<string, Record<string, unknown>>>(
      (acc, [taskId, taskConfig]) => ({
        ...acc,
        [taskId]: {
          ...(config.taskConfig[taskId] ?? {}),
          ...Object.fromEntries(
            Object.entries(taskConfig).filter(([, value]) => value !== undefined),
          ),
        },
      }),
      { ...config.taskConfig },
    ),
  };
}

async function executeSastPipeline(
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

  const { runPipeline } = await import("../cli/commands/scan.js");
  const { resolveRepo } = await import("../cli/shared.js");
  const { resolveScanSeverity } = await import("../cli/scan-config.js");
  const { configureTerminalOutput, resetTerminalOutput } = await import("../ui/output.js");
  const path = await import("node:path");

  const config = mergeTaskConfig(ctx.config, options?.taskConfig);
  const scanPath = path.default.resolve(target);
  const { root: repoRoot, name: repoName } = resolveRepo(target);
  const taskIds = options?.tasks ?? (params.tasks as string[] | undefined);
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

  if (ctx.uiStore) {
    ctx.uiStore.update({ repoName });
    configureTerminalOutput({ store: ctx.uiStore, quiet: true });
  }

  try {
    const result = await runPipeline({
      repoRoot,
      scanPath,
      repoName,
      config,
      scanOpts,
      opts: opts as import("../cli/scan-config.js").ScanCommandOptions,
      runtime: ctx.runtime,
      reportMode: ctx.uiStore ? "full" : "suppress",
      manageCache: false,
      uiStore: ctx.uiStore,
      signal: ctx.signal,
      returnModeOnComplete: ctx.uiStore?.getState().shell ? "shell" : undefined,
      postProcessMode: options?.postProcessMode ?? "full",
      seedTaskOutputs: ctx.seedTaskOutputs,
    });

    const label = options?.summaryLabel ?? "Scan";
    const findings = result.stats?.totalFindings ?? 0;
    const triaged = result.stats?.triaged ?? 0;
    const cost = result.stats?.totalCostUsd;

    const summary = result.aborted
      ? `${label} cancelled: ${repoName}`
      : result.status === "complete"
        ? options?.postProcessMode === "scan-only"
          ? `${label} complete: ${repoName} — ${findings} findings${cost ? ` ($${cost.toFixed(2)})` : ""}`
          : `${label} complete: ${repoName} — ${findings} findings, ${triaged} triaged${cost ? ` ($${cost.toFixed(2)})` : ""}`
        : `${label} finished with errors: ${repoName} — ${findings} findings${result.error ? ` (${result.error})` : ""}`;

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

async function runSingleTaskPipeline(
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
    taskConfig: extraOpts?.taskConfig,
    postProcessMode: "scan-only",
  });
}

const targetProperty = {
  type: "string",
  description: "Path to the repository to scan.",
} as const;

const severityProperty = {
  type: "array",
  items: { type: "string", enum: ["critical", "high", "medium", "low"] },
  description: "Minimum severity levels to include.",
} as const;

const scanTool: ModuleTool = {
  name: "sast:scan",
  description:
    "Run the full SAST pipeline on a target repository. " +
    "Orchestrates static scanners (Semgrep, CodeQL, agentic detectors), " +
    "normalizes and deduplicates findings, then runs AI triage to classify " +
    "each as true_positive, false_positive, or needs_review. " +
    "Supports presets (fast, standard, deep, reference) for cost/depth tradeoffs.",
  inputSchema: {
    type: "object",
    properties: {
      target: {
        type: "string",
        description: "Path to the repository to scan.",
      },
      preset: {
        type: "string",
        enum: ["fast", "standard", "deep", "reference"],
        default: "standard",
        description: "Scan depth preset. Defaults to standard.",
      },
      tasks: {
        type: "array",
        items: { type: "string" },
        description: "Specific task IDs to enable (e.g. ['semgrep', 'ssrf-detect']).",
      },
      severity: {
        type: "array",
        items: { type: "string", enum: ["critical", "high", "medium", "low"] },
        description: "Minimum severity levels to include.",
      },
      verify: {
        type: "boolean",
        description: "Enable post-triage exploitability verification.",
      },
      autoPatch: {
        type: "boolean",
        description: "Generate patches for confirmed vulnerabilities.",
      },
    },
    required: ["target"],
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    return executeSastPipeline(input, ctx, { summaryLabel: "Scan", postProcessMode: "full" });
  },
};

const semgrepTool: ModuleTool = {
  name: "sast:semgrep",
  description: "Run Semgrep only, with scan-only post-processing and report generation.",
  inputSchema: {
    type: "object",
    properties: {
      target: targetProperty,
      severity: severityProperty,
    },
    required: ["target"],
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    return runSingleTaskPipeline(["semgrep"], input, ctx, { summaryLabel: "Semgrep" });
  },
};

const codeqlTool: ModuleTool = {
  name: "sast:codeql",
  description: "Run CodeQL only, with scan-only post-processing and report generation.",
  inputSchema: {
    type: "object",
    properties: {
      target: targetProperty,
      severity: severityProperty,
    },
    required: ["target"],
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    return runSingleTaskPipeline(["codeql"], input, ctx, { summaryLabel: "CodeQL" });
  },
};

const agenticTool: ModuleTool = {
  name: "sast:agentic",
  description:
    "Run the agentic detector set only, with scan-only post-processing and report generation.",
  inputSchema: {
    type: "object",
    properties: {
      target: targetProperty,
      severity: severityProperty,
    },
    required: ["target"],
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    return runSingleTaskPipeline(["agentic"], input, ctx, { summaryLabel: "Agentic" });
  },
};

const threatHuntTool: ModuleTool = {
  name: "sast:threat-hunt",
  description:
    "Run the threat-hunt task only, with scan-only post-processing and report generation.",
  inputSchema: {
    type: "object",
    properties: {
      target: targetProperty,
      maxFindings: {
        type: "integer",
        default: 50,
        description: "Maximum number of findings to retain.",
      },
      maxActors: {
        type: "integer",
        default: 5,
        description: "Maximum number of threat actors to spawn.",
      },
      runsPerActor: {
        type: "integer",
        default: 1,
        description: "Number of hunts to run per actor.",
      },
      maxConcurrentHunts: {
        type: "integer",
        default: 3,
        description: "Maximum concurrent hunts.",
      },
      maxTurnsPerHunt: {
        type: "integer",
        default: 30,
        description: "Maximum turns per hunt.",
      },
    },
    required: ["target"],
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    const params = input as Record<string, unknown>;
    return runSingleTaskPipeline(["threat-hunt"], input, ctx, {
      summaryLabel: "Threat hunt",
      taskConfig: {
        "threat-hunt": {
          maxFindings: params.maxFindings,
          maxActors: params.maxActors,
          runsPerActor: params.runsPerActor,
          maxConcurrentHunts: params.maxConcurrentHunts,
          maxTurnsPerHunt: params.maxTurnsPerHunt,
        },
      },
    });
  },
};

const taintIrisTool: ModuleTool = {
  name: "sast:taint-iris",
  description:
    "Run IRIS taint analysis only, with scan-only post-processing and report generation.",
  inputSchema: {
    type: "object",
    properties: {
      target: targetProperty,
      severity: severityProperty,
    },
    required: ["target"],
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    return runSingleTaskPipeline(["taint-cwe-select", "taint-iris"], input, ctx, {
      summaryLabel: "Taint IRIS",
    });
  },
};

const triageTool: ModuleTool = {
  name: "sast:triage",
  description:
    "Run AI triage on a specific finding or set of findings. " +
    "The triage agent reads the code, traces dataflow, and classifies " +
    "each finding with a verdict (tp/fp/needs_review), confidence score, " +
    "rationale with code evidence, and verification steps.",
  inputSchema: {
    type: "object",
    properties: {
      fingerprint: {
        type: "string",
        description: "Finding fingerprint to triage.",
      },
      fingerprints: {
        type: "array",
        items: { type: "string" },
        description: "Multiple finding fingerprints to triage.",
      },
    },
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    const params = input as Record<string, unknown>;
    return {
      ok: true,
      output: `[sast:triage] Triage for finding(s) — implementation pending (Phase 2).`,
      data: { fingerprint: params.fingerprint, status: "pending" },
    };
  },
};

const verifyTool: ModuleTool = {
  name: "sast:verify",
  description:
    "Verify exploitability of a triaged finding. " +
    "The verification agent attempts to construct a concrete proof-of-concept " +
    "payload and optionally executes it in a sandboxed environment. " +
    "Returns exploitability assessment, PoC payload, attack vector, and proof level.",
  inputSchema: {
    type: "object",
    properties: {
      fingerprint: {
        type: "string",
        description: "Finding fingerprint to verify.",
      },
    },
    required: ["fingerprint"],
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    const params = input as Record<string, unknown>;
    return {
      ok: true,
      output: `[sast:verify] Verification for "${params.fingerprint}" — implementation pending (Phase 2).`,
      data: { fingerprint: params.fingerprint, status: "pending" },
    };
  },
};

const patchTool: ModuleTool = {
  name: "sast:patch",
  description:
    "Generate a security patch for a confirmed vulnerability. " +
    "Creates a fix in a disposable worktree, verifies the fix eliminates " +
    "the vulnerability, and returns the diff.",
  inputSchema: {
    type: "object",
    properties: {
      fingerprint: {
        type: "string",
        description: "Finding fingerprint to patch.",
      },
    },
    required: ["fingerprint"],
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    const params = input as Record<string, unknown>;
    return {
      ok: true,
      output: `[sast:patch] Patch generation for "${params.fingerprint}" — implementation pending (Phase 2).`,
      data: { fingerprint: params.fingerprint, status: "pending" },
    };
  },
};

const findingsTool: ModuleTool = {
  name: "sast:findings",
  description:
    "Query findings from the workspace database. " +
    "Filter by severity, verdict, scanner, CWE, file path, or fingerprint. " +
    "Returns structured finding data with triage results if available.",
  inputSchema: {
    type: "object",
    properties: {
      severity: {
        type: "array",
        items: { type: "string", enum: ["critical", "high", "medium", "low"] },
        description: "Filter by severity levels.",
      },
      verdict: {
        type: "array",
        items: { type: "string", enum: ["tp", "fp", "needs_review", "by_design"] },
        description: "Filter by triage verdict.",
      },
      path: {
        type: "string",
        description: "Filter by file path (prefix match).",
      },
      limit: {
        type: "number",
        default: 50,
        description: "Max number of findings to return. Defaults to 50.",
      },
    },
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    return {
      ok: true,
      output: `[sast:findings] Query findings — implementation pending (Phase 2).`,
      data: { status: "pending" },
    };
  },
};

// ---------------------------------------------------------------------------
// Context tool — direct task invocation for the application "map"
// ---------------------------------------------------------------------------

const contextTool: ModuleTool = {
  name: "sast:context",
  description:
    "Generate the application context map for a target repository. " +
    "Runs context gathering, LLM enrichment, app model extraction, " +
    "PASTA threat modeling, and threat scenario building. " +
    "Results are cached and required by tools like threat-hunt and taint-iris.",
  inputSchema: {
    type: "object",
    properties: {
      target: {
        type: "string",
        description: "Path to the repository to analyze.",
      },
      discovery: {
        type: "string",
        enum: ["auto", "flat", "modules"],
        default: "auto",
        description: "auto = detect monorepo, flat = single project, modules = force per-module.",
      },
      enrichment: {
        type: "boolean",
        default: true,
        description: "Run LLM context enrichment (1 API call).",
      },
      threatModel: {
        type: "boolean",
        default: true,
        description: "Run PASTA S1-S4 threat modeling.",
      },
      scenarios: {
        type: "boolean",
        default: true,
        description: "Build threat scenarios from STRIDE threats.",
      },
    },
    required: ["target"],
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    const params = input as Record<string, unknown>;
    const target = (params.target as string) ?? ctx.target;
    if (!target) {
      return { ok: false, output: "sast:context requires a target (repo path)." };
    }

    const enrichment = params.enrichment !== false;
    const threatModel = params.threatModel !== false;
    const scenarios = params.scenarios !== false && threatModel;
    const discovery = (params.discovery as string) ?? "auto";

    try {
      const snapshot = await generateContextSnapshot(target, ctx, {
        enrichment,
        threatModel,
        scenarios,
        discovery: discovery as "auto" | "flat" | "modules",
      });

      // Store on ShellState for gating and display
      if (ctx.uiStore) {
        const shell = ctx.uiStore.getState().shell;
        if (shell) {
          ctx.uiStore.update({ shell: { ...shell, contextSnapshot: snapshot } });
        }
      }

      return {
        ok: true,
        output: formatContextSummary(snapshot),
        data: snapshot,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { ok: false, output: `Context generation error: ${msg}` };
    }
  },
};

interface ContextGenOptions {
  enrichment: boolean;
  threatModel: boolean;
  scenarios: boolean;
  discovery: "auto" | "flat" | "modules";
}

async function generateContextSnapshot(
  target: string,
  ctx: ToolExecutionContext,
  opts: ContextGenOptions,
): Promise<import("../ui/state.js").ContextSnapshot> {
  const path = await import("node:path");
  const _crypto = await import("node:crypto");
  const { resolveRepo } = await import("../cli/shared.js");

  const scanPath = path.default.resolve(target);
  const { root: repoRoot, name: repoName } = resolveRepo(target);

  // Monorepo detection — branch to per-module context generation
  if (opts.discovery !== "flat") {
    const { looksLikeMonorepo } = await import("../discovery/repo-discovery.js");
    const isMonorepo = opts.discovery === "modules" || (await looksLikeMonorepo(repoRoot));
    if (isMonorepo) {
      return generateMonorepoSnapshot(target, ctx, opts, repoRoot, scanPath, repoName);
    }
  }

  // Single-project context generation — delegate to shared helper
  const updateProgress = (taskName: string) => {
    if (ctx.uiStore) {
      const shell = ctx.uiStore.getState().shell;
      if (shell) {
        ctx.uiStore.update({
          shell: { ...shell, currentTool: { name: taskName, elapsedSeconds: 0 } },
        });
      }
    }
  };

  const clearProgress = () => {
    if (ctx.uiStore) {
      const shell = ctx.uiStore.getState().shell;
      if (shell) {
        ctx.uiStore.update({ shell: { ...shell, currentTool: undefined } });
      }
    }
  };

  const result = await generateSingleProjectContext(
    scanPath,
    repoName,
    repoRoot,
    ctx,
    opts,
    updateProgress,
  );

  clearProgress();

  return {
    ...result,
    discovery: opts.discovery,
    options: {
      enrichment: opts.enrichment,
      threatModel: opts.threatModel,
      scenarios: opts.scenarios,
    },
  };
}

async function generateMonorepoSnapshot(
  target: string,
  ctx: ToolExecutionContext,
  opts: ContextGenOptions,
  repoRoot: string,
  scanPath: string,
  repoName: string,
): Promise<import("../ui/state.js").ContextSnapshot> {
  const pathMod = await import("node:path");
  const { discoverRepoStructure } = await import("../discovery/repo-discovery.js");

  const updateProgress = (taskName: string) => {
    if (ctx.uiStore) {
      const shell = ctx.uiStore.getState().shell;
      if (shell) {
        ctx.uiStore.update({
          shell: { ...shell, currentTool: { name: taskName, elapsedSeconds: 0 } },
        });
      }
    }
  };

  const clearProgress = () => {
    if (ctx.uiStore) {
      const shell = ctx.uiStore.getState().shell;
      if (shell) {
        ctx.uiStore.update({ shell: { ...shell, currentTool: undefined } });
      }
    }
  };

  // Discover sub-projects (metadata only — no LLM, fast and free)
  updateProgress("discovering modules");
  const discovery = await discoverRepoStructure(repoRoot, { maxModules: 15 });
  const discoveredModules = discovery.modules;

  if (discoveredModules.length === 0) {
    // No modules found — fall back to single-project mode
    clearProgress();
    return generateContextSnapshot(target, ctx, { ...opts, discovery: "flat" });
  }

  // Generate context for each discovered module (concurrency 3)
  const modules: Record<
    string,
    Omit<import("../ui/state.js").ContextSnapshot, "modules" | "discovery" | "options">
  > = {};
  const CONCURRENCY = 3;

  for (let i = 0; i < discoveredModules.length; i += CONCURRENCY) {
    const batch = discoveredModules.slice(i, i + CONCURRENCY);
    await Promise.all(
      batch.map(async (mod) => {
        const modulePath = pathMod.default.resolve(repoRoot, mod.path);
        const moduleRepoName = `${repoName}/${mod.path}`;
        try {
          const moduleSnapshot = await generateSingleProjectContext(
            modulePath,
            moduleRepoName,
            repoRoot,
            ctx,
            opts,
            (task) => updateProgress(`${mod.path}/${task}`),
          );
          modules[mod.path] = moduleSnapshot;
        } catch {
          // Skip failing modules, continue with others
        }
      }),
    );
  }

  clearProgress();

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
}

/**
 * Generate context for a single project. Shared by both single-project mode
 * and per-module monorepo context generation.
 */
async function generateSingleProjectContext(
  scanPath: string,
  repoName: string,
  repoRoot: string,
  ctx: ToolExecutionContext,
  opts: ContextGenOptions,
  updateProgress: (taskName: string) => void,
): Promise<Omit<import("../ui/state.js").ContextSnapshot, "modules" | "discovery" | "options">> {
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
  });

  // Step 1: context-gatherer (always)
  updateProgress("context-gatherer");
  const { contextGathererTask } = await import("../agents/tasks/context-gatherer.js");
  const gathererOutput = await contextGathererTask.run(scanOpts, buildTaskContext());
  upstreamOutputs.set("context-gatherer", gathererOutput);

  // Step 2: enricher + threat-model (parallel, optional)
  let enricherOutput: unknown;
  let threatModelOutput: unknown;
  const parallelTasks: Promise<void>[] = [];

  if (opts.enrichment) {
    parallelTasks.push(
      (async () => {
        updateProgress("context-enricher");
        try {
          const { contextEnricherTask } = await import("../agents/tasks/context-enricher.js");
          enricherOutput = await contextEnricherTask.run(undefined, buildTaskContext());
          upstreamOutputs.set("context-enricher", enricherOutput);
        } catch {
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
            "../agents/tasks/threat-modeling/randori.js"
          );
          threatModelOutput = await threatModelRandoriTask.run(scanOpts, buildTaskContext());
          upstreamOutputs.set("threat-model-randori", threatModelOutput);
        } catch {
          /* optional */
        }
      })(),
    );
  }

  await Promise.all(parallelTasks);

  // Step 3: app-model-build
  updateProgress("app-model-build");
  const { appModelBuildTask } = await import("../agents/tasks/app-model-build.js");
  let appModel: unknown;
  try {
    appModel = await appModelBuildTask.run(scanOpts, buildTaskContext());
    upstreamOutputs.set("app-model-build", appModel);
  } catch {
    /* optional */
  }

  // Step 4: threat-scenario-build
  let scenarioOutput: unknown;
  if (opts.scenarios && threatModelOutput && appModel) {
    updateProgress("threat-scenario-build");
    try {
      const { threatScenarioBuildTask } = await import("../agents/tasks/threat-scenario-build.js");
      scenarioOutput = await threatScenarioBuildTask.run(undefined, buildTaskContext());
      upstreamOutputs.set("threat-scenario-build", scenarioOutput);
    } catch {
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
  snapshot: import("../ui/state.js").ContextSnapshot,
  moduleFilter?: string,
): string {
  // Monorepo drill-down
  if (moduleFilter && snapshot.modules?.[moduleFilter]) {
    const mod = snapshot.modules[moduleFilter];
    return formatSingleContext(mod, `${snapshot.target}/${moduleFilter}`);
  }

  // Monorepo overview
  if (snapshot.modules && Object.keys(snapshot.modules).length > 0) {
    return formatMonorepoContext(snapshot);
  }

  // Single project
  return formatSingleContext(snapshot, snapshot.target);
}

function formatSingleContext(
  ctx: Pick<
    import("../ui/state.js").ContextSnapshot,
    "repoContext" | "appModel" | "threatModel" | "scenarios" | "target" | "timestamp"
  >,
  label: string,
): string {
  const sections: string[][] = [];

  // Header
  const headerLines = [`  Context: ${label}`];

  // Repo info
  const rc = asRepoContext(ctx.repoContext);
  if (rc) {
    headerLines.push("");
    if (rc.languages.length) headerLines.push(`  Languages:   ${rc.languages.join(", ")}`);
    if (rc.frameworks.length) headerLines.push(`  Frameworks:  ${rc.frameworks.join(", ")}`);
    if (rc.authPatterns.length) headerLines.push(`  Auth:        ${rc.authPatterns.join(", ")}`);
    if (rc.ormOrDb.length) headerLines.push(`  Database:    ${rc.ormOrDb.join(", ")}`);
  }
  sections.push(headerLines);

  // Routes from app model
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

  // Threat model
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

    // Top threats
    const topThreats = tm.threats
      .filter((t) => t.impact === "critical" || t.impact === "high")
      .slice(0, 3);
    for (const t of topThreats) {
      tmLines.push(`    ✗ ${t.title} (${t.impact})`);
    }
    sections.push(tmLines);
  }

  // Stats
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

function formatMonorepoContext(snapshot: import("../ui/state.js").ContextSnapshot): string {
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

  // Total threats
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

// --- Runtime shape helpers for unknown-typed snapshot fields ---

interface RepoContextShape {
  languages: string[];
  frameworks: string[];
  authPatterns: string[];
  ormOrDb: string[];
  entryPoints: string[];
  sanitizationLibs: string[];
}

function asRepoContext(raw: unknown): RepoContextShape | null {
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

function asAppModel(raw: unknown): AppModelShape | null {
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

function asThreatModel(raw: unknown): ThreatModelShape | null {
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

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

/**
 * Create the core SAST module.
 *
 * This is a factory function rather than a static object because
 * the module may need to reference the task registry or other
 * runtime-specific state during initialization.
 */
export function createCoreSastModule(): CopilotModule {
  return {
    id: "sast",
    displayName: "SAST Pipeline",
    category: "offense",
    version: "0.1.0",
    description:
      "Core static analysis security testing pipeline. " +
      "Runs Semgrep, CodeQL, and 30+ agentic detectors with AI triage, " +
      "verification, PoC generation, and patch synthesis.",

    tools: [
      contextTool,
      scanTool,
      semgrepTool,
      codeqlTool,
      agenticTool,
      threatHuntTool,
      taintIrisTool,
      triageTool,
      verifyTool,
      patchTool,
      findingsTool,
    ],

    // Tasks are not listed here — they're already registered via
    // createDefaultTaskRegistry(). The SAST module bridges to the
    // existing pipeline rather than re-declaring its 40+ tasks.
    tasks: undefined,

    events: {
      produces: [
        "scan:finding",
        "scan:complete",
        "triage:result",
        "verification:result",
        "patch:generated",
        "patch:verified",
      ],
      consumes: ["pipeline:start", "task:complete", "stage:complete"],
    },

    async init(_config, _ctx) {
      // The SAST pipeline is initialized by the existing orchestrator flow.
      // No additional init needed at the module level.
    },

    async dispose() {
      // Pipeline cleanup is handled by the orchestrator's shutdown logic.
    },
  };
}

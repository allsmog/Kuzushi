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

import type {
  CopilotModule,
  ModuleContext,
  ModuleTool,
  ToolExecutionContext,
  ToolResult,
} from "./types.js";

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

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
    const params = input as Record<string, unknown>;
    const target = (params.target as string) ?? ctx.target;
    if (!target) {
      return { ok: false, output: "sast:scan requires a target (repo path)." };
    }

    try {
      const path = await import("node:path");
      const { runPipeline } = await import("../cli/commands/scan.js");
      const { resolveRepo } = await import("../cli/shared.js");
      const { resolveScanSeverity } = await import("../cli/scan-config.js");

      const scanPath = path.default.resolve(target);
      const { root: repoRoot, name: repoName } = resolveRepo(target);

      // Map tool input to ScanCommandOptions (minimal subset)
      const preset = (params.preset as string) ?? "standard";
      const severityOpt = params.severity
        ? (params.severity as string[]).join(",")
        : undefined;
      const severity = resolveScanSeverity(ctx.config, { severity: severityOpt });

      const scanOpts = {
        severity,
        excludePatterns: ctx.config.excludePatterns ?? [],
        fresh: false,
        tasks: params.tasks as string[] | undefined,
      };

      const opts = {
        preset,
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
        tasks: params.tasks ? (params.tasks as string[]).join(",") : undefined,
      };

      const result = await runPipeline({
        repoRoot,
        scanPath,
        repoName,
        config: ctx.config,
        scanOpts,
        opts: opts as import("../cli/scan-config.js").ScanCommandOptions,
        runtime: ctx.runtime,
        reportMode: "suppress",
        manageCache: false,
      });

      return {
        ok: result.status === "complete",
        output: result.status === "complete"
          ? `[sast:scan] Pipeline complete for "${repoName}" (run: ${result.runId}). ` +
            `${result.stats?.totalFindings ?? 0} findings, ` +
            `${result.stats?.triaged ?? 0} triaged.`
          : `[sast:scan] Pipeline failed for "${repoName}" (run: ${result.runId}).`,
        data: {
          runId: result.runId,
          status: result.status,
          stats: result.stats ?? null,
        },
        costUsd: result.stats?.totalCostUsd,
      };
    } catch (err) {
      return {
        ok: false,
        output: `[sast:scan] Error: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
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

    tools: [scanTool, triageTool, verifyTool, patchTool, findingsTool],

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
      consumes: [
        "pipeline:start",
        "task:complete",
        "stage:complete",
      ],
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

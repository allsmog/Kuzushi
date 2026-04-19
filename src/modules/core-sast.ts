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
 *
 * Pipeline infra (runPipeline wrappers, JSONSchema fragments, context DAG,
 * context-summary renderer, runtime shape helpers) lives in ./sast/shared.ts
 * so the planned per-capability sub-modules (semgrep, codeql, taint-iris,
 * triage, verify, patch, threat-hunt, context, findings) can share it.
 */

import {
  executeSastPipeline,
  generateContextSnapshot,
  runSingleTaskPipeline,
  severityProperty,
  formatContextSummary as sharedFormatContextSummary,
  targetProperty,
} from "./sast/shared.js";
import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "./types.js";

// Re-export so external callers (src/copilot/shell.ts) keep working.
export const formatContextSummary = sharedFormatContextSummary;

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

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
  formatContextSummary as sharedFormatContextSummary,
} from "./sast/shared.js";
import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "./types.js";

// Re-export so external callers (src/copilot/shell.ts) keep working.
export const formatContextSummary = sharedFormatContextSummary;

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

const scanTool: ModuleTool = {
  name: "sast:scan",
  displayName: "Scan",
  formatInput(input) {
    const p = input as Record<string, unknown> | undefined;
    const target = typeof p?.["target"] === "string" ? (p["target"] as string) : null;
    const preset = typeof p?.["preset"] === "string" ? (p["preset"] as string) : null;
    if (target && preset) return `${target} · ${preset}`;
    return target ?? preset ?? null;
  },
  renderResult(result) {
    // Pipeline result is a multi-line summary — surface the first line as
    // the header result; the operator can scroll the scrollback for more.
    const firstLine = result.output.split("\n", 1)[0]?.trim();
    return firstLine && firstLine.length > 0 ? firstLine : null;
  },
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
    category: "defense",
    version: "0.17.2",
    description:
      "Umbrella for the full SAST DAG (context → scanners → triage → verify → patch). " +
      "For single-capability runs, use the dedicated modules: semgrep, codeql, " +
      "agentic-sast, taint-iris, threat-hunt, triage, verify, patch, findings, context.",
    rank: "excellent",
    tools: [scanTool],

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

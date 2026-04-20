/**
 * Patch sub-module — real implementation.
 *
 * Delegates to `runPatchPipeline` (same function the CLI's `kuzushi patch`
 * sub-command and the patch-worker use). Generates a fix in a disposable
 * worktree, verifies it eliminates the vulnerability, and returns the diff.
 */

import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "../types.js";

type Params = Record<string, unknown>;

const patchFindingTool: ModuleTool = {
  name: "patch:finding",
  description:
    "Generate a security patch for a confirmed vulnerability. Creates a fix in a " +
    "disposable worktree, runs build + test to verify the fix eliminates the finding, " +
    "and returns the diff.",
  inputSchema: {
    type: "object",
    properties: {
      fingerprint: { type: "string", description: "Finding fingerprint to patch." },
      maxIterations: {
        type: "integer",
        default: 3,
        description: "Max build/test retry iterations before giving up.",
      },
      buildCmd: {
        type: "string",
        description: "Override build command (autodetected by default).",
      },
      testCmd: { type: "string", description: "Override test command (autodetected by default)." },
    },
    required: ["fingerprint"],
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    const p = (input ?? {}) as Params;
    if (!ctx.workspace) {
      return { ok: false, output: "patch:finding needs an active workspace." };
    }
    const fingerprint = typeof p["fingerprint"] === "string" ? (p["fingerprint"] as string) : "";
    if (!fingerprint) return { ok: false, output: "patch:finding requires a fingerprint." };

    const repoRoot = ctx.target ?? ctx.cwd;
    const repoName = repoRoot.split("/").pop() ?? "repo";
    const db = ctx.workspace.rawDb();
    const model = ctx.config.model;

    ctx.print?.status(`Generating patch for ${fingerprint}...`);

    try {
      const { runPatchPipeline } = await import("../../patch.js");
      const result = await runPatchPipeline(db, {
        fingerprint,
        repoRoot,
        repoName,
        model,
        runtime: ctx.runtime,
        maxIterations: typeof p["maxIterations"] === "number" ? (p["maxIterations"] as number) : 3,
        buildCommand: typeof p["buildCmd"] === "string" ? (p["buildCmd"] as string) : null,
        testCommand: typeof p["testCmd"] === "string" ? (p["testCmd"] as string) : null,
      });

      const status = result.patchResult.status;
      const sound = status === "SOUND";
      const lines: string[] = [
        `[${sound ? "+" : "!"}] patch:finding ${sound ? "SOUND" : status}`,
        `      fingerprint:   ${fingerprint}`,
        `      iterations:    ${result.patchResult.iterations}`,
        `      cost:          $${result.costUsd.toFixed(4)}`,
      ];
      if (sound && result.patchResult.diff) {
        lines.push("");
        lines.push("Diff:");
        lines.push(result.patchResult.diff);
      } else if (result.patchResult.validatorLog) {
        lines.push("");
        lines.push("Validator log:");
        lines.push(result.patchResult.validatorLog);
      }

      return {
        ok: sound,
        output: lines.join("\n"),
        data: {
          status,
          iterations: result.patchResult.iterations,
          patchRunId: result.patchResult.patchRunId,
          diff: result.patchResult.diff,
          costUsd: result.costUsd,
        },
        costUsd: result.costUsd,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { ok: false, output: `[-] patch:finding failed: ${msg}` };
    }
  },
};

export function createPatchModule(): CopilotModule {
  return {
    id: "patch",
    displayName: "Auto Patch",
    category: "defense",
    version: "0.17.2",
    description:
      "Generate + verify security fixes for confirmed findings in a disposable worktree.",
    rank: "normal",
    references: [],
    notes: {
      stability: ["stable"],
      reliability: ["variable-recall"],
      sideEffects: ["writes worktrees", "costs LLM tokens"],
    },
    requires: [{ kind: "findings", minCount: 1 }],
    examples: ["# Patch a confirmed finding\nuse patch\nset FINGERPRINT fp_a3b2c1\nrun"],
    tools: [patchFindingTool],
  };
}

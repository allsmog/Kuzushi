/**
 * Patch sub-module — security-fix generation for confirmed vulnerabilities.
 * Currently a stub; Phase 3 will add PATCH_PROMPT + real wiring.
 */

import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "../types.js";

const patchFindingTool: ModuleTool = {
  name: "patch:finding",
  description:
    "Generate a security patch for a confirmed vulnerability. Creates a fix in a " +
    "disposable worktree, verifies the fix eliminates the vulnerability, and returns the diff.",
  inputSchema: {
    type: "object",
    properties: {
      fingerprint: { type: "string", description: "Finding fingerprint to patch." },
    },
    required: ["fingerprint"],
  },
  headless: true,
  async execute(input: unknown, _ctx: ToolExecutionContext): Promise<ToolResult> {
    const p = input as Record<string, unknown>;
    return {
      ok: true,
      output: `[patch:finding] Patch for "${p.fingerprint}" — implementation pending (Phase 2).`,
      data: { fingerprint: p.fingerprint, status: "pending" },
    };
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
    tools: [patchFindingTool],
  };
}

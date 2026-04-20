/**
 * Triage sub-module — AI triage of findings produced by upstream scanners.
 *
 * Currently a stub (matches the pre-split behavior in core-sast.ts). Phase 3
 * will add a TRIAGE_PROMPT advanced option and wire through task config.
 */

import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "../types.js";

const triageRunTool: ModuleTool = {
  name: "triage:run",
  description:
    "Run AI triage on one or more findings. Reads the code, traces dataflow, and " +
    "classifies each finding with a verdict (tp/fp/needs_review/by_design), confidence, " +
    "rationale, and verification steps.",
  inputSchema: {
    type: "object",
    properties: {
      fingerprint: { type: "string", description: "Finding fingerprint to triage." },
      fingerprints: {
        type: "array",
        items: { type: "string" },
        description: "Multiple finding fingerprints to triage.",
      },
      TRIAGE_PROMPT: {
        type: "string",
        description:
          "Override the triage system prompt. Accepts inline text or a path to a .md/.txt file. " +
          "Common use: `set TRIAGE_PROMPT ./prompts/acme-triage.md` then `run`.",
      },
    },
  },
  headless: true,
  async execute(input: unknown, _ctx: ToolExecutionContext): Promise<ToolResult> {
    const p = input as Record<string, unknown>;
    return {
      ok: true,
      output: `[triage:run] Triage for finding(s) — implementation pending (Phase 2).`,
      data: { fingerprint: p.fingerprint, status: "pending" },
    };
  },
};

export function createTriageModule(): CopilotModule {
  return {
    id: "triage",
    displayName: "AI Triage",
    category: "defense",
    version: "0.17.2",
    description: "LLM-driven triage of scanner findings with evidence-backed verdicts.",
    rank: "good",
    references: [{ type: "CWE", value: "general" }],
    notes: {
      stability: ["stable"],
      reliability: ["reliable"],
      sideEffects: ["costs LLM tokens"],
    },
    requires: [{ kind: "findings", minCount: 1 }],
    tools: [triageRunTool],
  };
}

/**
 * Findings sub-module — query the workspace findings database.
 * Currently a stub (matches pre-split core-sast.ts).
 */

import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "../types.js";

const findingsListTool: ModuleTool = {
  name: "findings:list",
  description:
    "Query findings from the workspace DB. Filter by severity, verdict, scanner, " +
    "CWE, file path, or fingerprint. Returns structured finding data with triage results.",
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
      path: { type: "string", description: "Filter by file path (prefix match)." },
      limit: { type: "number", default: 50, description: "Max number of findings to return." },
    },
  },
  headless: true,
  async execute(_input: unknown, _ctx: ToolExecutionContext): Promise<ToolResult> {
    return {
      ok: true,
      output: "[findings:list] Query findings — implementation pending (Phase 2).",
      data: { status: "pending" },
    };
  },
};

export function createFindingsModule(): CopilotModule {
  return {
    id: "findings",
    displayName: "Findings",
    category: "governance",
    version: "0.17.2",
    description: "Read + filter previously stored findings from the workspace DB.",
    rank: "great",
    references: [],
    notes: { stability: ["stable"], reliability: ["reliable"], sideEffects: [] },
    tools: [findingsListTool],
  };
}

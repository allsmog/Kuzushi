/**
 * Semgrep sub-module — thin wrapper around the "semgrep" pipeline task.
 */

import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "../types.js";
import { runSingleTaskPipeline, severityProperty, targetProperty } from "./shared.js";

const semgrepScanTool: ModuleTool = {
  name: "semgrep:scan",
  description: "Run Semgrep only, with scan-only post-processing and report generation.",
  inputSchema: {
    type: "object",
    properties: { target: targetProperty, severity: severityProperty },
    required: ["target"],
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    return runSingleTaskPipeline(["semgrep"], input, ctx, { summaryLabel: "Semgrep" });
  },
};

export function createSemgrepModule(): CopilotModule {
  return {
    id: "semgrep",
    displayName: "Semgrep",
    category: "defense",
    version: "0.17.2",
    description: "Static-pattern rule scanner backed by Semgrep (p/security-audit by default).",
    rank: "great",
    references: [
      { type: "URL", value: "https://semgrep.dev" },
      { type: "OWASP", value: "SAST" },
    ],
    notes: { stability: ["stable"], reliability: ["fast"], sideEffects: [] },
    tools: [semgrepScanTool],
  };
}

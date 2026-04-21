/**
 * Semgrep sub-module — thin wrapper around the "semgrep" pipeline task.
 */

import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "../types.js";
import { runSingleTaskPipeline, severityProperty, targetProperty } from "./shared.js";

const semgrepScanTool: ModuleTool = {
  name: "semgrep:scan",
  displayName: "Semgrep",
  formatInput(input) {
    const p = input as Record<string, unknown> | undefined;
    return typeof p?.["target"] === "string" ? (p["target"] as string) : null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
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

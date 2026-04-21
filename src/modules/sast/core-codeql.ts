/**
 * CodeQL sub-module — thin wrapper around the "codeql" pipeline task.
 */

import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "../types.js";
import { runSingleTaskPipeline, severityProperty, targetProperty } from "./shared.js";

const codeqlScanTool: ModuleTool = {
  name: "codeql:scan",
  displayName: "CodeQL",
  formatInput(input) {
    const p = input as Record<string, unknown> | undefined;
    return typeof p?.["target"] === "string" ? (p["target"] as string) : null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  description: "Run CodeQL only, with scan-only post-processing and report generation.",
  inputSchema: {
    type: "object",
    properties: { target: targetProperty, severity: severityProperty },
    required: ["target"],
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    return runSingleTaskPipeline(["codeql"], input, ctx, { summaryLabel: "CodeQL" });
  },
};

export function createCodeqlModule(): CopilotModule {
  return {
    id: "codeql",
    displayName: "CodeQL",
    category: "defense",
    version: "0.17.2",
    description: "GitHub's taint-query semantic analyzer. Deeper than pattern scanners; slower.",
    rank: "excellent",
    references: [
      { type: "URL", value: "https://codeql.github.com" },
      { type: "OWASP", value: "SAST" },
    ],
    notes: { stability: ["stable"], reliability: ["reliable"], sideEffects: [] },
    tools: [codeqlScanTool],
  };
}

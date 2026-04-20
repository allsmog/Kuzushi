/**
 * Agentic-SAST sub-module — LLM-driven bug-hunting detectors (SSRF, SQLi, XSS,
 * command injection, deserialization, auth-logic, etc.). Depends on the
 * context module's appModel to know what sinks + routes to probe.
 */

import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "../types.js";
import { runSingleTaskPipeline, severityProperty, targetProperty } from "./shared.js";

const agenticScanTool: ModuleTool = {
  name: "agentic-sast:scan",
  description:
    "Run the agentic detector set (SSRF, SQLi, XSS, command injection, deserialization, " +
    "auth-logic, etc.), with scan-only post-processing.",
  inputSchema: {
    type: "object",
    properties: {
      target: targetProperty,
      severity: severityProperty,
      AGENTIC_SAST_PROMPT: {
        type: "string",
        description:
          "Override the agentic-sast detector prompt. Accepts inline text or a path to .md/.txt.",
      },
    },
    required: ["target"],
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    return runSingleTaskPipeline(["agentic"], input, ctx, { summaryLabel: "Agentic" });
  },
};

export function createAgenticSastModule(): CopilotModule {
  return {
    id: "agentic-sast",
    displayName: "Agentic SAST",
    category: "defense",
    version: "0.17.2",
    description:
      "LLM-driven detectors that reason about data flow and intent rather than pattern-match.",
    rank: "good",
    references: [{ type: "OWASP", value: "Top 10" }],
    notes: {
      stability: ["stable"],
      reliability: ["reliable"],
      sideEffects: ["costs LLM tokens"],
    },
    requires: [{ kind: "snapshot", moduleId: "context", field: "appModel" }],
    tools: [agenticScanTool],
  };
}

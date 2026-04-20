/**
 * Taint-IRIS sub-module — taint analysis driven by IRIS (dataflow via LLM).
 * Depends on context.appModel for route + sink inventory.
 */

import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "../types.js";
import { resolvePromptValue } from "./prompts.js";
import { runSingleTaskPipeline, severityProperty, targetProperty } from "./shared.js";

const taintIrisHuntTool: ModuleTool = {
  name: "taint-iris:hunt",
  description: "Run IRIS taint analysis (taint-cwe-select then taint-iris), scan-only mode.",
  inputSchema: {
    type: "object",
    properties: {
      target: targetProperty,
      severity: severityProperty,
      TAINT_IRIS_PROMPT: {
        type: "string",
        description:
          "Override the taint-iris system prompt. Accepts inline text or a path to .md/.txt.",
      },
    },
    required: ["target"],
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    const p = input as Record<string, unknown>;
    const promptOverride = await resolvePromptValue(p["TAINT_IRIS_PROMPT"] as string, ctx.cwd);
    const taskConfig: Record<string, Record<string, unknown>> = {};
    if (promptOverride) taskConfig["taint-iris"] = { promptOverride };
    return runSingleTaskPipeline(["taint-cwe-select", "taint-iris"], input, ctx, {
      summaryLabel: "Taint IRIS",
      ...(Object.keys(taskConfig).length > 0 ? { taskConfig } : {}),
    });
  },
};

export function createTaintIrisModule(): CopilotModule {
  return {
    id: "taint-iris",
    displayName: "Taint IRIS",
    category: "defense",
    version: "0.17.2",
    description: "LLM-driven taint analysis selecting relevant CWEs then tracing source→sink.",
    rank: "good",
    references: [{ type: "CWE", value: "general" }],
    notes: { stability: ["stable"], reliability: ["variable-recall"], sideEffects: [] },
    requires: [{ kind: "snapshot", moduleId: "context", field: "appModel" }],
    tools: [taintIrisHuntTool],
  };
}

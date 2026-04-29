/**
 * Taint IRIS module — LLM-driven CodeQL taint analysis wrapped as a CopilotModule.
 *
 * The `taint-iris:hunt` DagTool advertises the shell-facing tool shape and
 * declares the DAG dependency on `pipeline:taint-cwe-select`. Shell-mode `execute()`
 * (installed by the module registry) re-enters the scan pipeline
 * with `chainBefore: ["taint-cwe-select"]` so the cwe-selection runs first
 * and its output populates `ctx.dag.upstreamOutputs` for the IRIS task.
 *
 * The scanner body lives in `src/agents/tasks/taint-iris/iris.ts`; this
 * DagTool invokes it through the native `ExecutionContext.dag` contract.
 */

import { taintIrisTask } from "../../agents/tasks/taint-iris/iris.js";
import type { Finding } from "../../scanners/types.js";
import type { ScanOpts } from "../../types.js";
import { defineDagTool, defineModule } from "../define.js";
import { buildDagRunContextFromExecutionContext } from "../hidden-dag-node.js";
import { severityProperty, targetProperty } from "../sast/schema-fragments.js";
import type { CopilotModule, ExecutionContext } from "../types.js";

export function createTaintIrisModule(): CopilotModule {
  const taintIrisHunt = defineDagTool<"taint-iris", ScanOpts, Finding[]>({
    name: "taint-iris:hunt",
    displayName: "Taint IRIS",
    description: "Run IRIS taint analysis (taint-cwe-select then taint-iris), scan-only mode.",
    headless: true,
    runLifecycle: {
      persistence: "pipeline-checkpoint",
      resume: "checkpoint",
      liveControl: "pause-resume",
      pipelineTasks: ["taint-iris:hunt"],
    },
    formatInput(input) {
      const p = input as Record<string, unknown> | undefined;
      return typeof p?.["target"] === "string" ? (p["target"] as string) : null;
    },
    renderResult(result) {
      const first = result.output.split("\n", 1)[0]?.trim();
      return first && first.length > 0 ? first : null;
    },
    inputSchema: {
      type: "object",
      properties: {
        target: targetProperty,
        severity: severityProperty,
        TAINT_IRIS_PROMPT: {
          type: "string",
          description:
            "Override the taint-iris system prompt. Accepts inline text or a path to .md/.txt.",
          "x-advanced": true,
        },
        resume: {
          type: ["boolean", "string"],
          description: "Resume the latest checkpoint or a specific run id.",
        },
      },
      required: ["target"],
    },
    dag: {
      outputKind: "findings",
      dependsOn: ["pipeline:taint-cwe-select"],
      // Shell-mode dispatches need both tasks pinned — pinned mode disables
      // dependency auto-resolution. Full-DAG scan mode ignores this field.
      chainBefore: ["pipeline:taint-cwe-select"],
    },
    async run(input: ScanOpts, ctx: ExecutionContext): Promise<Finding[]> {
      return taintIrisTask.run(input, buildDagRunContextFromExecutionContext(ctx));
    },
  });

  return defineModule({
    id: "taint-iris",
    displayName: "Taint IRIS",
    category: "defense",
    version: "0.17.2",
    description: "LLM-driven taint analysis selecting relevant CWEs then tracing source→sink.",
    rank: "good",
    references: [{ type: "CWE", value: "general" }],
    notes: { stability: ["stable"], reliability: ["variable-recall"], sideEffects: [] },
    requires: [{ kind: "snapshot", moduleId: "context", field: "appModel" }],
    tools: [taintIrisHunt],
  });
}

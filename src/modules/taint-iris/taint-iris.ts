/**
 * Taint IRIS module — LLM-driven CodeQL taint analysis wrapped as a CopilotModule.
 *
 * The `taint-iris:hunt` DagTool advertises the shell-facing tool shape and
 * declares the DAG dependency on `taint-cwe-select`. Shell-mode `execute()`
 * (installed by the module-registry bridge) re-enters the scan pipeline
 * with `chainBefore: ["taint-cwe-select"]` so the cwe-selection runs first
 * and its output populates `ctx.dag.upstreamOutputs` for the IRIS task.
 *
 * The actual DAG-node body still lives at
 * `src/agents/tasks/taint-iris/iris.ts` (registered in
 * `src/agents/index.ts`). The module bridge at
 * `src/modules/dag-bridge.ts:registerDagToolsInTaskRegistry` detects the
 * pre-existing registration and skips re-registering under the same id,
 * so both the module-forward authoring surface and the legacy task wiring
 * coexist without conflict. A future sweep (Step 4) can merge the task body
 * into `run()` once every caller of `taintIrisTask` is gone.
 */

import type { Finding } from "../../scanners/types.js";
import type { ScanOpts } from "../../types.js";
import { defineDagTool, defineModule } from "../define.js";
import { severityProperty, targetProperty } from "../sast/shared.js";
import type { CopilotModule, ExecutionContext } from "../types.js";

export function createTaintIrisModule(): CopilotModule {
  const taintIrisHunt = defineDagTool<"taint-iris", ScanOpts, Finding[]>({
    name: "taint-iris:hunt",
    displayName: "Taint IRIS",
    description: "Run IRIS taint analysis (taint-cwe-select then taint-iris), scan-only mode.",
    headless: true,
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
      },
      required: ["target"],
    },
    dag: {
      outputKind: "findings",
      dependsOn: ["taint-cwe-select"],
      // Shell-mode dispatches need both tasks pinned — pinned mode disables
      // dependency auto-resolution. Full-DAG scan mode ignores this field.
      chainBefore: ["taint-cwe-select"],
    },
    async run(_input: ScanOpts, _ctx: ExecutionContext): Promise<Finding[]> {
      // Delegate to the legacy AgentTask registration; the module-registry
      // bridge detects that "taint-iris" is already registered (from
      // src/agents/index.ts) and leaves the existing task intact. This
      // method is structurally present so defineDagTool is happy but is
      // not invoked by the orchestrator during normal scans.
      const { taintIrisTask } = await import("../../agents/tasks/taint-iris/iris.js");
      // Shouldn't be reached via the orchestrator — the AgentTask wins. If
      // a future call site invokes DagTool.run() directly, surface the
      // mis-use loudly rather than silently running a half-initialised
      // TaskContext→ExecutionContext conversion.
      throw new Error(
        `DagTool "${taintIrisTask.id}:run" body is not meant to be invoked directly — ` +
          "the orchestrator runs the legacy AgentTask registered in src/agents/index.ts.",
      );
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

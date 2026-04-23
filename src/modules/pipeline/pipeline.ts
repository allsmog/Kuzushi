/**
 * Pipeline module — orchestrator-level infrastructure DAG nodes.
 *
 * Hosts tasks that are part of the scan DAG but aren't user-facing detectors:
 * the dynamic task-selector, approval gates, and future policy hooks. Everything
 * here is `hidden: true` — operators never `/use pipeline; run`. The purpose is
 * to keep `createDefaultTaskRegistry` thin and ensure every DAG node is owned
 * by some `CopilotModule`.
 */

import { approvalBeforeVerification } from "../../agents/tasks/approval-gate.js";
import { taintCweSelectTask } from "../../agents/tasks/taint-iris/cwe-select.js";
import { taintIrisTask } from "../../agents/tasks/taint-iris/iris.js";
import { taskSelectorTask } from "../../agents/tasks/task-selector.js";
import { exposeAgentTaskAsHiddenDagTool } from "../dag-bridge.js";
import { defineModule } from "../define.js";
import type { CopilotModule } from "../types.js";

export function createPipelineModule(): CopilotModule {
  const hide = (task: Parameters<typeof exposeAgentTaskAsHiddenDagTool<"pipeline">>[0]) =>
    exposeAgentTaskAsHiddenDagTool<"pipeline">(task, { moduleId: "pipeline" });

  return defineModule({
    id: "pipeline",
    displayName: "Scan Pipeline",
    category: "defense",
    version: "0.17.2",
    description:
      "Orchestrator-level DAG nodes: dynamic task selection, approval gates, taint pipeline " +
      "sub-tasks. Not user-facing — loaded so every DAG participant has a module home.",
    rank: "excellent",
    hidden: true,
    notes: {
      stability: ["stable"],
      reliability: ["reliable"],
      sideEffects: [],
    },
    tools: [
      hide(taskSelectorTask),
      hide(approvalBeforeVerification),
      // Taint-iris chain: taint-cwe-select feeds taint-iris. The `taint-iris`
      // module already exposes a visible `taint-iris:hunt` DagTool; these are
      // the DAG participants that resolve under bare ids for `dependsOn`
      // chains inside the orchestrator.
      hide(taintCweSelectTask),
      hide(taintIrisTask),
    ],
  });
}

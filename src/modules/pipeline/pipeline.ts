/**
 * Pipeline module — orchestrator-level infrastructure DAG nodes.
 *
 * Hosts tasks that are part of the scan DAG but aren't user-facing detectors:
 * the dynamic task-selector, approval gates, and future policy hooks. Everything
 * here is `hidden: true` — operators never `/use pipeline; run`. The purpose is
 * to keep `createDefaultDagRegistry` thin and ensure every DAG node is owned
 * by some `CopilotModule`.
 */

import { approvalBeforeVerification } from "../../agents/tasks/approval-gate.js";
import { taintCweSelectTask } from "../../agents/tasks/taint-iris/cwe-select.js";
import { taskSelectorTask } from "../../agents/tasks/task-selector.js";
import { defineModule } from "../define.js";
import { defineHiddenDagNodeTool } from "../hidden-dag-node.js";
import type { CopilotModule } from "../types.js";

export function createPipelineModule(): CopilotModule {
  const hide = (task: Parameters<typeof defineHiddenDagNodeTool<"pipeline">>[0]) =>
    defineHiddenDagNodeTool<"pipeline">(task, { moduleId: "pipeline" });

  return defineModule({
    id: "pipeline",
    displayName: "Scan Pipeline",
    category: "defense",
    version: "0.17.2",
    description:
      "Orchestrator-level DAG nodes: dynamic task selection, approval gates, taint pipeline sub-tasks.",
    longDescription: "Not user-facing — loaded so every DAG participant has a module home.",
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
      // Taint-iris chain: this selector feeds the visible `taint-iris:hunt`
      // DagTool owned by the taint-iris module.
      hide(taintCweSelectTask),
    ],
  });
}

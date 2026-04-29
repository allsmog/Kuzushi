/**
 * Systems-hunt module — low-level memory-safety and protocol-bug finder.
 *
 * Hidden DagTool wrappers expose the four-stage systems-hunt chain
 * (systems-context-gatherer → systems-invariant-extract → systems-trigger-
 * synth → systems-hunt) plus the backward-compatible deep-semantic tasks
 * (deep-semantic-cwe-select, deep-semantic-hunt) via the module registry
 * so operators don't have to reach into `createDefaultDagRegistry` to
 * discover what participates in the scan DAG.
 *
 * Operators invoke the chain through the scan CLI (`kuzushi scan ...
 * --tasks systems-hunt`) or via `dependsOn: ["systems-hunt"]`. No
 * shell-facing `systems-hunt:run` verb exists yet — when one lands, swap
 * the hidden wrapper for a visible DagTool and wire `chainBefore:
 * ["systems-context-gatherer", "systems-invariant-extract", "systems-
 * trigger-synth"]` so shell dispatch runs the full chain.
 */

import { deepSemanticCweSelectTask } from "../../agents/tasks/deep-semantic/cwe-select.js";
import { deepSemanticHuntTask } from "../../agents/tasks/deep-semantic/hunt.js";
import { systemsContextGathererTask } from "../../agents/tasks/systems-hunt/context.js";
import { systemsHuntTask } from "../../agents/tasks/systems-hunt/hunt.js";
import { systemsInvariantExtractTask } from "../../agents/tasks/systems-hunt/invariant-extract.js";
import { systemsTriggerSynthTask } from "../../agents/tasks/systems-hunt/trigger-synth.js";
import { defineModule } from "../define.js";
import { defineHiddenDagNodeTool } from "../hidden-dag-node.js";
import type { CopilotModule } from "../types.js";

export function createSystemsHuntModule(): CopilotModule {
  const hide = (
    task: Parameters<typeof defineHiddenDagNodeTool<"systems-hunt">>[0],
    multiStrategy = false,
  ) =>
    defineHiddenDagNodeTool<"systems-hunt">(task, {
      moduleId: "systems-hunt",
      multiStrategy,
    });

  return defineModule({
    id: "systems-hunt",
    displayName: "Systems Hunt",
    category: "defense",
    version: "0.17.2",
    description:
      "LLM-driven hunt for memory-safety and low-level protocol bugs in systems code (C, " +
      "C++, Rust, Go). Four-stage chain: context gather → invariant extract → trigger synth → " +
      "hunt. Deep-semantic tasks preserved for backward compatibility.",
    rank: "good",
    notes: {
      stability: ["stable"],
      reliability: ["variable-recall"],
      sideEffects: ["costs LLM tokens"],
    },
    requires: [{ kind: "snapshot", moduleId: "context", field: "appModel" }],
    tools: [
      hide(systemsContextGathererTask),
      hide(systemsInvariantExtractTask),
      hide(systemsTriggerSynthTask),
      hide(systemsHuntTask),
      // Backward-compatibility: deep-semantic-hunt uses multi-strategy
      hide(deepSemanticCweSelectTask),
      hide(deepSemanticHuntTask, true),
    ],
  });
}

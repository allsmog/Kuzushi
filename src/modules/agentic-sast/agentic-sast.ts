/**
 * Agentic SAST module — LLM-driven bug hunter wrapped as a CopilotModule.
 *
 * Primary tool: `agentic-sast:scan` — delegates to `AgenticPlugin.scan`; the
 * module registry installs a shell-mode `execute()` that re-enters the scan
 * pipeline with `--tasks agentic`.
 *
 * Hidden detector tools: every LLM-driven detector (SSRF, NoSQL injection,
 * command injection, template injection, deserialization, XXE, prototype
 * pollution, GraphQL, secrets/crypto, race-condition, auth-logic, sharp-
 * edges, supply-chain, reachability-check, diff-review, crypto-behavioral)
 * is exposed here as a hidden DagTool via `defineHiddenDagNodeTool`.
 * Operators never invoke them directly — they participate in the scan DAG
 * as `dependsOn: ["ssrf-detect"]` targets — but declaring them on the
 * module puts all 16 detectors in one authoring surface and means the
 * module registry, not `createDefaultDagRegistry`, owns their lifecycle.
 *
 * Tasks flagged `multiStrategy: true` get wrapped with `withMultiStrategy`
 * at registration time (via the hidden DAG node helper), matching the
 * legacy `wrapTask(…)` behaviour from the old registry bootstrapping.
 *
 * Prompt overrides are intentionally not exposed here until the scanner
 * consumes them directly; hiding unwired knobs keeps the operator surface
 * truthful.
 */

import { authLogicDetectTask } from "../../agents/tasks/auth-logic-detect.js";
import { commandInjectionTask } from "../../agents/tasks/command-injection.js";
import { cryptoBehavioralTestTask } from "../../agents/tasks/crypto-behavioral-test.js";
import { deserializationDetectionTask } from "../../agents/tasks/deserialization-detection.js";
import { diffReviewTask } from "../../agents/tasks/diff-review.js";
import { graphqlSecurityTask } from "../../agents/tasks/graphql-security.js";
import { nosqlInjectionTask } from "../../agents/tasks/nosql-injection.js";
import { prototypePollutionTask } from "../../agents/tasks/prototype-pollution.js";
import { raceConditionTask } from "../../agents/tasks/race-condition.js";
import { reachabilityCheckTask } from "../../agents/tasks/reachability-check.js";
import { secretsCryptoDetectTask } from "../../agents/tasks/secrets-crypto-detect.js";
import { sharpEdgesDetectTask } from "../../agents/tasks/sharp-edges-detect.js";
import { ssrfDetectionTask } from "../../agents/tasks/ssrf-detection.js";
import { supplyChainTask } from "../../agents/tasks/supply-chain.js";
import { templateInjectionTask } from "../../agents/tasks/template-injection.js";
import { xxeDetectionTask } from "../../agents/tasks/xxe-detection.js";
import { AgenticPlugin } from "../../scanners/agentic.js";
import { defineModule } from "../define.js";
import { defineHiddenDagNodeTool } from "../hidden-dag-node.js";
import { severityProperty, targetProperty } from "../sast/schema-fragments.js";
import { buildScannerDagTool } from "../scanner-adapter.js";
import type { CopilotModule } from "../types.js";

export function createAgenticSastModule(): CopilotModule {
  const agenticScan = buildScannerDagTool<"agentic-sast">(new AgenticPlugin(), {
    name: "agentic-sast:scan",
    displayName: "Agentic SAST",
    description:
      "Run the agentic detector set (SSRF, SQLi, XSS, command injection, deserialization, " +
      "auth-logic, etc.), with scan-only post-processing.",
    inputSchema: {
      type: "object",
      properties: {
        target: targetProperty,
        severity: severityProperty,
      },
      required: ["target"],
    },
  });

  const hide = <Id extends "agentic-sast">(
    task: Parameters<typeof defineHiddenDagNodeTool<Id>>[0],
    multiStrategy = true,
  ) =>
    defineHiddenDagNodeTool<Id>(task, {
      moduleId: "agentic-sast" as Id,
      multiStrategy,
    });

  const hiddenDetectors = [
    // Multi-strategy-wrapped detectors (eligible for parallel CWE strategies)
    hide(ssrfDetectionTask),
    hide(nosqlInjectionTask),
    hide(commandInjectionTask),
    hide(templateInjectionTask),
    hide(deserializationDetectionTask),
    hide(xxeDetectionTask),
    hide(prototypePollutionTask),
    hide(graphqlSecurityTask),
    hide(secretsCryptoDetectTask),
    hide(raceConditionTask),
    hide(sharpEdgesDetectTask),
    hide(supplyChainTask),
    // Detectors without multi-strategy profiles (run single-strategy)
    hide(cryptoBehavioralTestTask, false),
    hide(authLogicDetectTask, false),
    hide(reachabilityCheckTask, false),
    hide(diffReviewTask, false),
  ];

  return defineModule({
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
    tools: [agenticScan, ...hiddenDetectors],
  });
}

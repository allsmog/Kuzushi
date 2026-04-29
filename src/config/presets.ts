import type { KuzushiConfig } from "../types.js";

export type ScanPreset = "safe" | "fast" | "standard" | "deep" | "reference";

export const SCAN_PRESETS: Record<ScanPreset, Partial<KuzushiConfig>> = {
  // Recommended for first-time users: tight cost and turn caps, no expensive optional tasks.
  safe: {
    tasks: [
      "context:context-gatherer",
      "context:context-enricher",
      "agentic-sast:secrets-crypto-detect",
      "context:code-config-detect",
    ],
    enableDynamicTaskSelection: false,
    triageMaxFindings: 20,
    triageSpecialistMaxTurns: 5,
    costBudgetUsd: 5,
    dynamicAnalysisEnabled: false,
    cryptoBehavioralTestEnabled: false,
  },
  fast: {
    tasks: ["semgrep:scan"],
    enableDynamicTaskSelection: false,
    enableContextGathering: false,
    enableContextEnrichment: false,
    variantAnalysis: false,
  },
  standard: {
    tasks: [
      "context:context-gatherer",
      "context:context-enricher",
      "agentic-sast:secrets-crypto-detect",
      "context:code-config-detect",
      "pipeline:taint-cwe-select",
      "taint-iris:hunt",
    ],
    enableDynamicTaskSelection: false,
  },
  deep: {
    tasks: [
      "context:context-gatherer",
      "context:context-enricher",
      "agentic-sast:secrets-crypto-detect",
      "context:code-config-detect",
      "pipeline:taint-cwe-select",
      "taint-iris:hunt",
      "threat-model:threat-model-randori",
      "carlini-threat-hunt:run",
      "systems-hunt:systems-context-gatherer",
      "systems-hunt:systems-invariant-extract",
      "systems-hunt:systems-trigger-synth",
      "systems-hunt:systems-hunt",
    ],
    verify: true,
    variantAnalysis: true,
    taskConfig: {
      "carlini-threat-hunt": { maxActors: 8, runsPerActor: 2 },
    },
  },
  reference: {
    // Inherits the user's configured task list — does not override it.
    // Orchid is used surgically for systems-hunt only (see taskConfig below).
    verify: true,
    pocHarness: true,
    codeGraphEnabled: true,
    enableDynamicTaskSelection: true,
    variantAnalysis: true,
    taskConfig: {
      "carlini-threat-hunt": {
        runsPerActor: 3,
        maxActors: 10,
        maxConcurrentHunts: 3,
      },
      "systems-hunt": {
        model: "anthropic:claude-orchid-preview",
        maxConcurrentSurfaces: 3,
        maxSurfaces: 12,
        surfacePackDepth: 6,
        maxTriggerHypothesesPerSurface: 4,
      },
    },
  },
};

export function isValidPreset(value: string): value is ScanPreset {
  return (
    value === "safe" ||
    value === "fast" ||
    value === "standard" ||
    value === "deep" ||
    value === "reference"
  );
}

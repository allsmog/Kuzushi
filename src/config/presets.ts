import type { KuzushiConfig } from "../types.js";

export type ScanPreset = "safe" | "fast" | "standard" | "deep" | "reference";

export const SCAN_PRESETS: Record<ScanPreset, Partial<KuzushiConfig>> = {
  // Recommended for first-time users: tight cost and turn caps, no expensive optional tasks.
  safe: {
    tasks: ["context-gatherer", "context-enricher", "secrets-crypto-detect", "code-config-detect"],
    enableDynamicTaskSelection: false,
    triageMaxFindings: 20,
    triageSpecialistMaxTurns: 5,
    costBudgetUsd: 5,
    dynamicAnalysisEnabled: false,
    cryptoBehavioralTestEnabled: false,
  },
  fast: {
    tasks: ["semgrep"],
    enableDynamicTaskSelection: false,
    enableContextGathering: false,
    enableContextEnrichment: false,
    variantAnalysis: false,
  },
  standard: {
    tasks: [
      "context-gatherer",
      "context-enricher",
      "secrets-crypto-detect",
      "code-config-detect",
      "taint-cwe-select",
      "taint-iris",
    ],
    enableDynamicTaskSelection: false,
  },
  deep: {
    tasks: [
      "context-gatherer",
      "context-enricher",
      "secrets-crypto-detect",
      "code-config-detect",
      "taint-cwe-select",
      "taint-iris",
      "threat-model-randori",
      "threat-hunt",
      "systems-context-gatherer",
      "systems-invariant-extract",
      "systems-trigger-synth",
      "systems-hunt",
    ],
    verify: true,
    variantAnalysis: true,
    taskConfig: {
      "threat-hunt": { maxActors: 8, runsPerActor: 2 },
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
      "threat-hunt": {
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

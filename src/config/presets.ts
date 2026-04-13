import type { KuzushiConfig } from "../types.js";

export type ScanPreset = "safe" | "fast" | "standard" | "deep" | "reference";

export const SCAN_PRESETS: Record<ScanPreset, Partial<KuzushiConfig>> = {
  // Recommended for first-time users: tight cost and turn caps, no expensive optional tasks.
  safe: {
    taskMode: "explicit",
    enabledTasks: [
      "context-gatherer",
      "context-enricher",
      "secrets-crypto-detect",
      "code-config-detect",
    ],
    enableDynamicTaskSelection: false,
    triageMaxFindings: 20,
    triageSpecialistMaxTurns: 5,
    costBudgetUsd: 5,
    dynamicAnalysisEnabled: false,
    cryptoBehavioralTestEnabled: false,
  },
  fast: {
    taskMode: "scanners-only",
    enabledTasks: [],
    enableDynamicTaskSelection: false,
    enableContextGathering: false,
    enableContextEnrichment: false,
    variantAnalysis: false,
  },
  standard: {
    taskMode: "explicit",
    enabledTasks: [
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
    taskMode: "explicit",
    enabledTasks: [
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
      "systems-hunt",
    ],
    verify: true,
    variantAnalysis: true,
    scannerConfig: {
      "threat-hunt": { maxActors: 8, runsPerActor: 2 },
    },
  },
  reference: {
    // Inherits the user's configured model and scanners — does not override.
    // Orchid is used surgically for systems-hunt only (see scannerConfig below).
    taskMode: "compat",
    verify: true,
    pocHarness: true,
    codeGraphEnabled: true,
    enableDynamicTaskSelection: true,
    variantAnalysis: true,
    scannerConfig: {
      "threat-hunt": {
        runsPerActor: 3,
        maxActors: 10,
        maxConcurrentHunts: 3,
      },
      "systems-hunt": {
        model: "anthropic:claude-orchid-preview",
        maxConcurrentSurfaces: 3,
        maxSurfaces: 12,
      },
    },
  },
};

export function isValidPreset(value: string): value is ScanPreset {
  return value === "safe" || value === "fast" || value === "standard" || value === "deep" || value === "reference";
}

import type { KuzushiConfig } from "../types.js";

export type ScanPreset = "fast" | "standard" | "deep" | "reference";

export const SCAN_PRESETS: Record<ScanPreset, Partial<KuzushiConfig>> = {
  fast: {
    enabledTasks: [],
    enableDynamicTaskSelection: false,
    enableContextGathering: false,
    enableContextEnrichment: false,
    variantAnalysis: false,
  },
  standard: {
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
    verify: true,
  },
  reference: {
    // Inherits the user's configured model and scanners — does not override.
    // Orchid is used surgically for threat-hunt only (see scannerConfig below).
    verify: true,
    pocHarness: true,
    codeGraphEnabled: true,
    enableDynamicTaskSelection: true,
    variantAnalysis: true,
    scannerConfig: {
      "threat-hunt": {
        model: "anthropic:claude-orchid-preview",
        runsPerActor: 3,
        maxConcurrentHunts: 3,
      },
    },
  },
};

export function isValidPreset(value: string): value is ScanPreset {
  return value === "fast" || value === "standard" || value === "deep" || value === "reference";
}

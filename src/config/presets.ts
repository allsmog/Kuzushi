import type { KuzushiConfig } from "../types.js";

export type ScanPreset = "fast" | "standard" | "deep";

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
};

export function isValidPreset(value: string): value is ScanPreset {
  return value === "fast" || value === "standard" || value === "deep";
}

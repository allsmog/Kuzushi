import type { ScannerConfig } from "./scanners/types.js";
import type { KuzushiConfig } from "./types.js";
import { isRecord } from "./utils.js";

export const TAINT_ANALYSIS_TASK_IDS = [
  "taint-analysis-preflight",
  "taint-analysis-label",
  "taint-analysis-run",
] as const;

export const TAINT_ANALYSIS_CROSS_SERVICE_TASK_IDS = [
  "taint-analysis-discover",
  "taint-analysis-cross-analyze",
  "taint-analysis-stitch",
] as const;

export interface CapabilityDefinition {
  publicId: string;
  configKey?: string;
  pluginId?: string;
  taskIds?: readonly string[];
  aliases?: readonly string[];
  scannerSelectable?: boolean;
}

const CAPABILITIES: CapabilityDefinition[] = [
  { publicId: "semgrep", configKey: "semgrep", pluginId: "semgrep", scannerSelectable: true },
  { publicId: "agentic", configKey: "agentic", pluginId: "agentic", scannerSelectable: true },
  { publicId: "codeql", configKey: "codeql", pluginId: "codeql", scannerSelectable: true },
  {
    publicId: "taint-analysis",
    configKey: "taint-analysis",
    taskIds: TAINT_ANALYSIS_TASK_IDS,
    aliases: TAINT_ANALYSIS_CROSS_SERVICE_TASK_IDS,
    scannerSelectable: true,
  },
  {
    publicId: "secrets",
    configKey: "secrets-crypto-detect",
    taskIds: ["secrets-crypto-detect"],
    aliases: ["secrets-detection", "secrets-detect", "secrets-crypto-detect"],
    scannerSelectable: true,
  },
  {
    publicId: "crypto-misuse",
    configKey: "secrets-crypto-detect",
    taskIds: ["secrets-crypto-detect"],
    aliases: ["crypto-misuse-detect", "secrets-crypto-detect"],
    scannerSelectable: true,
  },
  {
    publicId: "auth-access",
    configKey: "code-config-detect",
    taskIds: ["code-config-detect"],
    aliases: ["auth-access-detect", "code-config-detect"],
    scannerSelectable: true,
  },
  {
    publicId: "race-condition",
    configKey: "race-condition",
    taskIds: ["race-condition-detect"],
    aliases: ["race-condition-detect"],
    scannerSelectable: true,
  },
  {
    publicId: "dangerous-api",
    configKey: "code-config-detect",
    taskIds: ["code-config-detect"],
    aliases: ["dangerous-api-detect", "code-config-detect"],
    scannerSelectable: true,
  },
  {
    publicId: "diff-review",
    configKey: "diff-review",
    taskIds: ["diff-review"],
    scannerSelectable: true,
  },
  {
    publicId: "security-misconfig",
    configKey: "code-config-detect",
    taskIds: ["code-config-detect"],
    aliases: ["security-misconfig-detect", "code-config-detect"],
    scannerSelectable: true,
  },
  {
    publicId: "ssrf",
    configKey: "ssrf-detect",
    taskIds: ["ssrf-detect"],
    aliases: ["ssrf-detect", "ssrf-detection"],
    scannerSelectable: true,
  },
  {
    publicId: "prototype-pollution",
    configKey: "prototype-pollution",
    taskIds: ["prototype-pollution-detect"],
    aliases: ["prototype-pollution-detect"],
    scannerSelectable: true,
  },
  {
    publicId: "nosql-injection",
    configKey: "nosql-injection",
    taskIds: ["nosql-injection-detect"],
    aliases: ["nosql-injection-detect"],
    scannerSelectable: true,
  },
  {
    publicId: "template-injection",
    configKey: "template-injection",
    taskIds: ["template-injection-detect"],
    aliases: ["template-injection-detect"],
    scannerSelectable: true,
  },
  {
    publicId: "supply-chain",
    configKey: "supply-chain",
    taskIds: ["supply-chain-detect"],
    aliases: ["supply-chain-detect"],
    scannerSelectable: true,
  },
  {
    publicId: "graphql-security",
    configKey: "graphql-security",
    taskIds: ["graphql-security-detect"],
    aliases: ["graphql-security-detect"],
    scannerSelectable: true,
  },
  {
    publicId: "invariant-analysis",
    configKey: "invariant-analysis",
    taskIds: ["invariant-extract", "invariant-check"],
    aliases: ["invariant-extract", "invariant-check"],
    scannerSelectable: true,
  },
  {
    publicId: "threat-model",
    configKey: "threat-model",
    taskIds: ["threat-model-stride", "threat-model-pasta"],
    aliases: ["threat-model-stride", "threat-model-pasta"],
    scannerSelectable: true,
  },
  {
    publicId: "chain-analysis",
    configKey: "chain-analysis",
    taskIds: ["chain-analysis"],
  },
  {
    publicId: "context-gathering",
    taskIds: ["context-gatherer"],
    aliases: ["context-gatherer"],
  },
  {
    publicId: "context-enrichment",
    taskIds: ["context-enricher"],
    aliases: ["context-enricher"],
  },
  {
    publicId: "task-selection",
    taskIds: ["task-selector"],
    aliases: ["task-selector"],
  },
];

const CAPABILITY_LOOKUP = new Map<string, CapabilityDefinition>();
for (const capability of CAPABILITIES) {
  const keys = new Set<string>([
    capability.publicId,
    ...(capability.aliases ?? []),
    ...(capability.taskIds ?? []),
    ...(capability.pluginId ? [capability.pluginId] : []),
  ]);
  for (const key of keys) {
    CAPABILITY_LOOKUP.set(key, capability);
  }
}

function normalizeId(id: string): string {
  return id.trim();
}

function dedupeStrings(values: Iterable<string>): string[] {
  const result: string[] = [];
  const seen = new Set<string>();
  for (const raw of values) {
    const value = normalizeId(raw);
    if (!value || seen.has(value)) continue;
    seen.add(value);
    result.push(value);
  }
  return result;
}

export function resolveCapability(id: string): CapabilityDefinition | undefined {
  const normalized = normalizeId(id);
  if (!normalized) return undefined;
  return CAPABILITY_LOOKUP.get(normalized);
}

export function isKnownScannerSelectionId(id: string): boolean {
  const capability = resolveCapability(id);
  return capability?.scannerSelectable === true;
}

export function resolveRunnableIds(id: string): string[] {
  const normalized = normalizeId(id);
  if (!normalized) return [];

  const capability = resolveCapability(normalized);
  if (!capability) {
    return [normalized];
  }

  if (capability.pluginId === normalized) {
    return [normalized];
  }

  if (capability.taskIds?.includes(normalized)) {
    return [normalized];
  }

  if (capability.publicId === "taint-analysis" && normalized.startsWith("taint-analysis-")) {
    return [normalized];
  }

  if (capability.taskIds && capability.taskIds.length > 0) {
    return dedupeStrings(capability.taskIds);
  }

  if (capability.pluginId) {
    return [capability.pluginId];
  }

  return [normalized];
}

export function resolveCapabilityConfigKey(id: string): string {
  const normalized = normalizeId(id);
  if (!normalized) return normalized;
  return resolveCapability(normalized)?.configKey ?? normalized;
}

export function getCapabilityLookupIds(id: string): string[] {
  const normalized = normalizeId(id);
  if (!normalized) return [];

  const capability = resolveCapability(normalized);
  if (!capability) {
    return [normalized];
  }

  return dedupeStrings([
    capability.publicId,
    ...(capability.aliases ?? []),
    ...(capability.taskIds ?? []),
    ...(capability.pluginId ? [capability.pluginId] : []),
    ...(capability.configKey ? [capability.configKey] : []),
    normalized,
  ]);
}

export function resolveScannerConfig(
  config: KuzushiConfig,
  id: string,
): ScannerConfig {
  const resolved: ScannerConfig = {};

  for (const key of getCapabilityLookupIds(id)) {
    const raw = config.scannerConfig[key];
    if (!isRecord(raw)) continue;
    Object.assign(resolved, raw);
  }

  return resolved;
}

export function expandScannerSelections(
  selections: string[],
  config: KuzushiConfig,
): { pluginScanners: string[]; enabledTasks: string[] } {
  const pluginScanners: string[] = [];
  const enabledTasks: string[] = [];

  for (const raw of selections) {
    const id = normalizeId(raw);
    if (!id) continue;

    const capability = resolveCapability(id);
    if (!capability) {
      pluginScanners.push(id);
      continue;
    }

    if (capability.publicId === "taint-analysis") {
      const taintConfig = resolveScannerConfig(config, capability.publicId);
      const crossServiceEnabled = taintConfig["crossService"] === true;
      enabledTasks.push(
        ...(crossServiceEnabled ? TAINT_ANALYSIS_CROSS_SERVICE_TASK_IDS : TAINT_ANALYSIS_TASK_IDS),
      );
      continue;
    }

    if (capability.taskIds && capability.taskIds.length > 0) {
      enabledTasks.push(...capability.taskIds);
      continue;
    }

    if (capability.pluginId) {
      pluginScanners.push(capability.pluginId);
      continue;
    }

    pluginScanners.push(id);
  }

  return {
    pluginScanners: dedupeStrings(pluginScanners),
    enabledTasks: dedupeStrings(enabledTasks),
  };
}

export function normalizeTaskCapabilityIds(ids: string[]): string[] {
  const expanded = ids.flatMap((id) => resolveRunnableIds(id));
  return dedupeStrings(expanded);
}

export function taskCapabilityMatches(expected: string, taskId: string): boolean {
  const expectedIds = new Set(getCapabilityLookupIds(expected));
  const actualIds = new Set(getCapabilityLookupIds(taskId));

  for (const id of expectedIds) {
    if (actualIds.has(id)) {
      return true;
    }
  }

  return false;
}

export function normalizeScannerConfigAliases(
  scannerConfig: Record<string, ScannerConfig>,
): Record<string, ScannerConfig> {
  const normalized: Record<string, ScannerConfig> = {};

  for (const [key, value] of Object.entries(scannerConfig)) {
    if (!isRecord(value)) {
      continue;
    }

    const lookupIds = getCapabilityLookupIds(key);
    const targetKeys = lookupIds.length > 0 ? lookupIds : [key];

    for (const targetKey of targetKeys) {
      normalized[targetKey] = {
        ...(normalized[targetKey] ?? {}),
        ...value,
      };
    }
  }

  return normalized;
}

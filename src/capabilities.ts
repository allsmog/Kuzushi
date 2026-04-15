import type { TaskConfig } from "./scanners/types.js";
import type { KuzushiConfig } from "./types.js";
import { isRecord } from "./utils.js";

export const TAINT_ANALYSIS_TASK_IDS = [
  "taint-cwe-select",
  "taint-iris",
] as const;

export interface CapabilityDefinition {
  publicId: string;
  configKey?: string;
  taskIds?: readonly string[];
  aliases?: readonly string[];
  taskSelectable?: boolean;
}

const CAPABILITIES: CapabilityDefinition[] = [
  { publicId: "semgrep", configKey: "semgrep", taskIds: ["semgrep"], taskSelectable: true },
  { publicId: "agentic", configKey: "agentic", taskIds: ["agentic"], taskSelectable: true },
  { publicId: "codeql", configKey: "codeql", taskIds: ["codeql"], taskSelectable: true },
  {
    publicId: "taint-analysis",
    configKey: "taint-analysis",
    taskIds: TAINT_ANALYSIS_TASK_IDS,
    aliases: ["taint-cwe-select", "taint-iris"],
    taskSelectable: true,
  },
  {
    publicId: "secrets",
    configKey: "secrets-crypto-detect",
    taskIds: ["secrets-crypto-detect"],
    aliases: ["secrets-detection", "secrets-detect", "secrets-crypto-detect"],
    taskSelectable: true,
  },
  {
    publicId: "crypto-misuse",
    configKey: "secrets-crypto-detect",
    taskIds: ["secrets-crypto-detect"],
    aliases: ["crypto-misuse-detect", "secrets-crypto-detect"],
    taskSelectable: true,
  },
  {
    publicId: "auth-access",
    configKey: "code-config-detect",
    taskIds: ["code-config-detect"],
    aliases: ["auth-access-detect", "code-config-detect"],
    taskSelectable: true,
  },
  {
    publicId: "race-condition",
    configKey: "race-condition",
    taskIds: ["race-condition-detect"],
    aliases: ["race-condition-detect"],
    taskSelectable: true,
  },
  {
    publicId: "dangerous-api",
    configKey: "code-config-detect",
    taskIds: ["code-config-detect"],
    aliases: ["dangerous-api-detect", "code-config-detect"],
    taskSelectable: true,
  },
  {
    publicId: "diff-review",
    configKey: "diff-review",
    taskIds: ["diff-review"],
    taskSelectable: true,
  },
  {
    publicId: "security-misconfig",
    configKey: "code-config-detect",
    taskIds: ["code-config-detect"],
    aliases: ["security-misconfig-detect", "code-config-detect"],
    taskSelectable: true,
  },
  {
    publicId: "ssrf",
    configKey: "ssrf-detect",
    taskIds: ["ssrf-detect"],
    aliases: ["ssrf-detect", "ssrf-detection"],
    taskSelectable: true,
  },
  {
    publicId: "prototype-pollution",
    configKey: "prototype-pollution",
    taskIds: ["prototype-pollution-detect"],
    aliases: ["prototype-pollution-detect"],
    taskSelectable: true,
  },
  {
    publicId: "nosql-injection",
    configKey: "nosql-injection",
    taskIds: ["nosql-injection-detect"],
    aliases: ["nosql-injection-detect"],
    taskSelectable: true,
  },
  {
    publicId: "template-injection",
    configKey: "template-injection",
    taskIds: ["template-injection-detect"],
    aliases: ["template-injection-detect"],
    taskSelectable: true,
  },
  {
    publicId: "supply-chain",
    configKey: "supply-chain",
    taskIds: ["supply-chain-detect"],
    aliases: ["supply-chain-detect"],
    taskSelectable: true,
  },
  {
    publicId: "graphql-security",
    configKey: "graphql-security",
    taskIds: ["graphql-security-detect"],
    aliases: ["graphql-security-detect"],
    taskSelectable: true,
  },
  {
    publicId: "auth-logic",
    configKey: "auth-logic",
    taskIds: ["auth-logic-detect"],
    aliases: ["auth-logic-detect"],
    taskSelectable: true,
  },
  {
    publicId: "command-injection",
    configKey: "command-injection",
    taskIds: ["command-injection-detect"],
    aliases: ["command-injection-detect"],
    taskSelectable: true,
  },
  {
    publicId: "xxe",
    configKey: "xxe",
    taskIds: ["xxe-detect"],
    aliases: ["xxe-detect", "xxe-detection-detect"],
    taskSelectable: true,
  },
  {
    publicId: "deserialization",
    configKey: "deserialization",
    taskIds: ["deserialization-detect"],
    aliases: ["deserialization-detect", "deserialization-detection-detect"],
    taskSelectable: true,
  },
  {
    publicId: "invariant-analysis",
    configKey: "invariant-analysis",
    taskIds: ["invariant-extract", "invariant-check"],
    aliases: ["invariant-extract", "invariant-check"],
    taskSelectable: true,
  },
  {
    publicId: "threat-model",
    configKey: "threat-model",
    taskIds: ["threat-model-randori"],
    aliases: ["threat-model-randori"],
    taskSelectable: true,
  },
  {
    publicId: "threat-hunt",
    configKey: "threat-hunt",
    taskIds: ["threat-hunt"],
    taskSelectable: true,
  },
  {
    publicId: "tob-audit",
    configKey: "tob-audit",
    taskIds: ["tob-audit"],
    taskSelectable: true,
  },
  {
    publicId: "sharp-edges",
    configKey: "sharp-edges-detect",
    taskIds: ["sharp-edges-detect"],
    aliases: ["sharp-edges-detect"],
    taskSelectable: true,
  },
  {
    publicId: "systems-hunt",
    configKey: "systems-hunt",
    taskIds: ["systems-context-gatherer", "systems-invariant-extract", "systems-trigger-synth", "systems-hunt"],
    aliases: [
      "systems-context-gatherer",
      "systems-invariant-extract",
      "systems-trigger-synth",
      "deep-semantic",
      "deep-semantic-cwe-select",
      "deep-semantic-hunt",
    ],
    taskSelectable: true,
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
    if (!value || seen.has(value)) {
      continue;
    }
    seen.add(value);
    result.push(value);
  }
  return result;
}

export function resolveCapability(id: string): CapabilityDefinition | undefined {
  const normalized = normalizeId(id);
  if (!normalized) {
    return undefined;
  }
  return CAPABILITY_LOOKUP.get(normalized);
}

export function isKnownTaskSelectionId(id: string): boolean {
  const capability = resolveCapability(id);
  return capability?.taskSelectable === true;
}

export function resolveRunnableIds(id: string): string[] {
  const normalized = normalizeId(id);
  if (!normalized) {
    return [];
  }

  const capability = resolveCapability(normalized);
  if (!capability) {
    return [normalized];
  }

  if (capability.taskIds?.includes(normalized)) {
    return [normalized];
  }

  if (capability.publicId === "taint-analysis" && normalized !== "taint-analysis" && normalized.startsWith("taint-")) {
    return [normalized];
  }

  if (capability.taskIds && capability.taskIds.length > 0) {
    return dedupeStrings(capability.taskIds);
  }

  return [normalized];
}

export function resolveCapabilityConfigKey(id: string): string {
  const normalized = normalizeId(id);
  if (!normalized) {
    return normalized;
  }
  return resolveCapability(normalized)?.configKey ?? normalized;
}

export function getCapabilityLookupIds(id: string): string[] {
  const normalized = normalizeId(id);
  if (!normalized) {
    return [];
  }

  const capability = resolveCapability(normalized);
  if (!capability) {
    return [normalized];
  }

  return dedupeStrings([
    capability.publicId,
    ...(capability.aliases ?? []),
    ...(capability.taskIds ?? []),
    ...(capability.configKey ? [capability.configKey] : []),
    normalized,
  ]);
}

export function resolveTaskConfig(
  config: KuzushiConfig,
  id: string,
): TaskConfig {
  const resolved: TaskConfig = {};

  for (const key of getCapabilityLookupIds(id)) {
    const raw = config.taskConfig[key];
    if (!isRecord(raw)) {
      continue;
    }
    Object.assign(resolved, raw);
  }

  return resolved;
}

export function expandTaskSelections(
  selections: string[],
  config: KuzushiConfig,
): string[] {
  const tasks: string[] = [];

  for (const raw of selections) {
    const id = normalizeId(raw);
    if (!id) {
      continue;
    }

    const capability = resolveCapability(id);
    if (!capability) {
      tasks.push(id);
      continue;
    }

    if (capability.publicId === "taint-analysis") {
      tasks.push(...TAINT_ANALYSIS_TASK_IDS);
      continue;
    }

    tasks.push(...resolveRunnableIds(id));
  }

  return dedupeStrings(tasks);
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

export function normalizeTaskConfigAliases(
  taskConfig: Record<string, TaskConfig>,
): Record<string, TaskConfig> {
  const normalized: Record<string, TaskConfig> = {};

  for (const [key, value] of Object.entries(taskConfig)) {
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

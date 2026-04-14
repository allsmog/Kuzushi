import { resolveDefaultReadOnlyTools } from "../../agent-runtime/execution.js";
import type { AgentEffort, AgentRuntime } from "../../agent-runtime/types.js";
import { resolveTaskConfig as resolveConfiguredTaskConfig } from "../../capabilities.js";
import { ALL_TOOLS, buildPolicyLayers, resolveToolPolicy, type ToolPolicy } from "../../prompts/tool-policy.js";
import { isRecord } from "../../utils.js";
import type { KuzushiConfig } from "../../types.js";
import type { TaskContext } from "../types.js";

export function resolveTaskModel(
  context: TaskContext,
  configKey: string,
  ...fallbackConfigKeys: string[]
): string {
  const configuredModel = resolveTaskStringConfig(context, configKey, "model", ...fallbackConfigKeys);
  return context.modelOverride ?? configuredModel ?? context.config.model;
}

export function resolveTaskPositiveInt(
  context: TaskContext,
  configKey: string,
  optionKey: string,
  fallback: number,
  ...fallbackConfigKeys: string[]
): number {
  const configured = resolveTaskNumberConfig(context, configKey, optionKey, ...fallbackConfigKeys);
  if (configured != null && configured >= 1) {
    return Math.floor(configured);
  }
  return fallback;
}

export function resolveTaskAllowedTools(
  context: TaskContext,
  taskPolicy?: ToolPolicy,
  baseTools?: string[],
): string[] {
  const runtime = resolveTaskRuntime(context);
  const availableTools = dedupeTools(baseTools ?? resolveDefaultReadOnlyTools(runtime));
  if (!taskPolicy && !context.config.toolPolicies) {
    return availableTools;
  }

  const layers = buildPolicyLayers(taskPolicy, context.config.toolPolicies);
  return dedupeTools(resolveToolPolicy(availableTools.length > 0 ? availableTools : ALL_TOOLS, layers));
}

export function resolveTaskEffort(
  context: TaskContext,
  configKey: string,
  ...fallbackConfigKeys: string[]
): AgentEffort | undefined {
  const configured = resolveTaskStringConfig(context, configKey, "effort", ...fallbackConfigKeys);
  if (configured === "low" || configured === "medium" || configured === "high" || configured === "max") {
    return configured;
  }
  return undefined;
}

export function resolveTaskThinkingDisabled(
  context: TaskContext,
  configKey: string,
  ...fallbackConfigKeys: string[]
): boolean | undefined {
  for (const key of [configKey, ...fallbackConfigKeys]) {
    const raw = context.config.taskConfig[key];
    if (isRecord(raw) && typeof raw["thinkingDisabled"] === "boolean") {
      return raw["thinkingDisabled"];
    }
  }
  return undefined;
}

export function resolveTaskRuntime(context: TaskContext): AgentRuntime {
  return context.runtime;
}

export function resolveStageModel(
  config: Pick<KuzushiConfig, "model" | "taskConfig">,
  configKey: string,
  ...fallbackConfigKeys: string[]
): string {
  return resolveStageStringConfig(config, configKey, "model", ...fallbackConfigKeys) ?? config.model;
}

export function resolveStageEffort(
  config: Pick<KuzushiConfig, "taskConfig">,
  configKey: string,
  ...fallbackConfigKeys: string[]
): AgentEffort | undefined {
  const configured = resolveStageStringConfig(config, configKey, "effort", ...fallbackConfigKeys);
  if (configured === "low" || configured === "medium" || configured === "high" || configured === "max") {
    return configured;
  }
  return undefined;
}

export function resolveStageThinkingDisabled(
  config: Pick<KuzushiConfig, "taskConfig">,
  configKey: string,
  ...fallbackConfigKeys: string[]
): boolean | undefined {
  for (const key of [configKey, ...fallbackConfigKeys]) {
    const raw = resolveConfiguredTaskConfig(config as KuzushiConfig, key);
    if (typeof raw["thinkingDisabled"] === "boolean") {
      return raw["thinkingDisabled"];
    }
  }
  return undefined;
}

function resolveTaskStringConfig(
  context: TaskContext,
  configKey: string,
  optionKey: string,
  ...fallbackConfigKeys: string[]
): string | undefined {
  for (const key of [configKey, ...fallbackConfigKeys]) {
    const raw = resolveConfiguredTaskConfig(context.config, key);
    if (typeof raw[optionKey] === "string" && raw[optionKey].trim()) {
      return raw[optionKey].trim();
    }
  }
  return undefined;
}

function resolveTaskNumberConfig(
  context: TaskContext,
  configKey: string,
  optionKey: string,
  ...fallbackConfigKeys: string[]
): number | undefined {
  for (const key of [configKey, ...fallbackConfigKeys]) {
    const raw = resolveConfiguredTaskConfig(context.config, key);
    if (typeof raw[optionKey] === "number" && Number.isFinite(raw[optionKey])) {
      return raw[optionKey];
    }
  }
  return undefined;
}

function resolveStageStringConfig(
  config: Pick<KuzushiConfig, "taskConfig">,
  configKey: string,
  optionKey: string,
  ...fallbackConfigKeys: string[]
): string | undefined {
  for (const key of [configKey, ...fallbackConfigKeys]) {
    const raw = resolveConfiguredTaskConfig(config as KuzushiConfig, key);
    if (typeof raw[optionKey] === "string" && raw[optionKey].trim()) {
      return raw[optionKey].trim();
    }
  }
  return undefined;
}

function dedupeTools(tools: string[]): string[] {
  return [...new Set(tools.filter(Boolean))];
}

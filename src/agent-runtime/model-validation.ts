import type { AgentRuntimeBackend } from "../contracts.js";
import { AGENT_RUNTIME_BACKENDS } from "../contracts.js";
import { toErrorMessage } from "../utils.js";
import { parsePiAiModelSpec } from "./model-spec.js";
export function validateModelOverride(
  backend: AgentRuntimeBackend | undefined,
  model: string,
): string | null {
  const value = model.trim();
  if (value.length === 0) {
    return "model must be non-empty";
  }

  const resolvedBackend = backend ?? "pi-ai";
  if (resolvedBackend === "pi-ai") {
    try {
      parsePiAiModelSpec(value);
      return null;
    } catch (err) {
      return toErrorMessage(err);
    }
  }

  if (resolvedBackend === "codex") {
    const separatorIndex = value.indexOf(":");
    if (separatorIndex === -1) return null;
    const provider = value.slice(0, separatorIndex).trim().toLowerCase();
    const modelId = value.slice(separatorIndex + 1).trim();
    if (!provider || !modelId) {
      return `Codex model "${model}" is invalid. Expected a bare model id, openai:modelId, or codex:modelId`;
    }
    if (provider !== "openai" && provider !== "codex") {
      return `Codex runtime only accepts bare OpenAI model ids, openai:modelId, or codex:modelId, got ${provider}:...`;
    }
    return null;
  }

  const separatorIndex = value.indexOf(":");
  if (separatorIndex === -1) {
    return null;
  }

  const provider = value.slice(0, separatorIndex).trim().toLowerCase();
  const modelId = value.slice(separatorIndex + 1).trim();
  if (!provider || !modelId) {
    return `Claude model "${model}" is invalid. Expected a bare model id or anthropic:modelId`;
  }
  if (provider !== "anthropic") {
    return `Claude runtime only accepts bare Claude model ids or anthropic:modelId, got ${provider}:...`;
  }
  return null;
}

export function describeModelOverrideFormat(backend: AgentRuntimeBackend | undefined): string {
  const resolvedBackend = backend ?? "pi-ai";
  if (resolvedBackend === "claude") {
    return "Model override for this session. Claude accepts bare Claude model ids or anthropic:<model>.";
  }
  if (resolvedBackend === "codex") {
    return "Model override for this session. Codex accepts bare OpenAI model ids, openai:<model>, or codex:<model>.";
  }
  return "Model override for this session. pi-ai expects provider:<model>.";
}

export function validateRuntimeModel(runtimeId: string, model: string): string | null {
  if (!isKnownAgentRuntimeBackend(runtimeId)) return null;
  return validateModelOverride(runtimeId, model);
}

export function assertRuntimeModelCompatible(runtimeId: string, model: string): void {
  const error = validateRuntimeModel(runtimeId, model);
  if (!error) return;
  throw new Error(
    [
      `Model "${model}" is not compatible with agent runtime "${runtimeId}".`,
      error,
      "Choose a compatible model explicitly with /model, /provider, --model, or config set model.",
      "Kuzushi will not silently switch models or providers.",
    ].join(" "),
  );
}

export function assertRuntimeModelSelection(
  runtimeId: string,
  model: string,
  fallbackModel?: string,
): void {
  assertRuntimeModelCompatible(runtimeId, model);
  if (!fallbackModel || fallbackModel.trim().length === 0) return;
  throw new Error(
    [
      `Fallback model "${fallbackModel}" was provided for agent runtime "${runtimeId}".`,
      "Automatic model fallback is disabled because Kuzushi must not switch models without operator consent.",
      "Choose the intended model explicitly with /model, /provider, --model, or config set model.",
    ].join(" "),
  );
}

function isKnownAgentRuntimeBackend(value: string): value is AgentRuntimeBackend {
  return (AGENT_RUNTIME_BACKENDS as readonly string[]).includes(value);
}

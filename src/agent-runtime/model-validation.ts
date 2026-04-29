import type { AgentRuntimeBackend } from "../contracts.js";
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
      return err instanceof Error ? err.message : String(err);
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

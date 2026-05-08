export interface PiAiModelSpec {
  provider: string;
  modelId: string;
}

/**
 * Parse a pi-ai model identifier in provider:modelId format.
 */
export function parsePiAiModelSpec(model: string): PiAiModelSpec {
  const value = model.trim();
  const separatorIndex = value.indexOf(":");

  if (separatorIndex === -1) {
    throw new Error(`pi-ai model "${model}" is invalid. Expected format: provider:modelId`);
  }

  const provider = value.slice(0, separatorIndex).trim();
  const modelId = value.slice(separatorIndex + 1).trim();

  if (!provider || !modelId) {
    throw new Error(`pi-ai model "${model}" is invalid. Expected format: provider:modelId`);
  }

  return { provider, modelId };
}

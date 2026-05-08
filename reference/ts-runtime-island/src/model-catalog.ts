import { parsePiAiModelSpec } from "./agent-runtime/model-spec.js";

export interface ModelProviderOption {
  id: string;
  name: string;
  description: string;
  detail: string;
}

export interface ModelCatalogEntry {
  id: string;
  provider: string;
  name: string;
  description: string;
  detail: string;
  summary: string;
}

export const MODEL_PROVIDERS: ReadonlyArray<ModelProviderOption> = [
  {
    id: "anthropic",
    name: "Anthropic",
    description: "Claude API or Claude OAuth",
    detail: "Use Claude Opus, Sonnet, or Haiku through Anthropic credentials.",
  },
  {
    id: "openai-codex",
    name: "ChatGPT Codex",
    description: "Codex OAuth",
    detail: "Use ChatGPT Codex OAuth credentials saved by /auth.",
  },
  {
    id: "openai",
    name: "OpenAI",
    description: "OpenAI API",
    detail: "Use GPT models through OPENAI_API_KEY or saved project credentials.",
  },
  {
    id: "google",
    name: "Google",
    description: "Gemini API",
    detail: "Use Gemini models through GOOGLE_API_KEY.",
  },
  {
    id: "openrouter",
    name: "OpenRouter",
    description: "Unified model gateway",
    detail: "Use provider/model ids proxied by OpenRouter.",
  },
  {
    id: "groq",
    name: "Groq",
    description: "Fast OSS inference",
    detail: "Use Groq-hosted open models.",
  },
  {
    id: "mistral",
    name: "Mistral",
    description: "Mistral API",
    detail: "Use Mistral and Codestral models.",
  },
  {
    id: "xai",
    name: "xAI",
    description: "Grok API",
    detail: "Use Grok models through XAI_API_KEY.",
  },
  {
    id: "cerebras",
    name: "Cerebras",
    description: "Cerebras API",
    detail: "Use Cerebras-hosted fast inference models.",
  },
  {
    id: "ollama",
    name: "Ollama / local",
    description: "OpenAI-compatible local endpoint",
    detail: "Use local models with agentRuntimeConfig.baseUrl.",
  },
];

export const MODEL_CATALOG: ReadonlyArray<ModelCatalogEntry> = [
  {
    id: "anthropic:claude-sonnet-4-6",
    provider: "anthropic",
    name: "Claude Sonnet 4.6",
    description: "Balanced default",
    detail: "Good default for scans, triage, and verification.",
    summary: "Best first choice for most repos.",
  },
  {
    id: "anthropic:claude-opus-4-6",
    provider: "anthropic",
    name: "Claude Opus 4.6",
    description: "Highest accuracy",
    detail: "Use when recall and reasoning depth matter more than cost.",
    summary: "Best for deep investigations.",
  },
  {
    id: "anthropic:claude-haiku-4-5",
    provider: "anthropic",
    name: "Claude Haiku 4.5",
    description: "Fast and cheap",
    detail: "Use for quick passes, large repos, and low-cost triage.",
    summary: "Best for speed-sensitive work.",
  },
  {
    id: "openai-codex:gpt-5.4-mini",
    provider: "openai-codex",
    name: "GPT-5.4 Mini",
    description: "Codex balanced",
    detail: "Recommended starting point for ChatGPT Codex OAuth.",
    summary: "Good latency and cost for shell use.",
  },
  {
    id: "openai-codex:gpt-5.4",
    provider: "openai-codex",
    name: "GPT-5.4",
    description: "Codex stronger reasoning",
    detail: "Use when the default Codex mini model misses nuance.",
    summary: "Better for complex code reasoning.",
  },
  {
    id: "openai-codex:gpt-5.3-codex",
    provider: "openai-codex",
    name: "GPT-5.3 Codex",
    description: "Codex coding specialist",
    detail: "Use for coding-heavy shell sessions and patch review.",
    summary: "Strong fit for implementation work.",
  },
  {
    id: "openai-codex:gpt-5.3-codex-spark",
    provider: "openai-codex",
    name: "GPT-5.3 Codex Monorepo",
    description: "Codex fast coding",
    detail: "Use when latency matters more than maximum reasoning depth.",
    summary: "Fastest Codex option in the curated list.",
  },
  {
    id: "openai:gpt-5-mini",
    provider: "openai",
    name: "GPT-5 Mini",
    description: "OpenAI balanced",
    detail: "Good default for OpenAI API users.",
    summary: "Balanced OpenAI choice.",
  },
  {
    id: "openai:gpt-5",
    provider: "openai",
    name: "GPT-5",
    description: "OpenAI most capable",
    detail: "Use for complex reasoning when cost is acceptable.",
    summary: "Highest-reasoning OpenAI API choice.",
  },
  {
    id: "google:gemini-2.5-flash",
    provider: "google",
    name: "Gemini 2.5 Flash",
    description: "Fast Gemini",
    detail: "Good for low-latency, low-cost cloud runs.",
    summary: "Fast Google option.",
  },
  {
    id: "google:gemini-2.5-pro",
    provider: "google",
    name: "Gemini 2.5 Pro",
    description: "Strong multi-step",
    detail: "Use for larger context and complex repo reasoning.",
    summary: "Stronger Google option.",
  },
  {
    id: "openrouter:anthropic/claude-sonnet-4-6",
    provider: "openrouter",
    name: "Claude Sonnet via OpenRouter",
    description: "OpenRouter balanced",
    detail: "Use Anthropic models through OpenRouter billing.",
    summary: "Good OpenRouter default.",
  },
  {
    id: "openrouter:openai/gpt-5-mini",
    provider: "openrouter",
    name: "GPT-5 Mini via OpenRouter",
    description: "OpenRouter OpenAI",
    detail: "Use OpenAI models through OpenRouter billing.",
    summary: "Good OpenRouter OpenAI choice.",
  },
  {
    id: "groq:llama-3.3-70b-versatile",
    provider: "groq",
    name: "Llama 3.3 70B",
    description: "Groq fast OSS",
    detail: "Use when latency matters more than peak accuracy.",
    summary: "Fast open-model option.",
  },
  {
    id: "mistral:mistral-large-latest",
    provider: "mistral",
    name: "Mistral Large",
    description: "Mistral general reasoning",
    detail: "Use the latest Mistral Large model exposed by the provider.",
    summary: "General Mistral choice.",
  },
  {
    id: "mistral:codestral-latest",
    provider: "mistral",
    name: "Codestral",
    description: "Mistral coding",
    detail: "Use the latest Codestral model for code-focused tasks.",
    summary: "Mistral code option.",
  },
  {
    id: "xai:grok-code-fast-1",
    provider: "xai",
    name: "Grok Code Fast",
    description: "xAI code model",
    detail: "Use for low-latency code tasks through xAI.",
    summary: "Fast xAI coding option.",
  },
  {
    id: "cerebras:llama3.1-70b",
    provider: "cerebras",
    name: "Llama 3.1 70B",
    description: "Cerebras fast OSS",
    detail: "Use for low-latency open-model runs on Cerebras.",
    summary: "Fast Cerebras option.",
  },
  {
    id: "ollama:llama3.1",
    provider: "ollama",
    name: "Llama 3.1 local",
    description: "Local default",
    detail: "Use with a configured local OpenAI-compatible endpoint.",
    summary: "Starter local model id.",
  },
];

export function providerFromModelId(model: string | undefined): string | undefined {
  if (!model) return undefined;
  try {
    return parsePiAiModelSpec(model).provider;
  } catch {
    return undefined;
  }
}

export function modelOptionsForProvider(
  provider: string,
  opts: {
    activeModel?: string;
    availableModels?: ReadonlyArray<string>;
  } = {},
): ModelCatalogEntry[] {
  const seen = new Set<string>();
  const out: ModelCatalogEntry[] = [];

  const push = (entry: ModelCatalogEntry): void => {
    if (seen.has(entry.id)) return;
    seen.add(entry.id);
    out.push(entry);
  };

  const activeProvider = providerFromModelId(opts.activeModel);
  if (opts.activeModel && activeProvider === provider) {
    push(customEntry(opts.activeModel, provider, "Current model"));
  }

  for (const entry of MODEL_CATALOG) {
    if (entry.provider === provider) push(entry);
  }

  for (const id of opts.availableModels ?? []) {
    if (providerFromModelId(id) === provider) push(customEntry(id, provider, "Saved pool model"));
  }

  return out;
}

function customEntry(id: string, provider: string, description: string): ModelCatalogEntry {
  return {
    id,
    provider,
    name: id,
    description,
    detail: "This model id is already configured locally.",
    summary: "Select it to make it the default model.",
  };
}

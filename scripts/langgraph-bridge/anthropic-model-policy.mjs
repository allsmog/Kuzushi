// Per-model Anthropic request policy shared by the API-key (@langchain/anthropic)
// and subscription OAuth adapters, so one model id behaves the same on both
// credential paths.

// Adaptive-thinking-only models think before answering on their own, and that
// thinking is billed against the same `max_tokens` as the visible answer.
const ADAPTIVE_THINKING_MODEL_PREFIXES = [
  "claude-opus-4-7",
  "claude-opus-4-8",
  "claude-fable-5",
  "claude-opus-5",
  "claude-sonnet-5",
  "claude-haiku-5",
];

// Visible-output budget when the caller does not request one. Mirrors the
// @langchain/anthropic per-model defaults and covers the families it omits
// (it has no claude-haiku-5 entry, so its 4096 fallback truncated structured
// agentic-SAST output). Explicit request budgets always win.
const DEFAULT_MAX_OUTPUT_TOKENS_BY_PREFIX = [
  ["claude-opus-5", 16384],
  ["claude-sonnet-5", 16384],
  ["claude-haiku-5", 16384],
  ["claude-fable-5", 16384],
  ["claude-opus-4", 16384],
  ["claude-sonnet-4", 16384],
  ["claude-haiku-4-5", 16384],
  ["claude-3-7-sonnet", 8192],
  ["claude-3-5-sonnet", 8192],
  ["claude-3-5-haiku", 8192],
];
const FALLBACK_MAX_OUTPUT_TOKENS = 4096;

// Room reserved for adaptive thinking on top of the visible-output budget.
// Without it, a long think can exhaust a structured-output budget and truncate
// the JSON (threat-model:build asks for 32000 and Haiku 5.5 was observed using
// ~22000 of them thinking).
export const ADAPTIVE_THINKING_HEADROOM_TOKENS = 32000;

// Adaptive-thinking models also reject sampling knobs: the API answers
// `temperature` with HTTP 400 ("`temperature` is deprecated for this model"),
// and @langchain/anthropic `validateInvocationParamCompatibility` throws before
// any HTTP call. A caller-pinned deterministic temperature (e.g. triage's 0.0)
// therefore degrades to the provider default instead of failing every call.
export function temperatureLockedModelName(modelName) {
  return adaptiveThinkingModelName(modelName);
}

export function anthropicDefaultMaxOutputTokens(modelName) {
  const match = DEFAULT_MAX_OUTPUT_TOKENS_BY_PREFIX.find(([prefix]) => modelId(modelName).startsWith(prefix));
  return match?.[1] ?? FALLBACK_MAX_OUTPUT_TOKENS;
}

// The `max_tokens` to send: the requested (or default) visible-output budget,
// plus thinking headroom for models that think adaptively.
export function anthropicMaxTokens(modelName, requestedOutputTokens) {
  const visible = positiveInteger(requestedOutputTokens) ?? anthropicDefaultMaxOutputTokens(modelName);
  return adaptiveThinkingModelName(modelName) ? visible + ADAPTIVE_THINKING_HEADROOM_TOKENS : visible;
}

function adaptiveThinkingModelName(modelName) {
  return ADAPTIVE_THINKING_MODEL_PREFIXES.some((prefix) => modelId(modelName).startsWith(prefix));
}

function positiveInteger(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? Math.floor(number) : undefined;
}

function modelId(modelName) {
  return String(modelName ?? "");
}

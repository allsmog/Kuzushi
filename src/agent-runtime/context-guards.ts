/**
 * Context window safety guards for agent runtime.
 *
 * Prevents infinite retry on context overflow by enforcing minimum
 * token reserves and truncating oversized tool results.
 */

/** Default minimum token reserve to prevent context overflow loops. */
const DEFAULT_MIN_TOKEN_RESERVE = 4096;

/** Rough chars-per-token estimate for English text. */
const CHARS_PER_TOKEN = 4;

/** Options for context guard behavior. */
export interface ContextGuardOptions {
  /** Maximum context window size in tokens for the target model. */
  maxContextTokens: number;
  /** Minimum tokens to reserve for model output. Default 4096. */
  minOutputReserve?: number;
  /** Maximum characters allowed for a single tool result. Default 100_000. */
  maxToolResultChars?: number;
  /** Whether to account for cached prompt prefix. */
  cachedPrefixTokens?: number;
}

/** Result of a context budget check. */
export interface ContextBudgetCheck {
  /** Whether there is enough room to proceed. */
  ok: boolean;
  /** Estimated tokens currently used. */
  estimatedUsedTokens: number;
  /** Remaining token budget after reserving output space. */
  remainingBudget: number;
  /** Warning message if budget is tight. */
  warning?: string;
}

/** Estimate token count from a character count. */
export function estimateTokens(charCount: number): number {
  return Math.ceil(charCount / CHARS_PER_TOKEN);
}

/** Estimate character count from a token count. */
export function estimateChars(tokenCount: number): number {
  return tokenCount * CHARS_PER_TOKEN;
}

/**
 * Check whether the current context has enough token budget remaining.
 *
 * Returns a budget check with ok=false if the model would overflow
 * or have insufficient room for meaningful output.
 */
export function checkContextBudget(
  currentContextChars: number,
  options: ContextGuardOptions,
): ContextBudgetCheck {
  const minReserve = options.minOutputReserve ?? DEFAULT_MIN_TOKEN_RESERVE;
  const cachedTokens = options.cachedPrefixTokens ?? 0;

  const estimatedUsedTokens = estimateTokens(currentContextChars);
  // Cached tokens are stored server-side and don't count against the input limit
  // the same way, but we include them for safety accounting.
  const effectiveUsed = Math.max(0, estimatedUsedTokens - cachedTokens);
  const remainingBudget = options.maxContextTokens - effectiveUsed - minReserve;

  if (remainingBudget <= 0) {
    return {
      ok: false,
      estimatedUsedTokens,
      remainingBudget,
      warning: `Context budget exhausted: ~${estimatedUsedTokens} tokens used, need ${minReserve} reserved for output, max ${options.maxContextTokens}`,
    };
  }

  const warningThreshold = options.maxContextTokens * 0.1;
  const warning =
    remainingBudget < warningThreshold
      ? `Context budget low: ~${remainingBudget} tokens remaining (${Math.round((remainingBudget / options.maxContextTokens) * 100)}%)`
      : undefined;

  return {
    ok: true,
    estimatedUsedTokens,
    remainingBudget,
    warning,
  };
}

/**
 * Truncate a tool result string if it exceeds the maximum allowed size.
 *
 * Truncation preserves the beginning of the content and appends
 * a marker indicating how much was removed.
 */
export function truncateToolResult(result: string, maxChars?: number): string {
  const limit = maxChars ?? 100_000;
  if (result.length <= limit) {
    return result;
  }

  const truncated = result.slice(0, limit);
  const removedChars = result.length - limit;
  return `${truncated}\n\n[... truncated ${removedChars} characters]`;
}

/**
 * Truncate content to fit within a token budget.
 *
 * Unlike truncateToolResult (which uses a char limit), this function
 * targets a specific token budget, which is useful when you need to
 * fit content into a known remaining context window.
 */
export function truncateToTokenBudget(content: string, maxTokens: number): string {
  const maxChars = estimateChars(maxTokens);
  return truncateToolResult(content, maxChars);
}

/** Well-known model context window sizes (in tokens). */
export const MODEL_CONTEXT_WINDOWS: Record<string, number> = {
  "claude-sonnet-4-6": 200_000,
  "claude-opus-4-6": 200_000,
  "claude-haiku-4-5": 200_000,
  "claude-sonnet-4-5": 200_000,
};

/**
 * Look up a model's context window size.
 * Falls back to 200k if the model is unknown.
 */
export function getModelContextWindow(modelId: string): number {
  // Strip provider prefix (e.g., "anthropic:claude-sonnet-4-6" -> "claude-sonnet-4-6")
  const stripped = modelId.includes(":") ? modelId.split(":").pop()! : modelId;
  return MODEL_CONTEXT_WINDOWS[stripped] ?? 200_000;
}

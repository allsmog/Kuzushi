import { toErrorMessage } from "../utils.js";

/** Error categories for classification. */
export type ErrorCategory =
  | "transient"
  | "rate_limit"
  | "auth"
  | "billing"
  | "context_overflow"
  | "unknown";

/** Classified error with category and metadata. */
export interface ClassifiedError {
  category: ErrorCategory;
  retryable: boolean;
  message: string;
  /** Suggested backoff multiplier relative to base delay. */
  backoffMultiplier: number;
}

const TRANSIENT_STATUS_CODES = new Set([500, 502, 503, 529]);
const RATE_LIMIT_STATUS_CODES = new Set([429]);

const TRANSIENT_NETWORK_TOKENS = [
  "ETIMEDOUT",
  "ECONNREFUSED",
  "ECONNRESET",
  "socket hang up",
  "fetch failed",
  "Request timed out",
];

const TRANSIENT_API_TOKENS = [
  "overloaded",
  "temporarily unavailable",
  "Service Temporarily Unavailable",
];

const AUTH_TOKENS = [
  "authentication_error",
  "invalid_api_key",
  "invalid x-api-key",
  "permission_error",
  "401",
  "403",
];

const BILLING_TOKENS = ["billing_error", "insufficient_quota", "payment_required", "402"];

const CONTEXT_OVERFLOW_TOKENS = [
  "context_length_exceeded",
  "max_tokens",
  "prompt is too long",
  "context window",
];

/** Classify an error into a category with retry/backoff metadata. */
export function classifyError(error: unknown): ClassifiedError {
  const message = toErrorMessage(error);
  const lower = message.toLowerCase();

  // Rate limit (429) — retryable with long backoff
  if (isRateLimitMessage(message)) {
    return { category: "rate_limit", retryable: true, message, backoffMultiplier: 3 };
  }

  // Auth errors — not retryable
  if (AUTH_TOKENS.some((t) => lower.includes(t.toLowerCase()))) {
    return { category: "auth", retryable: false, message, backoffMultiplier: 1 };
  }

  // Billing errors — not retryable
  if (BILLING_TOKENS.some((t) => lower.includes(t.toLowerCase()))) {
    return { category: "billing", retryable: false, message, backoffMultiplier: 1 };
  }

  // Context overflow — not retryable (needs truncation, not retry)
  if (CONTEXT_OVERFLOW_TOKENS.some((t) => lower.includes(t.toLowerCase()))) {
    return { category: "context_overflow", retryable: false, message, backoffMultiplier: 1 };
  }

  // Transient server errors — retryable with normal backoff
  if (isTransientMessage(message)) {
    return { category: "transient", retryable: true, message, backoffMultiplier: 1 };
  }

  return { category: "unknown", retryable: false, message, backoffMultiplier: 1 };
}

/** Check if an error message indicates a transient/retryable condition. */
export function isTransientError(error: unknown): boolean {
  const message = toErrorMessage(error);
  return isTransientMessage(message) || isRateLimitMessage(message);
}

/** Check if an error message indicates a rate limit (429). */
export function isRateLimitError(error: unknown): boolean {
  const message = typeof error === "string" ? error : toErrorMessage(error);
  return isRateLimitMessage(message);
}

function isTransientMessage(message: string): boolean {
  for (const code of TRANSIENT_STATUS_CODES) {
    if (message.includes(String(code))) return true;
  }
  for (const token of TRANSIENT_NETWORK_TOKENS) {
    if (message.includes(token)) return true;
  }
  for (const token of TRANSIENT_API_TOKENS) {
    if (message.toLowerCase().includes(token.toLowerCase())) return true;
  }
  return false;
}

function isRateLimitMessage(message: string): boolean {
  return message.includes("429") || /rate.?limit/i.test(message);
}

/** Calculate adaptive backoff delay. */
export function calculateBackoff(
  attempt: number,
  baseMs: number,
  classified: ClassifiedError,
): number {
  return baseMs * classified.backoffMultiplier * 2 ** attempt;
}

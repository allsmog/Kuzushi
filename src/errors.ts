/**
 * Typed error hierarchy for kuzushi.
 *
 * Every error thrown by kuzushi internals should be (or wrap) a `KuzushiError`
 * so callers can inspect `category` and `retryable` to decide how to proceed.
 */

// ---------------------------------------------------------------------------
// Category
// ---------------------------------------------------------------------------

export type ErrorCategory =
  | "transient"
  | "rate_limit"
  | "validation"
  | "auth"
  | "budget"
  | "fatal";

const RETRYABLE_CATEGORIES: ReadonlySet<ErrorCategory> = new Set<ErrorCategory>([
  "transient",
  "rate_limit",
]);

// ---------------------------------------------------------------------------
// Base class
// ---------------------------------------------------------------------------

export class KuzushiError extends Error {
  readonly category: ErrorCategory;
  readonly retryable: boolean;
  readonly costUsd?: number;

  constructor(
    message: string,
    category: ErrorCategory,
    options?: { cause?: unknown; costUsd?: number },
  ) {
    super(message, { cause: options?.cause });
    this.name = "KuzushiError";
    this.category = category;
    this.retryable = RETRYABLE_CATEGORIES.has(category);
    if (options?.costUsd !== undefined) {
      this.costUsd = options.costUsd;
    }
  }
}

// ---------------------------------------------------------------------------
// Subclasses
// ---------------------------------------------------------------------------

export class TransientError extends KuzushiError {
  constructor(message: string, options?: { cause?: unknown; costUsd?: number }) {
    super(message, "transient", options);
    this.name = "TransientError";
  }
}

export class RateLimitError extends KuzushiError {
  constructor(message: string, options?: { cause?: unknown; costUsd?: number }) {
    super(message, "rate_limit", options);
    this.name = "RateLimitError";
  }
}

export class ValidationError extends KuzushiError {
  constructor(message: string, options?: { cause?: unknown; costUsd?: number }) {
    super(message, "validation", options);
    this.name = "ValidationError";
  }
}

export class AuthError extends KuzushiError {
  constructor(message: string, options?: { cause?: unknown; costUsd?: number }) {
    super(message, "auth", options);
    this.name = "AuthError";
  }
}

export class BudgetError extends KuzushiError {
  constructor(message: string, options?: { cause?: unknown; costUsd?: number }) {
    super(message, "budget", options);
    this.name = "BudgetError";
  }
}

export class FatalError extends KuzushiError {
  constructor(message: string, options?: { cause?: unknown; costUsd?: number }) {
    super(message, "fatal", options);
    this.name = "FatalError";
  }
}

// ---------------------------------------------------------------------------
// Classification helper
// ---------------------------------------------------------------------------

/** Status-code tokens extracted from error messages. */
const STATUS_PATTERNS: Array<{ pattern: RegExp; category: ErrorCategory }> = [
  // Rate limiting
  { pattern: /\b429\b/, category: "rate_limit" },
  { pattern: /rate.?limit/i, category: "rate_limit" },
  { pattern: /too many requests/i, category: "rate_limit" },

  // Auth
  { pattern: /\b401\b/, category: "auth" },
  { pattern: /\b403\b/, category: "auth" },
  { pattern: /unauthorized/i, category: "auth" },
  { pattern: /forbidden/i, category: "auth" },
  { pattern: /invalid.?api.?key/i, category: "auth" },
  { pattern: /authentication/i, category: "auth" },

  // Validation (client errors)
  { pattern: /\b400\b/, category: "validation" },
  { pattern: /\b422\b/, category: "validation" },
  { pattern: /invalid request/i, category: "validation" },

  // Transient (server / network)
  { pattern: /\b500\b/, category: "transient" },
  { pattern: /\b502\b/, category: "transient" },
  { pattern: /\b503\b/, category: "transient" },
  { pattern: /\b529\b/, category: "transient" },
  { pattern: /ETIMEDOUT/i, category: "transient" },
  { pattern: /ECONNREFUSED/i, category: "transient" },
  { pattern: /ECONNRESET/i, category: "transient" },
  { pattern: /socket hang up/i, category: "transient" },
  { pattern: /fetch failed/i, category: "transient" },
  { pattern: /request timed out/i, category: "transient" },
  { pattern: /overloaded/i, category: "transient" },
  { pattern: /temporarily unavailable/i, category: "transient" },
  { pattern: /service temporarily unavailable/i, category: "transient" },
  { pattern: /timeout/i, category: "transient" },

  // Budget
  { pattern: /budget.?exceeded/i, category: "budget" },
];

/**
 * Inspect an unknown error and return the most appropriate `ErrorCategory`.
 *
 * For `KuzushiError` instances the category is returned directly.
 * For other errors the message (and optionally an HTTP status code) is
 * matched against well-known patterns.  If nothing matches, `"fatal"` is
 * returned as the conservative default.
 */
export function classifyError(error: unknown): ErrorCategory {
  if (error instanceof KuzushiError) {
    return error.category;
  }

  const message = errorMessage(error);

  for (const { pattern, category } of STATUS_PATTERNS) {
    if (pattern.test(message)) {
      return category;
    }
  }

  return "fatal";
}

/**
 * Wrap an unknown error as the appropriate `KuzushiError` subclass.
 *
 * If the error is already a `KuzushiError`, it is returned as-is.
 */
export function wrapError(error: unknown): KuzushiError {
  if (error instanceof KuzushiError) {
    return error;
  }

  const category = classifyError(error);
  const message = errorMessage(error);
  const opts = { cause: error };

  switch (category) {
    case "transient":
      return new TransientError(message, opts);
    case "rate_limit":
      return new RateLimitError(message, opts);
    case "validation":
      return new ValidationError(message, opts);
    case "auth":
      return new AuthError(message, opts);
    case "budget":
      return new BudgetError(message, opts);
    case "fatal":
      return new FatalError(message, opts);
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    let msg = error.message;
    if (error.cause instanceof Error) msg += ` ${error.cause.message}`;
    return msg;
  }
  return String(error);
}

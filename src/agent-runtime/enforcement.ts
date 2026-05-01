/**
 * Central enforcement boundary for "no silent model fallback". The pi-ai
 * runtime adapter calls `enforceAgentQuery` before dispatching a provider
 * request, and `loadConfig` calls the same `validateModelOverride` helper
 * at startup so a misconfigured model fails before any LLM invocation.
 *
 * Allowed fallbacks (per project policy):
 *   - same-model transport retries (handled inside the adapter, model
 *     object is reused);
 *   - batch → sequential when the runtime preserves the same model
 *     (`src/agent-runtime/execution.ts` does this);
 *   - informational stale-model warnings (no rewrite);
 *   - backend defaults only when the operator did not configure a model
 *     at all (kuzushi's config-loader always populates `config.model`,
 *     so reaching a hardcoded constant means we silently overrode the
 *     operator's choice — the enforcement here is what catches that);
 *   - deterministic non-LLM fallback that is clearly labeled.
 *
 * Forbidden behaviors caught here:
 *   - empty/missing model substituted with a backend default;
 *   - model that doesn't parse as `provider:modelId`;
 *   - `fallbackModel` plumbed through without explicit operator consent.
 */

import { validateModelOverride } from "./model-validation.js";

export interface EnforceAgentQueryInput {
  /** Concrete runtime id, e.g. "pi-ai". Used in error messages. */
  runtimeId: string;
  /** Operator-resolved model — must be a non-empty `provider:modelId`. */
  model: string | undefined;
  /** Optional automated-failover model. Forbidden unless `fallbackConsent` is true. */
  fallbackModel: string | undefined;
  /**
   * `true` only when the operator explicitly opted into automated failover for
   * this call (per-options `consentToModelFallback: true` or the global env
   * `KUZUSHI_ALLOW_MODEL_FALLBACK=1`).
   */
  fallbackConsent: boolean;
  /** Logical call site, e.g. "pi-ai.query", used in error messages. */
  callsite: string;
}

export class KuzushiSilentFallbackError extends Error {
  readonly code = "KUZUSHI_SILENT_FALLBACK" as const;

  constructor(message: string) {
    super(message);
    this.name = "KuzushiSilentFallbackError";
  }
}

/**
 * Throw a {@link KuzushiSilentFallbackError} if any policy rule is violated.
 * Returns void on success so callers can use it as a one-line guard.
 */
export function enforceAgentQuery(input: EnforceAgentQueryInput): void {
  const { runtimeId, model, fallbackModel, fallbackConsent, callsite } = input;

  if (typeof model !== "string" || model.trim() === "") {
    throw new KuzushiSilentFallbackError(
      `${callsite}: model is required. Kuzushi will not silently substitute a default model. ` +
        `Pass an operator-configured model (e.g. via ctx.config.model) or run /model use <provider>:<model>.`,
    );
  }

  const validationError = validateModelOverride(model);
  if (validationError) {
    throw new KuzushiSilentFallbackError(
      `${callsite}: model "${model}" is not valid for runtime "${runtimeId}" (${validationError}). ` +
        `Choose a compatible model or run /model edit to change the available pool.`,
    );
  }

  if (typeof fallbackModel === "string" && fallbackModel.trim() !== "" && !fallbackConsent) {
    throw new KuzushiSilentFallbackError(
      `${callsite}: fallbackModel ("${fallbackModel}") was supplied without operator consent. ` +
        `Kuzushi will not silently switch models. ` +
        `Set KUZUSHI_ALLOW_MODEL_FALLBACK=1 (or pass consentToModelFallback: true) ` +
        `to opt this call site into automated failover.`,
    );
  }
}

/**
 * Resolve the per-call fallback consent flag. Centralized so every adapter
 * checks the same env var + per-options precedence.
 */
export function resolveFallbackConsent(consentToModelFallback: boolean | undefined): boolean {
  if (consentToModelFallback === true) return true;
  if (process.env.KUZUSHI_ALLOW_MODEL_FALLBACK === "1") return true;
  return false;
}

/**
 * Central enforcement boundary for "no silent model/provider/runtime
 * fallback". Every concrete `AgentRuntime` adapter (claude / pi-ai / codex)
 * calls `enforceAgentQuery` before dispatching a provider request, and
 * `loadConfig` calls the same `validateModelOverride` helper at startup so
 * incompatible runtime/model pairs fail before any LLM invocation.
 *
 * Allowed fallbacks (per project policy):
 *   - same-model transport retries (handled inside each adapter, model
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
 *   - operator-configured model that is incompatible with the chosen
 *     runtime (e.g. `agentRuntimeBackend=codex` + `model=anthropic:...`);
 *   - `fallbackModel` plumbed through without explicit operator consent.
 */

import type { AgentRuntimeBackend } from "../contracts.js";
import { validateModelOverride } from "./model-validation.js";

export interface EnforceAgentQueryInput {
  /** Concrete runtime id, e.g. "claude" / "pi-ai" / "codex". Used in error messages. */
  runtimeId: string;
  /** The configured backend the runtime was built for. */
  backend: AgentRuntimeBackend;
  /** Operator-resolved model — must be non-empty. */
  model: string | undefined;
  /** Optional automated-failover model. Forbidden unless `fallbackConsent` is true. */
  fallbackModel: string | undefined;
  /**
   * `true` only when the operator explicitly opted into automated failover for
   * this call (per-options `consentToModelFallback: true` or the global env
   * `KUZUSHI_ALLOW_MODEL_FALLBACK=1`).
   */
  fallbackConsent: boolean;
  /** Logical call site, e.g. "claude.query", used in error messages. */
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
  const { runtimeId, backend, model, fallbackModel, fallbackConsent, callsite } = input;

  if (typeof model !== "string" || model.trim() === "") {
    throw new KuzushiSilentFallbackError(
      `${callsite}: model is required. Kuzushi will not silently substitute a default model. ` +
        `Pass an operator-configured model (e.g. via ctx.config.model) or run /provider <provider>:<model>.`,
    );
  }

  const validationError = validateModelOverride(backend, model);
  if (validationError) {
    throw new KuzushiSilentFallbackError(
      `${callsite}: model "${model}" is not compatible with runtime "${runtimeId}" (${validationError}). ` +
        `Kuzushi will not silently switch runtimes or providers. ` +
        `Choose a compatible model or run /backend <id> to switch backends.`,
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

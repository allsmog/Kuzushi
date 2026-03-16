/**
 * Model fallback chain: automatic failover to alternate models
 * when the primary model consistently fails with non-transient errors.
 */

export interface FallbackChain {
  primary: string;
  fallbacks: string[];
  cooldownMs: number;
}

interface ModelFailureState {
  lastFailure: number; // Date.now()
  consecutiveFailures: number;
}

/** Threshold of consecutive non-transient failures before cooldown. */
const FAILURE_THRESHOLD = 3;
const DEFAULT_COOLDOWN_MS = 60_000;

/** Non-transient error categories that trigger fallback. */
const FALLBACK_CATEGORIES = new Set(["auth", "budget", "fatal"]);

export class ModelFallbackManager {
  private readonly failures = new Map<string, ModelFailureState>();
  private onFallback?: (from: string, to: string) => void;

  constructor(onFallback?: (from: string, to: string) => void) {
    this.onFallback = onFallback;
  }

  /**
   * Select the best available model from a fallback chain.
   * Skips models that are in cooldown.
   */
  selectModel(chain: FallbackChain): string {
    const cooldownMs = chain.cooldownMs || DEFAULT_COOLDOWN_MS;

    if (!this.isInCooldown(chain.primary, cooldownMs)) {
      return chain.primary;
    }

    for (const fallback of chain.fallbacks) {
      if (!this.isInCooldown(fallback, cooldownMs)) {
        this.onFallback?.(chain.primary, fallback);
        return fallback;
      }
    }

    // All models in cooldown — try primary anyway (best effort).
    return chain.primary;
  }

  /**
   * Record a non-transient failure for a model.
   * After FAILURE_THRESHOLD consecutive failures, the model enters cooldown.
   */
  recordFailure(model: string, errorCategory: string): void {
    if (!FALLBACK_CATEGORIES.has(errorCategory)) return;

    const state = this.failures.get(model) ?? {
      lastFailure: 0,
      consecutiveFailures: 0,
    };

    state.consecutiveFailures += 1;
    state.lastFailure = Date.now();
    this.failures.set(model, state);
  }

  /** Record a success for a model, resetting its failure counter. */
  recordSuccess(model: string): void {
    this.failures.delete(model);
  }

  /** Build a FallbackChain from config. */
  static buildChain(
    primary: string,
    fallbacks?: string[],
    cooldownMs?: number,
  ): FallbackChain {
    return {
      primary,
      fallbacks: fallbacks ?? [],
      cooldownMs: cooldownMs ?? DEFAULT_COOLDOWN_MS,
    };
  }

  private isInCooldown(model: string, cooldownMs: number): boolean {
    const state = this.failures.get(model);
    if (!state) return false;

    if (state.consecutiveFailures < FAILURE_THRESHOLD) return false;

    const elapsed = Date.now() - state.lastFailure;
    if (elapsed >= cooldownMs) {
      // Cooldown expired — reset and allow retry.
      this.failures.delete(model);
      return false;
    }

    return true;
  }
}

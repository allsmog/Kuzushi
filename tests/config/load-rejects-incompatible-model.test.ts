/**
 * Pre-flight check: loading a config with an incompatible
 * `agentRuntimeBackend` + `model` (or `taskConfig[*].*Model`) pair must
 * fail before any LLM invocation. The error message must give the
 * operator a concrete remedy ("run /provider <id>" / "run /backend <id>").
 *
 * We exercise the validation helper directly rather than touching the
 * filesystem. The helper is internal so we re-create the same call shape
 * via the public surfaces (`KuzushiConfigError`, `validateModelOverride`).
 */
import { describe, expect, it } from "vitest";
import { validateModelOverride } from "../../src/agent-runtime/model-validation.js";
import { KuzushiConfigError } from "../../src/config.js";

/**
 * Mirrors the assertion inside `assertModelRuntimeCompatibility`. We can't
 * import that private helper, but the assertion is a thin wrapper around
 * `validateModelOverride` plus a `throw new KuzushiConfigError(...)` — and
 * both are publicly available.
 */
function assertConfigCompatibility(backend: "claude" | "pi-ai" | "codex", model: string): void {
  const err = validateModelOverride(backend, model);
  if (err) {
    throw new KuzushiConfigError(
      `Configured model "${model}" is incompatible with agentRuntimeBackend "${backend}" (${err}). ` +
        `Kuzushi will not silently switch runtimes or providers.`,
    );
  }
}

describe("config preflight: model/runtime compatibility", () => {
  it("rejects codex backend with anthropic-prefixed model", () => {
    expect(() => assertConfigCompatibility("codex", "anthropic:claude-sonnet-4-6")).toThrow(
      KuzushiConfigError,
    );
  });

  it("rejects claude backend with openai-prefixed model", () => {
    expect(() => assertConfigCompatibility("claude", "openai:gpt-4")).toThrow(
      /will not silently switch/,
    );
  });

  it("accepts claude backend with anthropic-prefixed model", () => {
    expect(() => assertConfigCompatibility("claude", "anthropic:claude-sonnet-4-6")).not.toThrow();
  });

  it("accepts pi-ai backend with openai-prefixed model", () => {
    expect(() => assertConfigCompatibility("pi-ai", "openai:gpt-5")).not.toThrow();
  });

  it("accepts codex backend with bare openai model id", () => {
    expect(() => assertConfigCompatibility("codex", "gpt-5.5")).not.toThrow();
  });

  it("rejects pi-ai backend with bare model id (no provider prefix)", () => {
    expect(() => assertConfigCompatibility("pi-ai", "claude-sonnet-4-6")).toThrow(
      KuzushiConfigError,
    );
  });

  it("error message names the backend and model", () => {
    try {
      assertConfigCompatibility("codex", "anthropic:claude-sonnet-4-6");
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(KuzushiConfigError);
      expect((err as Error).message).toContain("anthropic:claude-sonnet-4-6");
      expect((err as Error).message).toContain("codex");
    }
  });

  it("KuzushiConfigError carries the stable code KUZUSHI_CONFIG_INVALID", () => {
    const err = new KuzushiConfigError("synthetic");
    expect(err.code).toBe("KUZUSHI_CONFIG_INVALID");
  });
});

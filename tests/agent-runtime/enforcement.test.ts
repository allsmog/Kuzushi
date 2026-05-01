import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  enforceAgentQuery,
  KuzushiSilentFallbackError,
  resolveFallbackConsent,
} from "../../src/agent-runtime/enforcement.js";

describe("enforceAgentQuery", () => {
  it("rejects an empty model with KuzushiSilentFallbackError", () => {
    expect(() =>
      enforceAgentQuery({
        runtimeId: "pi-ai",
        model: "",
        fallbackModel: undefined,
        fallbackConsent: false,
        callsite: "test.empty",
      }),
    ).toThrow(KuzushiSilentFallbackError);
  });

  it("rejects an undefined model", () => {
    expect(() =>
      enforceAgentQuery({
        runtimeId: "pi-ai",
        model: undefined,
        fallbackModel: undefined,
        fallbackConsent: false,
        callsite: "test.undef",
      }),
    ).toThrow(/model is required/);
  });

  it("rejects whitespace-only model", () => {
    expect(() =>
      enforceAgentQuery({
        runtimeId: "pi-ai",
        model: "   ",
        fallbackModel: undefined,
        fallbackConsent: false,
        callsite: "test.whitespace",
      }),
    ).toThrow(/model is required/);
  });

  it("rejects bare model id without provider prefix", () => {
    expect(() =>
      enforceAgentQuery({
        runtimeId: "pi-ai",
        model: "claude-sonnet-4-6",
        fallbackModel: undefined,
        fallbackConsent: false,
        callsite: "test.pi-ai.bare",
      }),
    ).toThrow(/not valid for runtime "pi-ai"/);
  });

  it("accepts compatible provider-prefixed model", () => {
    expect(() =>
      enforceAgentQuery({
        runtimeId: "pi-ai",
        model: "anthropic:claude-sonnet-4-6",
        fallbackModel: undefined,
        fallbackConsent: false,
        callsite: "test.pi-ai.ok",
      }),
    ).not.toThrow();
  });

  it("rejects fallbackModel without consent", () => {
    expect(() =>
      enforceAgentQuery({
        runtimeId: "pi-ai",
        model: "anthropic:claude-sonnet-4-6",
        fallbackModel: "anthropic:claude-haiku-4-5",
        fallbackConsent: false,
        callsite: "test.fallback.no-consent",
      }),
    ).toThrow(/will not silently switch models/);
  });

  it("rejects fallbackModel error message names the fallback model", () => {
    try {
      enforceAgentQuery({
        runtimeId: "pi-ai",
        model: "anthropic:claude-sonnet-4-6",
        fallbackModel: "anthropic:claude-haiku-4-5",
        fallbackConsent: false,
        callsite: "test.fallback.message",
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(KuzushiSilentFallbackError);
      expect((err as Error).message).toMatch(/anthropic:claude-haiku-4-5/);
      expect((err as Error).message).toMatch(/KUZUSHI_ALLOW_MODEL_FALLBACK/);
    }
  });

  it("accepts fallbackModel when consent is true", () => {
    expect(() =>
      enforceAgentQuery({
        runtimeId: "pi-ai",
        model: "anthropic:claude-sonnet-4-6",
        fallbackModel: "anthropic:claude-haiku-4-5",
        fallbackConsent: true,
        callsite: "test.fallback.consent",
      }),
    ).not.toThrow();
  });

  it("treats empty fallbackModel as no fallback request", () => {
    expect(() =>
      enforceAgentQuery({
        runtimeId: "pi-ai",
        model: "anthropic:claude-sonnet-4-6",
        fallbackModel: "",
        fallbackConsent: false,
        callsite: "test.fallback.empty",
      }),
    ).not.toThrow();
  });

  it("error message mentions callsite for debuggability", () => {
    try {
      enforceAgentQuery({
        runtimeId: "pi-ai",
        model: "",
        fallbackModel: undefined,
        fallbackConsent: false,
        callsite: "pi-ai.queryBatch",
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Error).message).toMatch(/^pi-ai\.queryBatch:/);
    }
  });
});

describe("resolveFallbackConsent", () => {
  const originalEnv = process.env.KUZUSHI_ALLOW_MODEL_FALLBACK;

  beforeEach(() => {
    delete process.env.KUZUSHI_ALLOW_MODEL_FALLBACK;
  });

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.KUZUSHI_ALLOW_MODEL_FALLBACK;
    } else {
      process.env.KUZUSHI_ALLOW_MODEL_FALLBACK = originalEnv;
    }
  });

  it("defaults to false", () => {
    expect(resolveFallbackConsent(undefined)).toBe(false);
  });

  it("returns true when option is true", () => {
    expect(resolveFallbackConsent(true)).toBe(true);
  });

  it("returns true when KUZUSHI_ALLOW_MODEL_FALLBACK=1", () => {
    process.env.KUZUSHI_ALLOW_MODEL_FALLBACK = "1";
    expect(resolveFallbackConsent(undefined)).toBe(true);
    expect(resolveFallbackConsent(false)).toBe(true);
  });

  it("ignores other env values like 'true' (only '1' opts in)", () => {
    process.env.KUZUSHI_ALLOW_MODEL_FALLBACK = "true";
    expect(resolveFallbackConsent(undefined)).toBe(false);
  });
});

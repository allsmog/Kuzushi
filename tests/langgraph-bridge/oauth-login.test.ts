import { afterEach, describe, expect, it, vi } from "vitest";
import {
  buildAuthorizeUrl,
  // @ts-expect-error -- plain .mjs bridge module without type declarations
  credentialFromTokenResponse,
  exchangeAuthorizationCode,
  mergeCredentialBag,
  parseOauthLoginArgs,
  parsePastedCode,
  pkcePair,
  resolveProviderConfig,
  // @ts-expect-error -- plain .mjs bridge module without type declarations
} from "../../scripts/langgraph-bridge/oauth-login.mjs";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("parseOauthLoginArgs", () => {
  it("extracts provider and method after the flag", () => {
    expect(parseOauthLoginArgs(["--oauth-login", "openai", "browser"])).toEqual({
      providerArg: "openai",
      method: "browser",
    });
  });

  it("returns undefined when the flag is absent", () => {
    expect(parseOauthLoginArgs(["--ping"])).toBeUndefined();
  });

  it("returns undefined when the provider argument is missing", () => {
    expect(parseOauthLoginArgs(["--oauth-login"])).toBeUndefined();
  });
});

describe("resolveProviderConfig", () => {
  it("maps the openai alias to the codex storage key", () => {
    expect(resolveProviderConfig("openai")?.storageKey).toBe("openai-codex");
  });

  it("resolves anthropic directly", () => {
    expect(resolveProviderConfig("anthropic")?.storageKey).toBe("anthropic");
  });

  it("rejects unknown providers", () => {
    expect(resolveProviderConfig("github-copilot")).toBeUndefined();
  });
});

describe("pkcePair", () => {
  it("derives a base64url S256 challenge from a fresh verifier", () => {
    const a = pkcePair();
    const b = pkcePair();
    expect(a.verifier).not.toEqual(b.verifier);
    expect(a.challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(a.challenge).not.toContain("=");
  });
});

describe("buildAuthorizeUrl", () => {
  it("encodes PKCE, scope, and provider-specific extra params", () => {
    const cfg = resolveProviderConfig("anthropic");
    const url = new URL(
      buildAuthorizeUrl(cfg, {
        challenge: "chal",
        state: "st",
        redirectUri: cfg.redirectUri,
      }),
    );
    expect(url.searchParams.get("client_id")).toBe(cfg.clientId);
    expect(url.searchParams.get("code_challenge")).toBe("chal");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("state")).toBe("st");
    expect(url.searchParams.get("code")).toBe("true");
  });
});

describe("parsePastedCode", () => {
  it("parses the bare code", () => {
    expect(parsePastedCode("abc123")).toEqual({ code: "abc123", state: undefined });
  });

  it("splits the Claude code#state form", () => {
    expect(parsePastedCode("abc123#xyz")).toEqual({ code: "abc123", state: "xyz" });
  });

  it("extracts code and state from a full redirect URL", () => {
    expect(parsePastedCode("http://localhost:1455/auth/callback?code=abc&state=xyz")).toEqual({
      code: "abc",
      state: "xyz",
    });
  });

  it("returns undefined for empty input", () => {
    expect(parsePastedCode("   ")).toBeUndefined();
  });

  it("returns undefined for a URL without a code", () => {
    expect(parsePastedCode("http://localhost:1455/auth/callback?error=denied")).toBeUndefined();
  });
});

describe("credentialFromTokenResponse", () => {
  it("computes an absolute expiry and keeps the prior refresh when absent", () => {
    const credential = credentialFromTokenResponse(
      { access_token: "at", expires_in: 100 },
      "prior-refresh",
      1_000,
    );
    expect(credential).toEqual({ access: "at", refresh: "prior-refresh", expires: 101_000 });
  });

  it("prefers a freshly issued refresh token", () => {
    const credential = credentialFromTokenResponse(
      { access_token: "at", refresh_token: "rt", expires_in: 60 },
      "prior-refresh",
      0,
    );
    expect(credential.refresh).toBe("rt");
  });

  it("throws when no access token is present", () => {
    expect(() => credentialFromTokenResponse({ refresh_token: "rt" }, undefined)).toThrow(
      /access_token/,
    );
  });
});

describe("mergeCredentialBag", () => {
  it("sets the provider entry without disturbing other providers", () => {
    const bag = { anthropic: { access: "keep" } };
    const merged = mergeCredentialBag(bag, "openai-codex", { access: "new" });
    expect(merged).toEqual({
      anthropic: { access: "keep" },
      "openai-codex": { access: "new" },
    });
    expect(bag["openai-codex"]).toBeUndefined();
  });
});

describe("OAuth token exchange error redaction", () => {
  it("does not expose a non-2xx token response body", async () => {
    const sentinel = "raw-oauth-token-provider-body-sentinel";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(`{"error":"${sentinel}"}`, { status: 400 }) as never,
    );
    const cfg = resolveProviderConfig("anthropic");

    const error = await exchangeAuthorizationCode(cfg, {
      code: "code",
      verifier: "verifier",
      redirectUri: cfg.redirectUri,
    }).catch((failure: unknown) => failure);

    expect(String(error)).toBe("BridgePublicError: Provider rejected the request (HTTP 400).");
    expect(JSON.stringify(error, Object.getOwnPropertyNames(error))).not.toContain(sentinel);
  });
});

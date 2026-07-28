import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import process from "node:process";
import test from "node:test";
import {
  buildAuthorizeUrl,
  credentialFromTokenResponse,
  exchangeAuthorizationCode,
  mergeCredentialBag,
  OAUTH_PROVIDERS,
  parseOauthLoginArgs,
  parsePastedCode,
  pkcePair,
  resolveProviderConfig,
  runOauthLogin,
} from "./oauth-login.mjs";

function base64url(buffer) {
  return buffer.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function installFetchStub(t, implementation) {
  const original = globalThis.fetch;
  globalThis.fetch = implementation;
  t.after(() => {
    globalThis.fetch = original;
  });
}

test("OAuth login arguments require a provider after the flag", () => {
  assert.equal(parseOauthLoginArgs(["node", "bridge.mjs"]), undefined);
  assert.equal(parseOauthLoginArgs(["--oauth-login"]), undefined);
  assert.deepEqual(parseOauthLoginArgs(["bridge", "--oauth-login", "openai"]), {
    providerArg: "openai",
    method: undefined,
  });
  assert.deepEqual(
    parseOauthLoginArgs(["bridge", "--oauth-login", "anthropic", "headless", "ignored"]),
    { providerArg: "anthropic", method: "headless" },
  );
});

test("OAuth provider aliases resolve case-insensitively to canonical configurations", () => {
  for (const alias of ["openai", " OPENAI-CODEX ", "Codex"]) {
    assert.equal(resolveProviderConfig(alias), OAUTH_PROVIDERS["openai-codex"]);
  }
  for (const alias of ["anthropic", " CLAUDE "]) {
    assert.equal(resolveProviderConfig(alias), OAUTH_PROVIDERS.anthropic);
  }
  assert.equal(resolveProviderConfig("unknown"), undefined);
  assert.equal(resolveProviderConfig(undefined), undefined);
});

test("PKCE pairs use base64url entropy and an S256 challenge", () => {
  const { verifier, challenge } = pkcePair();

  assert.match(verifier, /^[A-Za-z0-9_-]{86}$/);
  assert.match(challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(challenge, base64url(createHash("sha256").update(verifier).digest()));
  assert.equal(verifier.includes("="), false);
  assert.equal(challenge.includes("="), false);
});

test("authorization URLs carry fixed state and PKCE fields without leaking the verifier", () => {
  const cfg = {
    ...OAUTH_PROVIDERS.anthropic,
    authorizeUrl: "https://issuer.example/authorize?existing=preserved",
    extraAuthorizeParams: { audience: "kuzushi", code: "true" },
  };
  const url = new URL(
    buildAuthorizeUrl(cfg, {
      challenge: "fixed-challenge",
      state: "fixed-state",
      redirectUri: "https://client.example/callback",
    }),
  );

  assert.equal(url.origin, "https://issuer.example");
  assert.equal(url.pathname, "/authorize");
  assert.equal(url.searchParams.get("existing"), "preserved");
  assert.equal(url.searchParams.get("client_id"), cfg.clientId);
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("redirect_uri"), "https://client.example/callback");
  assert.equal(url.searchParams.get("scope"), cfg.scope);
  assert.equal(url.searchParams.get("code_challenge"), "fixed-challenge");
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.equal(url.searchParams.get("state"), "fixed-state");
  assert.equal(url.searchParams.get("audience"), "kuzushi");
  assert.equal(url.searchParams.get("code"), "true");
  assert.equal(url.searchParams.has("code_verifier"), false);
});

test("pasted authorization input accepts bare, hash-state, and redirect URL forms", () => {
  assert.deepEqual(parsePastedCode("  bare-code  "), {
    code: "bare-code",
    state: undefined,
  });
  assert.deepEqual(parsePastedCode("code-value#state-value"), {
    code: "code-value",
    state: "state-value",
  });
  assert.deepEqual(
    parsePastedCode("https://client.example/callback?code=encoded%2Fcode&state=state%20value"),
    { code: "encoded/code", state: "state value" },
  );
  assert.equal(parsePastedCode(""), undefined);
  assert.equal(parsePastedCode("https://client.example/callback?state=missing-code"), undefined);
  assert.equal(parsePastedCode("https://%"), undefined);
});

test("credentials require a non-empty access token and calculate expiry from a fixed clock", () => {
  const now = 1_700_000_000_000;
  assert.deepEqual(
    credentialFromTokenResponse(
      { access_token: " access ", refresh_token: " refresh ", expires_in: "120" },
      "prior-refresh",
      now,
    ),
    { access: "access", refresh: "refresh", expires: now + 120_000 },
  );
  assert.deepEqual(credentialFromTokenResponse({ access_token: "access" }, "prior", now), {
    access: "access",
    refresh: "prior",
    expires: now + 3_600_000,
  });
  assert.deepEqual(
    credentialFromTokenResponse(
      { access_token: "access", refresh_token: "  ", expires_in: 0 },
      "preserved",
      now,
    ),
    { access: "access", refresh: "preserved", expires: now + 1_000 },
  );

  for (const parsed of [undefined, {}, { access_token: " " }, { access_token: 42 }]) {
    assert.throws(
      () => credentialFromTokenResponse(parsed, undefined, now),
      /token response did not include an access_token/,
    );
  }
});

test("credential bag merge replaces one provider without mutating caller-owned values", () => {
  const existingAnthropic = Object.freeze({
    access: "anthropic-access",
    refresh: "anthropic-refresh",
    expires: 10,
  });
  const bag = Object.freeze({ anthropic: existingAnthropic, metadata: Object.freeze({ version: 1 }) });
  const credential = Object.freeze({
    access: "openai-access",
    refresh: "openai-refresh",
    expires: 20,
  });

  const merged = mergeCredentialBag(bag, "openai-codex", credential);

  assert.notEqual(merged, bag);
  assert.deepEqual(merged, {
    anthropic: existingAnthropic,
    metadata: bag.metadata,
    "openai-codex": credential,
  });
  assert.deepEqual(bag, { anthropic: existingAnthropic, metadata: { version: 1 } });
  assert.equal(merged.anthropic, existingAnthropic);
  assert.equal(merged["openai-codex"], credential);
});

test("authorization code exchange emits provider-specific bodies through a stubbed fetch", async (t) => {
  const calls = [];
  installFetchStub(t, async (url, init) => {
    calls.push({ url, init });
    return {
      ok: true,
      status: 200,
      text: async () => '{"access_token":"stubbed-token","expires_in":60}',
    };
  });

  const parameters = {
    code: "authorization-code",
    verifier: "pkce-verifier",
    redirectUri: "https://client.example/callback",
  };
  assert.deepEqual(await exchangeAuthorizationCode(OAUTH_PROVIDERS.anthropic, parameters), {
    access_token: "stubbed-token",
    expires_in: 60,
  });
  assert.deepEqual(await exchangeAuthorizationCode(OAUTH_PROVIDERS["openai-codex"], parameters), {
    access_token: "stubbed-token",
    expires_in: 60,
  });

  assert.equal(calls[0].url, OAUTH_PROVIDERS.anthropic.tokenUrl);
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers["content-type"], "application/json");
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    grant_type: "authorization_code",
    code: parameters.code,
    redirect_uri: parameters.redirectUri,
    client_id: OAUTH_PROVIDERS.anthropic.clientId,
    code_verifier: parameters.verifier,
  });

  assert.equal(calls[1].url, OAUTH_PROVIDERS["openai-codex"].tokenUrl);
  assert.equal(calls[1].init.headers["content-type"], "application/x-www-form-urlencoded");
  assert.deepEqual(Object.fromEntries(new URLSearchParams(calls[1].init.body)), {
    grant_type: "authorization_code",
    code: parameters.code,
    redirect_uri: parameters.redirectUri,
    client_id: OAUTH_PROVIDERS["openai-codex"].clientId,
    code_verifier: parameters.verifier,
  });
});

test("authorization code exchange validates HTTP status and JSON using a stubbed fetch", async (t) => {
  let response = { ok: false, status: 429, text: async () => "ignored" };
  installFetchStub(t, async () => response);
  const parameters = {
    code: "authorization-code",
    verifier: "pkce-verifier",
    redirectUri: OAUTH_PROVIDERS.anthropic.redirectUri,
  };

  await assert.rejects(
    () => exchangeAuthorizationCode(OAUTH_PROVIDERS.anthropic, parameters),
    (error) => error.errorClass === "rate_limited" && error.status === 429,
  );

  response = { ok: true, status: 200, text: async () => "not-json" };
  await assert.rejects(
    () => exchangeAuthorizationCode(OAUTH_PROVIDERS.anthropic, parameters),
    (error) => error.errorClass === "provider_response_invalid",
  );
});

test("unsupported OAuth login providers fail before interactive side effects", async () => {
  const writes = [];
  const originalWrite = process.stderr.write;
  process.stderr.write = (chunk) => {
    writes.push(String(chunk));
    return true;
  };

  let status;
  try {
    status = await runOauthLogin({ providerArg: "unsupported", method: "headless" });
  } finally {
    process.stderr.write = originalWrite;
  }

  assert.equal(status, 1);
  assert.deepEqual(writes, [
    'unsupported oauth provider "unsupported" (expected openai or anthropic)\n',
  ]);
});

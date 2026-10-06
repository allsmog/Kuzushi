import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { BridgePublicError } from "./errors.mjs";
import { modelForRequest, oauthAccessToken } from "./model.mjs";

function fixture(t, entry) {
  const root = mkdtempSync(path.join(tmpdir(), "kuzushi-oauth-readiness-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const credentials = path.join(root, "credentials.json");
  writeFileSync(credentials, JSON.stringify({ "openai-codex": entry }), { mode: 0o600 });
  return {
    root,
    credentials,
    request: {
      model: "openai-codex:gpt-6-luna",
      thinkingLevel: "low",
      oauthCredentialsPath: credentials,
      oauthAllowEnvToken: false,
      apiKey: "<fixture-unused-api-key>",
    },
  };
}

function authenticationError(error) {
  return error instanceof BridgePublicError && error.errorClass === "authentication";
}

test("an unexpired access-only credential keeps the exact OAuth model and reasoning", (t) => {
  const { request } = fixture(t, {
    access: "unexpired-access-fixture",
    expires: Date.now() + 600_000,
    accountId: "fixture-account",
  });
  const model = modelForRequest(request);
  assert.equal(model.modelName, "gpt-6-luna");
  assert.equal(model.request.oauthAccountId, "fixture-account");
  assert.deepEqual(model.body([]).reasoning, { effort: "low" });
});

test("an expired access-only credential fails before client construction without API fallback", (t) => {
  const { request } = fixture(t, { access: "expired-access-fixture", expires: Date.now() - 1 });
  assert.throws(() => modelForRequest(request), authenticationError);
  assert.throws(() => oauthAccessToken(request, "openai-codex"), authenticationError);
});

test("missing, malformed and non-finite stored expiry cannot authenticate", (t) => {
  for (const expires of [undefined, null, "99999999999999", 0, Infinity, NaN]) {
    const { request } = fixture(t, { access: "invalid-expiry-fixture", expires });
    assert.throws(() => modelForRequest(request), authenticationError);
  }
});

test("failed refresh retains the stored credential and refuses expired inference", (t) => {
  const { root, credentials, request } = fixture(t, {
    access: "expired-access-fixture",
    refresh: "failed-refresh-fixture",
    expires: 1,
  });
  const marker = path.join(root, "requests.jsonl");
  const hook = path.join(root, "auth-transport-fixture.mjs");
  writeFileSync(hook, `
    import { appendFileSync } from 'node:fs';
    globalThis.fetch = async (url) => {
      if (url !== 'https://auth.openai.com/oauth/token') throw new Error('Unexpected network request');
      appendFileSync(${JSON.stringify(marker)}, JSON.stringify({endpoint:'oauth/token'})+'\\n');
      return new Response(JSON.stringify({error:'invalid_grant'}), {status:400});
    };
  `);
  const priorOptions = process.env.NODE_OPTIONS;
  const before = readFileSync(credentials, "utf8");
  try {
    process.env.NODE_OPTIONS = `--import=${pathToFileURL(hook).href}`;
    assert.throws(() => modelForRequest(request), authenticationError);
  } finally {
    if (priorOptions === undefined) delete process.env.NODE_OPTIONS;
    else process.env.NODE_OPTIONS = priorOptions;
  }
  assert.equal(readFileSync(credentials, "utf8"), before);
  assert.deepEqual(readFileSync(marker, "utf8").trim().split("\n").map(JSON.parse), [
    { endpoint: "oauth/token" },
  ]);
});

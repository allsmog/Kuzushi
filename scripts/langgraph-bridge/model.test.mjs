import assert from "node:assert/strict";
import test from "node:test";
import { AIMessage } from "@langchain/core/messages";
import {
  bridgeQueryResult,
  isTruncatedStopReason,
  openAiAccountIdFromJwt,
  openAiCredentialFromRefreshResponse,
} from "./model.mjs";
import { oauthModelForRequest, openAiOauthHeaders } from "./oauth-models.mjs";

test("forced conclusions remain structured but are marked truncated", () => {
  const result = bridgeQueryResult(
    [new AIMessage('{"verdict":"confirmed"}')],
    "forced_conclusion",
  );

  assert.deepEqual(result.structured, { verdict: "confirmed" });
  assert.equal(result.stopReason, "forced_conclusion");
  assert.equal(result.truncated, true);
});

test("natural completion is not marked truncated", () => {
  assert.equal(isTruncatedStopReason(undefined), false);
  assert.equal(isTruncatedStopReason("stop"), false);
});

test("OpenAI refresh response rotates credentials and retains the account identity", () => {
  const idToken = jwt({ chatgpt_account_id: "account-123" });
  const credential = openAiCredentialFromRefreshResponse(
    JSON.stringify({
      access_token: jwt({ sub: "operator" }),
      refresh_token: "rotated-refresh",
      id_token: idToken,
      expires_in: 900,
    }),
    "prior-refresh",
    1_000,
  );

  assert.deepEqual(credential, {
    access: jwt({ sub: "operator" }),
    refresh: "rotated-refresh",
    expires: 901_000,
    accountId: "account-123",
  });
});

test("OpenAI refresh response preserves a rotating refresh token when omitted", () => {
  const credential = openAiCredentialFromRefreshResponse(
    JSON.stringify({ access_token: jwt({ organizations: [{ id: "org-456" }] }), expires_in: 60 }),
    "prior-refresh",
    2_000,
  );

  assert.equal(credential.refresh, "prior-refresh");
  assert.equal(credential.accountId, "org-456");
  assert.equal(credential.expires, 62_000);
});

test("OpenAI account identity accepts the namespaced claim", () => {
  const token = jwt({
    "https://api.openai.com/auth": { chatgpt_account_id: "account-namespaced" },
  });
  assert.equal(openAiAccountIdFromJwt(token), "account-namespaced");
  assert.equal(openAiAccountIdFromJwt("not-a-jwt"), undefined);
});

test("OpenAI OAuth requests include the account header only when known", () => {
  assert.deepEqual(openAiOauthHeaders("access", "account-123"), {
    authorization: "Bearer access",
    "content-type": "application/json",
    "ChatGPT-Account-Id": "account-123",
  });
  assert.deepEqual(openAiOauthHeaders("access", undefined), {
    authorization: "Bearer access",
    "content-type": "application/json",
  });
});

test("OpenAI OAuth rejects malformed tool-call arguments instead of defaulting to an empty object", async (t) => {
  t.mock.method(globalThis, "fetch", async () => oauthSseResponse('{"path":'));
  const model = oauthModelForRequest("openai-codex", "gpt-test", "access", {});

  await assertInvalidProviderResponse(() => model.invoke([]));
});

test("OpenAI OAuth requires tool-call arguments to decode to an object", async (t) => {
  let argumentsJson = "null";
  t.mock.method(globalThis, "fetch", async () => oauthSseResponse(argumentsJson));
  const model = oauthModelForRequest("openai-codex", "gpt-test", "access", {});

  for (const invalid of ["null", "[]", '"path"', "1", "true", ""]) {
    argumentsJson = invalid;
    await assertInvalidProviderResponse(() => model.invoke([]));
  }
});

test("OpenAI OAuth preserves a valid empty-object tool call", async (t) => {
  t.mock.method(globalThis, "fetch", async () => oauthSseResponse("{}"));
  const model = oauthModelForRequest("openai-codex", "gpt-test", "access", {});

  const message = await model.invoke([]);

  assert.equal(message.tool_calls.length, 1);
  assert.equal(message.tool_calls[0].name, "Read");
  assert.deepEqual(message.tool_calls[0].args, {});
});

async function assertInvalidProviderResponse(invoke) {
  await assert.rejects(invoke, (error) => {
    assert.equal(error?.name, "BridgePublicError");
    assert.equal(error?.errorClass, "provider_response_invalid");
    assert.equal(error?.message, "Provider returned an invalid response.");
    return true;
  });
}

function oauthSseResponse(argumentsJson) {
  const event = {
    type: "response.output_item.done",
    item: {
      type: "function_call",
      call_id: "call-1",
      name: "Read",
      arguments: argumentsJson,
    },
  };
  return {
    ok: true,
    text: async () => `data: ${JSON.stringify(event)}\n\n`,
  };
}

function jwt(claims) {
  const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  return `${header}.${payload}.signature`;
}

import assert from "node:assert/strict";
import test from "node:test";
import { AIMessage, HumanMessage, ToolMessage } from "@langchain/core/messages";
import { BridgePublicError } from "./errors.mjs";
import {
  bridgeQueryResult,
  credentialForRequest,
  humanMessageForRequest,
  isTruncatedStopReason,
  loopOpeningMessageForRequest,
  modelContinuationDecision,
  openAiAccountIdFromJwt,
  openAiCredentialFromRefreshResponse,
  promptCacheSplit,
  spendForStop,
  TOOL_RESULT_MAX_CHARS,
  toolMessageForOutput,
  turnBudgetNotice,
  usageFromMessages,
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

test("API model credentials fail as typed authentication before SDK invocation", () => {
  assert.throws(
    () =>
      credentialForRequest(
        { apiKeyEnv: "KUZUSHI_TEST_DEFINITELY_MISSING_OPENAI_KEY" },
        "openai",
        "OPENAI_API_KEY",
      ),
    (error) => error instanceof BridgePublicError && error.errorClass === "authentication",
  );
  assert.equal(
    credentialForRequest({ apiKey: "test-present" }, "openai", "OPENAI_API_KEY"),
    "test-present",
  );
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

test("Anthropic OAuth requires a provider content array", async (t) => {
  let payload = {};
  t.mock.method(globalThis, "fetch", async () => anthropicOauthResponse(payload));
  const model = oauthModelForRequest("anthropic", "claude-test", "access", {});

  for (const invalid of [null, [], {}, { content: null }, { content: {} }, { content: "text" }]) {
    payload = invalid;
    await assertInvalidProviderResponse(() => model.invoke([]));
  }
});

test("Anthropic OAuth requires provider tool-use identities", async (t) => {
  let block = { type: "tool_use", id: undefined, name: "read_file", input: {} };
  t.mock.method(globalThis, "fetch", async () => anthropicOauthResponse({ content: [block] }));
  const model = oauthModelForRequest("anthropic", "claude-test", "access", {});

  for (const invalid of [undefined, "", "   ", 42]) {
    block = { type: "tool_use", id: invalid, name: "read_file", input: {} };
    await assertInvalidProviderResponse(() => model.invoke([]));
  }
  for (const invalid of [undefined, "", "   ", 42]) {
    block = { type: "tool_use", id: "tool-1", name: invalid, input: {} };
    await assertInvalidProviderResponse(() => model.invoke([]));
  }
});

test("Anthropic OAuth requires tool input to be an explicit object", async (t) => {
  let input;
  t.mock.method(globalThis, "fetch", async () =>
    anthropicOauthResponse({
      content: [{ type: "tool_use", id: "tool-1", name: "read_file", input }],
    }),
  );
  const model = oauthModelForRequest("anthropic", "claude-test", "access", {});

  for (const invalid of [undefined, null, [], "path", 1, true]) {
    input = invalid;
    await assertInvalidProviderResponse(() => model.invoke([]));
  }
});

test("Anthropic OAuth preserves valid tool-use identity and empty-object input", async (t) => {
  t.mock.method(globalThis, "fetch", async () =>
    anthropicOauthResponse({
      content: [{ type: "tool_use", id: "tool-provider-1", name: "read_file", input: {} }],
      stop_reason: "tool_use",
    }),
  );
  const model = oauthModelForRequest("anthropic", "claude-test", "access", {});

  const message = await model.invoke([]);

  assert.equal(message.tool_calls.length, 1);
  assert.equal(message.tool_calls[0].id, "tool-provider-1");
  assert.equal(message.tool_calls[0].name, "read_file");
  assert.deepEqual(message.tool_calls[0].args, {});
});

test("Anthropic OAuth leaves absent usage unreported instead of inventing zero tokens", async (t) => {
  t.mock.method(globalThis, "fetch", async () =>
    anthropicOauthResponse({ content: [{ type: "text", text: "done" }], stop_reason: "end_turn" }),
  );
  const model = oauthModelForRequest("anthropic", "claude-test", "access", {});

  const result = bridgeQueryResult([await model.invoke([])]);

  assert.equal(result.input_tokens, undefined);
  assert.equal(result.output_tokens, undefined);
  assert.equal(result.input_reported_calls, 0);
  assert.equal(result.output_reported_calls, 0);
});

test("Anthropic OAuth rejects malformed usage instead of coercing it to zero", async (t) => {
  t.mock.method(globalThis, "fetch", async () =>
    anthropicOauthResponse({
      content: [{ type: "text", text: "done" }],
      usage: { input_tokens: "not-a-number", output_tokens: 2 },
    }),
  );
  const model = oauthModelForRequest("anthropic", "claude-test", "access", {});

  await assertInvalidProviderResponse(() => model.invoke([]));
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

test("OpenAI OAuth requires the provider call_id instead of substituting another identity", async (t) => {
  let itemOverrides = { call_id: undefined, id: "item-only" };
  t.mock.method(globalThis, "fetch", async () => oauthSseResponse("{}", itemOverrides));
  const model = oauthModelForRequest("openai-codex", "gpt-test", "access", {});

  for (const invalid of [
    { call_id: undefined, id: "item-only" },
    { call_id: undefined },
    { call_id: "" },
    { call_id: "   " },
    { call_id: 42 },
  ]) {
    itemOverrides = invalid;
    await assertInvalidProviderResponse(() => model.invoke([]));
  }
});

test("OpenAI OAuth requires a nonempty provider tool name", async (t) => {
  let itemOverrides = { name: undefined };
  t.mock.method(globalThis, "fetch", async () => oauthSseResponse("{}", itemOverrides));
  const model = oauthModelForRequest("openai-codex", "gpt-test", "access", {});

  for (const invalid of [{ name: undefined }, { name: "" }, { name: "   " }, { name: 42 }]) {
    itemOverrides = invalid;
    await assertInvalidProviderResponse(() => model.invoke([]));
  }
});

test("OpenAI OAuth preserves a valid empty-object tool call", async (t) => {
  t.mock.method(globalThis, "fetch", async () => oauthSseResponse("{}"));
  const model = oauthModelForRequest("openai-codex", "gpt-test", "access", {});

  const message = await model.invoke([]);

  assert.equal(message.tool_calls.length, 1);
  assert.equal(message.tool_calls[0].id, "call-1");
  assert.equal(message.tool_calls[0].name, "Read");
  assert.deepEqual(message.tool_calls[0].args, {});
});

test("OpenAI OAuth leaves absent usage unreported instead of inventing zero tokens", async (t) => {
  const event = JSON.stringify({ type: "response.output_text.done", text: "complete" });
  t.mock.method(globalThis, "fetch", async () => oauthRawSseResponse(`data: ${event}\n\n`));
  const model = oauthModelForRequest("openai-codex", "gpt-test", "access", {});

  const result = bridgeQueryResult([await model.invoke([])]);

  assert.equal(result.input_tokens, undefined);
  assert.equal(result.output_tokens, undefined);
  assert.equal(result.input_reported_calls, 0);
  assert.equal(result.output_reported_calls, 0);
});

test("OpenAI OAuth rejects malformed usage instead of coercing it to zero", async (t) => {
  const event = JSON.stringify({
    type: "response.completed",
    response: { usage: { input_tokens: -1, output_tokens: 2 } },
  });
  t.mock.method(globalThis, "fetch", async () => oauthRawSseResponse(`data: ${event}\n\n`));
  const model = oauthModelForRequest("openai-codex", "gpt-test", "access", {});

  await assertInvalidProviderResponse(() => model.invoke([]));
});

test("OpenAI OAuth rejects malformed SSE JSON instead of dropping a corrupted event", async (t) => {
  const valid = JSON.stringify({ type: "response.output_text.done", text: "trusted-prefix" });
  const raw = `data: ${valid}\n\ndata: {"type":"response.output_text.delta","delta":\n\n`;
  t.mock.method(globalThis, "fetch", async () => oauthRawSseResponse(raw));
  const model = oauthModelForRequest("openai-codex", "gpt-test", "access", {});

  await assertInvalidProviderResponse(() => model.invoke([]));
});

test("OpenAI OAuth rejects malformed no-space SSE data fields", async (t) => {
  const raw = 'data:{"type":"response.output_text.delta","delta":\n\n';
  t.mock.method(globalThis, "fetch", async () => oauthRawSseResponse(raw));
  const model = oauthModelForRequest("openai-codex", "gpt-test", "access", {});

  await assertInvalidProviderResponse(() => model.invoke([]));
});

test("OpenAI OAuth requires SSE JSON payloads to decode to event objects", async (t) => {
  let payload = "null";
  t.mock.method(globalThis, "fetch", async () => oauthRawSseResponse(`data: ${payload}\n\n`));
  const model = oauthModelForRequest("openai-codex", "gpt-test", "access", {});

  for (const invalid of ["null", "[]", '"event"', "1", "true"]) {
    payload = invalid;
    await assertInvalidProviderResponse(() => model.invoke([]));
  }
});

test("OpenAI OAuth joins multi-line SSE data fields before JSON parsing", async (t) => {
  const raw = 'data: {"type":"response.output_text.done",\ndata: "text":"complete"}\n\n';
  t.mock.method(globalThis, "fetch", async () => oauthRawSseResponse(raw));
  const model = oauthModelForRequest("openai-codex", "gpt-test", "access", {});

  const message = await model.invoke([]);

  assert.equal(message.content, "complete");
  assert.equal(message.tool_calls.length, 0);
});

test("OpenAI OAuth accepts no-space SSE data fields and CRLF framing", async (t) => {
  const event = JSON.stringify({ type: "response.output_text.done", text: "complete" });
  t.mock.method(
    globalThis,
    "fetch",
    async () => oauthRawSseResponse(`data:${event}\r\n\r\ndata:[DONE]\r\n\r\n`),
  );
  const model = oauthModelForRequest("openai-codex", "gpt-test", "access", {});

  const message = await model.invoke([]);

  assert.equal(message.content, "complete");
  assert.equal(message.tool_calls.length, 0);
});

test("OpenAI OAuth accepts the SSE done sentinel after a valid JSON event", async (t) => {
  const event = JSON.stringify({ type: "response.output_text.done", text: "complete" });
  t.mock.method(
    globalThis,
    "fetch",
    async () => oauthRawSseResponse(`data: ${event}\n\ndata: [DONE]\n\n`),
  );
  const model = oauthModelForRequest("openai-codex", "gpt-test", "access", {});

  const message = await model.invoke([]);

  assert.equal(message.content, "complete");
  assert.equal(message.tool_calls.length, 0);
});

async function assertInvalidProviderResponse(invoke) {
  await assert.rejects(invoke, (error) => {
    assert.equal(error?.name, "BridgePublicError");
    assert.equal(error?.errorClass, "provider_response_invalid");
    assert.equal(error?.message, "Provider returned an invalid response.");
    return true;
  });
}

function anthropicOauthResponse(payload) {
  return {
    ok: true,
    text: async () => JSON.stringify(payload),
  };
}

function oauthSseResponse(argumentsJson, itemOverrides = {}) {
  const event = {
    type: "response.output_item.done",
    item: {
      type: "function_call",
      call_id: "call-1",
      name: "Read",
      arguments: argumentsJson,
      ...itemOverrides,
    },
  };
  return oauthRawSseResponse(`data: ${JSON.stringify(event)}\n\n`);
}

function oauthRawSseResponse(text) {
  return {
    ok: true,
    text: async () => text,
  };
}

function jwt(claims) {
  const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  return `${header}.${payload}.signature`;
}

test("a declared prompt prefix is honoured only when it really leads the prompt", () => {
  assert.deepEqual(
    promptCacheSplit({ prompt: "inventory\nactor", cacheablePromptPrefix: "inventory\n" }),
    { prefix: "inventory\n", remainder: "actor" },
  );
  assert.equal(promptCacheSplit({ prompt: "actor", cacheablePromptPrefix: "inventory" }), undefined);
  assert.equal(promptCacheSplit({ prompt: "   actor", cacheablePromptPrefix: "   " }), undefined);
  assert.equal(promptCacheSplit({ prompt: "actor" }), undefined);
});

test("the opening user turn carries the prefix as its own cache-marked block", () => {
  const marked = humanMessageForRequest({
    prompt: "inventory\nactor",
    cacheablePromptPrefix: "inventory\n",
  });
  assert.deepEqual(marked.content, [
    { type: "text", text: "inventory\n", cache_control: { type: "ephemeral" } },
    { type: "text", text: "actor" },
  ]);

  const whole = humanMessageForRequest({ prompt: "inventory", cacheablePromptPrefix: "inventory" });
  assert.deepEqual(whole.content, [
    { type: "text", text: "inventory", cache_control: { type: "ephemeral" } },
  ]);

  assert.equal(humanMessageForRequest({ prompt: "actor", cacheablePromptPrefix: "stale" }).content, "actor");
  assert.equal(humanMessageForRequest({ prompt: "actor" }).content, "actor");
});

test("Anthropic OAuth forwards the prefix cache block intact and stays within four breakpoints", async (t) => {
  let body;
  t.mock.method(globalThis, "fetch", async (_url, init) => {
    body = JSON.parse(init.body);
    return anthropicOauthResponse({ content: [{ type: "text", text: "ok" }] });
  });
  const model = oauthModelForRequest("anthropic", "claude-test", "access", {});
  const opening = humanMessageForRequest({
    prompt: "inventory\nactor",
    cacheablePromptPrefix: "inventory\n",
  });

  await model.invoke([opening]);
  assert.deepEqual(body.messages, [
    {
      role: "user",
      content: [
        { type: "text", text: "inventory\n", cache_control: { type: "ephemeral" } },
        { type: "text", text: "actor" },
      ],
    },
  ]);
  assert.equal(cacheBreakpointCount(body), 1);

  await model.invoke([opening, new AIMessage("looking"), new HumanMessage("continue")]);
  assert.deepEqual(body.messages[0].content[0].cache_control, { type: "ephemeral" });
  assert.deepEqual(body.messages.at(-1).content, [
    { type: "text", text: "continue", cache_control: { type: "ephemeral" } },
  ]);
  assert.ok(cacheBreakpointCount(body) <= 4, `breakpoints: ${cacheBreakpointCount(body)}`);
});

function cacheBreakpointCount(body) {
  return JSON.stringify(body).split('"cache_control"').length - 1;
}

test("cache counters ride the aggregated usage only when a call reported them", () => {
  const uncached = bridgeQueryResult(
    [new AIMessage({ content: "a", usage_metadata: { input_tokens: 10, output_tokens: 2 } })],
    "stop",
  );
  assert.equal(uncached.cache_read_input_tokens, undefined);
  assert.equal(uncached.cache_creation_input_tokens, undefined);
  assert.equal(uncached.cache_reported_calls, 0);

  const cached = bridgeQueryResult(
    [
      new AIMessage({
        content: "a",
        usage_metadata: {
          input_tokens: 10,
          output_tokens: 2,
          cache_read_input_tokens: 4000,
          cache_creation_input_tokens: 0,
        },
      }),
      new AIMessage({
        content: "b",
        usage_metadata: {
          input_tokens: 5,
          output_tokens: 1,
          input_token_details: { cache_read: 4000, cache_creation: 300 },
        },
      }),
    ],
    "stop",
  );
  assert.equal(cached.input_tokens, 15);
  assert.equal(cached.cache_read_input_tokens, 8000);
  assert.equal(cached.cache_creation_input_tokens, 300);
  assert.equal(cached.cache_reported_calls, 2);
  assert.equal(usageFromMessages([]).cacheReportedCalls, 0);
});

test("Anthropic OAuth passes prompt-cache usage through to the message usage", async (t) => {
  t.mock.method(globalThis, "fetch", async () =>
    anthropicOauthResponse({
      content: [{ type: "text", text: "ok" }],
      usage: { input_tokens: 12, output_tokens: 3, cache_read_input_tokens: 900 },
    }),
  );
  const model = oauthModelForRequest("anthropic", "claude-test", "access", {});

  const message = await model.invoke([new HumanMessage("hi")]);

  assert.deepEqual(message.usage_metadata, {
    input_tokens: 12,
    output_tokens: 3,
    cache_read_input_tokens: 900,
  });
});

const HAIKU_RATES = {
  inputUsdPerMtok: 1,
  outputUsdPerMtok: 5,
  cacheReadUsdPerMtok: 0.1,
  cacheCreationUsdPerMtok: 1.25,
};

function unmeteredCall(input, output, details) {
  return new AIMessage({
    content: "",
    tool_calls: [{ name: "read_source", args: {}, id: "call-1" }],
    usage_metadata: {
      input_tokens: input,
      output_tokens: output,
      total_tokens: input + output,
      ...(details ? { input_token_details: details } : {}),
    },
  });
}

test("unmetered calls continue under a spend stop when list prices estimate them", () => {
  const messages = [unmeteredCall(100_000, 2_000)];
  assert.equal(modelContinuationDecision(messages, 1, undefined, HAIKU_RATES), "continue");
  assert.equal(modelContinuationDecision(messages, 0.1, undefined, HAIKU_RATES), "observed_spend_exhausted");
  assert.equal(modelContinuationDecision(messages, 1), "observed_spend_incomplete");
});

test("the stop estimate prices cache buckets apart from the inclusive input total", () => {
  const usage = usageFromMessages([
    unmeteredCall(13_000, 500, { cache_read: 10_000, cache_creation: 2_000 }),
  ]);
  // 1k uncached ($0.001) + 10k reads ($0.001) + 2k writes ($0.0025) + 500 out ($0.0025).
  assert.ok(Math.abs(spendForStop(usage, HAIKU_RATES) - 0.007) < 1e-12);
});

test("mixed receipts, missing tokens, or malformed rates stay unknown", () => {
  const metered = new AIMessage({
    content: "",
    usage_metadata: { input_tokens: 10, output_tokens: 10, total_tokens: 20, cost_usd: 0.01 },
  });
  const mixed = usageFromMessages([metered, unmeteredCall(10, 10)]);
  assert.equal(spendForStop(mixed, HAIKU_RATES), undefined);
  const tokenless = usageFromMessages([new AIMessage("no usage")]);
  assert.equal(spendForStop(tokenless, HAIKU_RATES), undefined);
  const priced = usageFromMessages([unmeteredCall(10, 10)]);
  assert.equal(spendForStop(priced, { ...HAIKU_RATES, outputUsdPerMtok: -1 }), undefined);
  assert.equal(spendForStop(priced, undefined), undefined);
});

test("oversized tool results are cut with a disclosed, actionable note", () => {
  const call = { id: "call-1", name: "read_source" };
  const small = toolMessageForOutput(call, "short");
  assert.equal(small.content, "short");

  const big = toolMessageForOutput(call, "x".repeat(TOOL_RESULT_MAX_CHARS + 500));
  assert.ok(big.content.startsWith("x".repeat(TOOL_RESULT_MAX_CHARS)));
  assert.match(big.content, /truncated: showed 24000 of 24500 characters; narrow/);

  const mcp = new ToolMessage({
    tool_call_id: "call-2",
    content: [
      { type: "text", text: "a".repeat(TOOL_RESULT_MAX_CHARS - 10) },
      { type: "text", text: "b".repeat(100) },
    ],
  });
  const bounded = toolMessageForOutput(call, mcp);
  assert.equal(bounded.content[0].text.length, TOOL_RESULT_MAX_CHARS - 10);
  assert.match(bounded.content[1].text, /^b{10}\n\[tool output truncated: showed 10 of 100/);
});

test("a declared turn budget replaces the default turn limit", () => {
  const turns = Array.from({ length: 12 }, () => unmeteredCall(10, 10));
  assert.equal(modelContinuationDecision(turns, undefined), "model_turn_limit");
  assert.equal(modelContinuationDecision(turns, undefined, 20), "continue");
  assert.throws(() => modelContinuationDecision(turns, undefined, 0), /positive safe integer/);
});

test("the model is told its turn budget only in the last turns", () => {
  const turns = (n) => Array.from({ length: n }, () => unmeteredCall(10, 10));
  assert.equal(turnBudgetNotice(turns(9), 12), undefined);
  assert.match(turnBudgetNotice(turns(10), 12).content, /2 model turn\(s\) remain/);
  assert.match(turnBudgetNotice(turns(11), 12).content, /1 model turn\(s\) remain/);
  assert.equal(turnBudgetNotice(turns(12), 12), undefined, "no notice once the stop applies");
  assert.match(turnBudgetNotice(turns(10)).content, /2 model turn/, "defaults to the bridge limit");
});

test("an anthropic agent loop caches its whole opening prompt", () => {
  const anthropic = loopOpeningMessageForRequest({
    model: "anthropic:claude-haiku-4-5",
    prompt: "inventory",
  });
  assert.deepEqual(anthropic.content, [
    { type: "text", text: "inventory", cache_control: { type: "ephemeral" } },
  ]);
  const other = loopOpeningMessageForRequest({ model: "openai:gpt-5.5", prompt: "inventory" });
  assert.equal(other.content, "inventory");
  const split = loopOpeningMessageForRequest({
    model: "anthropic:claude-haiku-4-5",
    prompt: "shared tail",
    cacheablePromptPrefix: "shared ",
  });
  assert.equal(split.content[0].text, "shared ", "a declared prefix keeps its own boundary");
});

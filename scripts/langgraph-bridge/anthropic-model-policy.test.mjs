import assert from "node:assert/strict";
import test from "node:test";
import { HumanMessage } from "@langchain/core/messages";
import {
  ADAPTIVE_THINKING_HEADROOM_TOKENS,
  anthropicDefaultMaxOutputTokens,
  anthropicMaxTokens,
  temperatureLockedModelName,
} from "./anthropic-model-policy.mjs";
import { modelForRequest } from "./model.mjs";
import { oauthModelForRequest } from "./oauth-models.mjs";

test("Claude 5 families are temperature-locked; earlier models keep sampling knobs", () => {
  for (const model of ["claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5", "claude-fable-5-1", "claude-opus-4-7"]) {
    assert.equal(temperatureLockedModelName(model), true, model);
  }
  for (const model of ["claude-sonnet-4-6", "claude-haiku-4-5", "claude-3-5-haiku-latest", "", undefined]) {
    assert.equal(temperatureLockedModelName(model), false, String(model));
  }
});

test("default output budget covers Claude families @langchain/anthropic omits", () => {
  assert.equal(anthropicDefaultMaxOutputTokens("claude-haiku-5-5"), 16384);
  assert.equal(anthropicDefaultMaxOutputTokens("claude-sonnet-4-6"), 16384);
  assert.equal(anthropicDefaultMaxOutputTokens("claude-3-5-haiku-latest"), 8192);
  assert.equal(anthropicDefaultMaxOutputTokens("claude-unknown"), 4096);
});

test("adaptive-thinking models get thinking headroom on top of the visible budget", () => {
  assert.equal(anthropicMaxTokens("claude-haiku-5-5", 32000), 32000 + ADAPTIVE_THINKING_HEADROOM_TOKENS);
  assert.equal(anthropicMaxTokens("claude-haiku-5-5", undefined), 16384 + ADAPTIVE_THINKING_HEADROOM_TOKENS);
  assert.equal(anthropicMaxTokens("claude-sonnet-4-6", 32000), 32000);
  assert.equal(anthropicMaxTokens("claude-3-5-haiku-latest", undefined), 8192);
});

test("Anthropic OAuth drops pinned temperature and reserves thinking headroom", async (t) => {
  const body = await captureOauthBody(t, "claude-haiku-5-5", { temperature: 0, maxOutputTokens: 32000 });

  assert.equal("temperature" in body, false);
  assert.equal(body.max_tokens, 32000 + ADAPTIVE_THINKING_HEADROOM_TOKENS);
});

test("Anthropic OAuth keeps temperature and explicit budgets where the model accepts them", async (t) => {
  const body = await captureOauthBody(t, "claude-3-5-haiku-latest", { temperature: 0, maxOutputTokens: 2048 });

  assert.equal(body.temperature, 0);
  assert.equal(body.max_tokens, 2048);
});

test("Anthropic API-key model gets the same temperature and output-budget policy", () => {
  const locked = modelForRequest({ model: "anthropic:claude-haiku-5-5", apiKey: "test-key", temperature: 0 });
  assert.equal(locked.temperature, undefined);
  assert.equal(locked.maxTokens, 16384 + ADAPTIVE_THINKING_HEADROOM_TOKENS);
  assert.equal(locked.streaming, true);

  const explicit = modelForRequest({ model: "anthropic:claude-3-5-haiku-latest", apiKey: "test-key", maxOutputTokens: 1024 });
  assert.equal(explicit.maxTokens, 1024);
  assert.equal(explicit.streaming, false);
});

async function captureOauthBody(t, modelName, request) {
  let captured;
  t.mock.method(globalThis, "fetch", async (_url, init) => {
    captured = JSON.parse(init.body);
    return { ok: true, text: async () => JSON.stringify({ content: [{ type: "text", text: "ok" }] }) };
  });
  await oauthModelForRequest("anthropic", modelName, "access", request).invoke([new HumanMessage("hi")]);
  return captured;
}

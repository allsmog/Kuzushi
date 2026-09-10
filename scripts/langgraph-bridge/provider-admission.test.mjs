import assert from "node:assert/strict";
import { PassThrough, Readable } from "node:stream";
import test from "node:test";
import { bridgeErrorResponse } from "./errors.mjs";
import { modelOptions } from "./model.mjs";
import { openProviderAdmission, readBridgeRequest, withProviderAdmission } from "./provider-admission.mjs";

const ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

async function fixture(t, reserveReply = { type: "admitted", requestId: ID }) {
  const input = new PassThrough();
  t.after(() => input.destroy());
  input.write(`${JSON.stringify({ model: "openai-codex:gpt-5.5", providerAdmission: "stdio-v1" })}\n`);
  const request = await readBridgeRequest(input);
  const actions = [];
  await openProviderAdmission(request, async (frame) => {
    const { action } = JSON.parse(frame.slice(1));
    actions.push(action);
    const replies = { hello: { type: "ready", protocol: 1 }, reserve: reserveReply, settle: { type: "settled", requestId: action.requestId } };
    input.write(`${JSON.stringify(replies[action.type])}\n`);
  });
  return { request, actions };
}

test("legacy multi-line JSON remains compatible without admission", async () => {
  const request = await readBridgeRequest(Readable.from(['{\n "model":', '"explicit-model"\n}']));
  assert.equal(request.model, "explicit-model");
  let called = 0;
  await withProviderAdmission(request, async () => { called++; }, () => ({}));
  assert.equal(called, 1);
});

test("admission precedes the provider and unknown cost is recorded as unknown", async (t) => {
  const { request, actions } = await fixture(t);
  await withProviderAdmission(request, async () => {
    assert.equal(actions.at(-1).type, "reserve");
    assert.equal(actions.at(-1).model, request.model);
    return "response";
  }, () => ({}));
  assert.deepEqual(actions.map((action) => action.type), ["hello", "reserve", "settle"]);
  assert.equal(actions.at(-1).costUsd, null);
});

test("refused calls never invoke the provider and preserve a typed stop reason", async (t) => {
  const { request } = await fixture(t, { type: "refused" });
  let called = false;
  await assert.rejects(withProviderAdmission(request, async () => { called = true; }, () => ({})), (error) => {
    assert.equal(bridgeErrorResponse(error).errorClass, "allowance_refused");
    return true;
  });
  assert.equal(called, false);
});

test("a failed provider attempt gets an unknown-cost receipt before a distinct retry", async (t) => {
  const { request, actions } = await fixture(t);
  await assert.rejects(withProviderAdmission(request, async () => { throw new Error("transport failed"); }, () => ({})), /transport failed/);
  await withProviderAdmission(request, async () => "retried", () => ({ costUsd: 0 }));
  assert.deepEqual(actions.map((action) => action.type), ["hello", "reserve", "settle", "reserve", "settle"]);
  assert.equal(actions[2].costUsd, null);
  assert.equal(actions[4].costUsd, 0);
});

test("invalid admission replies cannot authorize transport", async (t) => {
  const { request } = await fixture(t, { type: "admitted", requestId: "wrong" });
  let called = false;
  await assert.rejects(withProviderAdmission(request, async () => { called = true; }, () => ({})));
  assert.equal(called, false);
});

test("an admission flag without the connected host fails before transport", async () => {
  let called = false;
  await assert.rejects(withProviderAdmission({ providerAdmission: "stdio-v1" }, async () => { called = true; }, () => ({})));
  assert.equal(called, false);
});

test("unsupported admission versions fail before reading any provider credentials", async () => {
  await assert.rejects(readBridgeRequest(Readable.from(['{"providerAdmission":"future"}\n'])));
});

test("an EOF request cannot downgrade an allowance channel to legacy transport", async () => {
  for (const protocol of ["stdio-v1", "future", null]) {
    const body = JSON.stringify({ providerAdmission: protocol });
    await assert.rejects(readBridgeRequest(Readable.from([body])));
  }
});

test("admitted model invocations disable invisible SDK retries", () => {
  assert.equal(modelOptions({ providerAdmission: "stdio-v1" }).maxRetries, 0);
  assert.equal(modelOptions({}).maxRetries, 8);
});

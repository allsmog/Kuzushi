import assert from "node:assert/strict";
import test from "node:test";
import { AIMessageChunk } from "@langchain/core/messages";
import { messageText } from "./model.mjs";
import { oauthModelForRequest } from "./oauth-models.mjs";
import { invokeWithResponseText, responseStreamFor } from "./response-stream.mjs";

const event = (value) => `data: ${JSON.stringify(value)}\n\n`;

test("OAuth delivers public text before the provider response finishes", async (t) => {
  let controller;
  const stream = new ReadableStream({ start(value) { controller = value; } });
  t.mock.method(globalThis, "fetch", async () => new Response(stream));
  const seen = [];
  const model = oauthModelForRequest("openai-codex", "gpt-5.5", "fixture-token", {});
  const pending = model.invoke([], { onText: async (text) => seen.push(text) });
  controller.enqueue(new TextEncoder().encode(event({ type: "response.output_text.delta", delta: "Hello 東京" })));
  await new Promise((resolve) => setTimeout(resolve, 30));
  const beforeCompletion = [...seen];
  controller.enqueue(new TextEncoder().encode(event({ type: "response.completed", response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } } })));
  controller.close();
  const result = await pending;
  assert.deepEqual(beforeCompletion, ["Hello 東京"]);
  assert.equal(result.content, "Hello 東京");
  assert.equal(result.usage_metadata.output_tokens, 3);
});


function completed(extra = {}) {
  return { type: "response.completed", response: { status: "completed", ...extra } };
}

for (const tail of ["", event({ type: "response.failed" }), event({ type: "response.incomplete" }), "data: PRIVATE_SOURCE\n\n", "data: {}", event(completed({ status: "incomplete" }))]) {
  test(`observed OAuth rejects incomplete/malformed termination ${JSON.stringify(tail).slice(0, 65)}`, async (t) => {
    t.mock.method(globalThis, "fetch", async () => new Response(event({ type: "response.output_text.delta", delta: "partial" }) + tail));
    const seen = [];
    const model = oauthModelForRequest("openai-codex", "gpt-5.5", "fixture", {});
    await assert.rejects(model.invoke([], { onText: async (text) => seen.push(text) }), (error) => {
      assert.equal(String(error).includes("PRIVATE_SOURCE"), false);
      return true;
    });
    assert.deepEqual(seen, ["partial"]);
  });
}

test("OAuth decodes fragmented UTF-8 and excludes reasoning while retaining tool identity and usage", async (t) => {
  const model = oauthModelForRequest("openai-codex", "gpt-5.5", "fixture", {}).bindTools([
    { name: "source:read", schema: { type: "object", properties: {} } },
  ]);
  const providerName = model.body([]).tools[0].name;
  const payload = [
    { type: "response.reasoning_text.delta", delta: "PRIVATE_REASONING" },
    { type: "response.output_text.delta", delta: "東京 🐉" },
    { type: "response.output_text.done", text: "東京 🐉" },
    { type: "response.output_item.done", item: { type: "function_call", call_id: "call_1", name: providerName, arguments: '{"path":"src"}' } },
    completed({ usage: { input_tokens: 11, output_tokens: 13 } }),
  ].map(event).join("").replaceAll("\n", "\r\n");
  const bytes = new TextEncoder().encode(payload);
  t.mock.method(globalThis, "fetch", async () => new Response(new ReadableStream({ start(controller) {
    for (const byte of bytes) controller.enqueue(new Uint8Array([byte]));
    controller.close();
  } })));
  const seen = [];
  const result = await model.invoke([], { onText: async (text) => seen.push(text) });
  assert.deepEqual(seen, ["東京 🐉"]);
  assert.equal(result.content, "東京 🐉");
  assert.deepEqual(result.tool_calls.map(({ id, name, args }) => ({ id, name, args })), [{ id: "call_1", name: "source:read", args: { path: "src" } }]);
  assert.equal(result.usage_metadata.input_tokens, 11);
  assert.equal(result.usage_metadata.output_tokens, 13);
});

function framedRequest() {
  const request = { responseEvents: "text-v1" };
  const frames = [];
  const writer = responseStreamFor(request, async (payload) => {
    assert.equal(payload[0], "\x1e");
    assert.equal(payload.at(-1), "\n");
    frames.push(JSON.parse(payload.slice(1)));
  });
  return { request, frames, writer };
}

test("API message chunks retain fragmented tool arguments and usage and only publish text blocks", async () => {
  const { request, frames, writer } = framedRequest();
  const model = { async *stream() {
    yield new AIMessageChunk({ content: [{ type: "reasoning", text: "PRIVATE_REASONING" }, { type: "text", text: "Checking " }], tool_call_chunks: [{ index: 0, id: "c", name: "Read", args: '{"path":' }] });
    yield new AIMessageChunk({ content: [{ type: "text", text: "source" }], tool_call_chunks: [{ index: 0, args: '"src"}' }], usage_metadata: { input_tokens: 2, output_tokens: 3, total_tokens: 5 } });
  } };
  const result = await invokeWithResponseText(model, [], request);
  await writer.finish({ ok: true });
  assert.deepEqual(result.tool_calls[0].args, { path: "src" });
  assert.equal(result.usage_metadata.total_tokens, 5);
  assert.equal(messageText(result), "Checking source");
  assert.equal(frames.filter((f) => f.type === "text").map((f) => f.text).join(""), "Checking source");
  assert.equal(JSON.stringify(frames).includes("PRIVATE_REASONING"), false);
  assert.equal(frames.at(-1).type, "result");
});

test("each model invocation resets preview; failed invocation flushes partial text before terminal failure", async () => {
  const { request, frames, writer } = framedRequest();
  const model = { async invoke(_messages, { onText }) {
    await onText("first"); await onText(" second");
    throw new Error("local failure");
  } };
  await assert.rejects(invokeWithResponseText(model, [], request));
  await assert.rejects(invokeWithResponseText(model, [], request));
  await writer.finish({ ok: false, errorClass: "transport" });
  assert.equal(frames.filter((f) => f.type === "reset").length, 2);
  assert.equal(frames.filter((f) => f.type === "text").map((f) => f.text).join(""), "first secondfirst second");
  assert.equal(frames.at(-1).result.ok, false);
});

test("unobserved requests preserve invoke and legacy output", async () => {
  const request = {};
  assert.equal(responseStreamFor(request, () => assert.fail("unexpected framing")), undefined);
  const result = await invokeWithResponseText({ invoke: async () => "legacy", stream: () => assert.fail("unexpected streaming") }, [], request);
  assert.equal(result, "legacy");
});

test("long Unicode deltas split into bounded valid text frames", async () => {
  const { request, frames, writer } = framedRequest();
  const text = "🐉東京\n".repeat(5000);
  await invokeWithResponseText({ invoke: async (_, { onText }) => { await onText(text); return {}; } }, [], request);
  await writer.finish({ ok: true });
  const deltas = frames.filter((frame) => frame.type === "text");
  assert.equal(deltas.map((frame) => frame.text).join(""), text);
  assert.ok(deltas.every((frame) => Buffer.byteLength(frame.text) <= 16384));
});

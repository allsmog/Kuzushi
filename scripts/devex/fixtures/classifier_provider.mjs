// Owned metadata responses only. Every fetch is intercepted; no network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const calls = join(dirname(fileURLToPath(import.meta.url)), "classifier-calls.jsonl");
const responses = [{}, { likely: true, score: 0 }, { score: 0.9 }, { score: -0.4 }];
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-classifier-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert(!body.tools?.length);
  assert.equal(body.previous_response_id, undefined);
  const input = JSON.stringify(body.input);
  assert(input.includes("owned.env") && input.includes("aws-access-key"));
  assert(!input.includes("AKIAIOSFODNN7EXAMPLE"), "Only redacted finding metadata is supplied");
  const count = existsSync(calls) ? readFileSync(calls, "utf8").trim().split("\n").length : 0;
  assert(count < responses.length, "Only four explicit metadata responses are available");
  appendFileSync(
    calls,
    `${JSON.stringify({ response: responses[count], model: body.model, reasoning: body.reasoning, tools: 0, freshSession: true, liveProviderRequests: 0 })}\n`,
  );
  const text = JSON.stringify(responses[count]);
  const events = [
    { type: "response.output_text.done", text },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

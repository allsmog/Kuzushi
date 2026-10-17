// Owned malformed-output fixture. Every request is intercepted with no network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const calls = join(dirname(fileURLToPath(import.meta.url)), "catalog-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-catalog-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.equal(body.previous_response_id, undefined);
  const count = existsSync(calls) ? readFileSync(calls, "utf8").trim().split("\n").length : 0;
  assert(count < 2, "Only initial and repair Discovery requests are available");
  const input = JSON.stringify(body.input);
  assert(input.includes(count === 0 ? "owned_input" : "Return only strict JSON"));
  appendFileSync(
    calls,
    `${JSON.stringify({
      ordinal: count + 1,
      model: body.model,
      reasoning: body.reasoning,
      toolsOffered: body.tools?.length ?? 0,
      toolCalls: 0,
      freshSession: true,
      liveProviderRequests: 0,
    })}\n`,
  );
  const events = [
    { type: "response.output_text.done", text: "LABELED_INVALID_TAINT_OUTPUT" },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

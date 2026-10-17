// Labeled protocol fixture. Every fetch is intercepted with no network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const folder = dirname(fileURLToPath(import.meta.url));
const calls = join(folder, "randori-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-randori-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert(!body.tools?.length);
  assert.equal(body.previous_response_id, undefined);
  assert(JSON.stringify(body.input).includes("Owned note catalog"));
  const count = existsSync(calls) ? readFileSync(calls, "utf8").trim().split("\n").length : 0;
  assert(count < 2, "Only two explicitly requested draft responses are available");
  appendFileSync(
    calls,
    `${JSON.stringify({
      model: body.model,
      reasoning: body.reasoning,
      tools: 0,
      freshSession: true,
      liveProviderRequests: 0,
    })}\n`,
  );
  const text = readFileSync(join(folder, "protocol-document.json"), "utf8");
  const events = [
    { type: "response.output_text.done", text },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

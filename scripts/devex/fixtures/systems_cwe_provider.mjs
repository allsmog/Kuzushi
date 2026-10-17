// Owned metadata fixture. All transport is intercepted with no network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const calls = join(dirname(fileURLToPath(import.meta.url)), "catalog-calls.jsonl");
const valid = {
  cwes: [
    {
      id: "CWE-20",
      name: "Owned source metadata",
      reason: "owned café.c contains owned_input metadata. No vulnerability is asserted.",
    },
  ],
};

globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-catalog-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert(!body.tools?.length);
  assert.equal(body.previous_response_id, undefined);
  const input = JSON.stringify(body.input);
  assert(input.includes("owned_input") && input.includes("owned_sink"));
  assert(input.includes("untrusted data"));
  const count = existsSync(calls) ? readFileSync(calls, "utf8").trim().split("\n").length : 0;
  assert(count < 2, "Only two separately invoked intercepted CWE proposal requests are available");
  const value = count === 0 ? { labeledInvalidCweProposal: true } : valid;
  appendFileSync(
    calls,
    `${JSON.stringify({
      ordinal: count + 1,
      model: body.model,
      reasoning: body.reasoning,
      tools: 0,
      freshSession: true,
      liveProviderRequests: 0,
      labeledResponse: value,
    })}\n`,
  );
  const events = [
    { type: "response.output_text.done", text: JSON.stringify(value) },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

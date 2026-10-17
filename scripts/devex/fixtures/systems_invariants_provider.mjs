// Owned inert context fixture. Every request is intercepted; no network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const folder = dirname(fileURLToPath(import.meta.url));
const calls = join(folder, "catalog-calls.jsonl");
const surfaceId = JSON.parse(readFileSync(join(folder, "surface.json"), "utf8")).id;

globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-catalog-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert(!body.tools?.length);
  assert.equal(body.previous_response_id, undefined);
  const input = JSON.stringify(body.input);
  assert(input.includes("owned_input") && input.includes(surfaceId));
  assert(input.includes("untrusted data"));
  assert(!input.includes("owned_omitted_context"));
  const count = existsSync(calls) ? readFileSync(calls, "utf8").trim().split("\n").length : 0;
  assert(count < 2, "Only two separately invoked intercepted Context requests are available");
  const value =
    count === 0
      ? { labeledInvalidInvariant: true }
      : {
          invariants: [
            {
              id: "owned-assumption",
              surfaceId,
              kind: "owned-context-assumption",
              summary: "Review the owned guard assumption",
              statement: "The owned guard assumption needs operator review",
              rationale: "The supplied source comment names owned_input",
              evidence: ["owned_input"],
              attackerControlledFields: [],
              cheapVerifiable: false,
            },
          ],
        };
  appendFileSync(
    calls,
    `${JSON.stringify({
      ordinal: count + 1,
      model: body.model,
      reasoning: body.reasoning,
      tools: 0,
      freshSession: true,
      liveProviderRequests: 0,
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

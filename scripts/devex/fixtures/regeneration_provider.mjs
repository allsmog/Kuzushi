// Every transport request is intercepted. This fixture has no network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const calls = join(evidence, "provider-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-regeneration-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.equal(body.previous_response_id, undefined);
  assert.equal(body.tools, undefined);
  assert.match(body.instructions, /ContextTextRegeneration/);
  assert.ok(
    !existsSync(calls) || !readFileSync(calls, "utf8").trim(),
    "Only one fixture request is approved",
  );
  const input = JSON.stringify(body.input);
  assert.ok(input.includes("Alpha") && !input.includes("Beta"), "Use the selected exact parent");
  assert.ok(input.includes("Keep human context α") && input.includes("Labeled fixture source"));
  assert.ok(input.includes("/dfd/nodes/1/purpose"));
  appendFileSync(
    calls,
    `${JSON.stringify({
      model: body.model,
      reasoning: body.reasoning,
      tools: 0,
      liveProviderRequests: 0,
      selectedParent: true,
      guidanceIncluded: true,
      fixtureKind: "intercepted OAuth, labeled explanatory text",
    })}\n`,
  );
  const text = JSON.stringify({
    schemaVersion: 1,
    edits: [
      {
        pointer: "/dfd/nodes/1/purpose",
        text: "Labeled regeneration: records the selected item; source excerpts leave caller ownership uncertain.",
      },
    ],
  });
  const events = [
    { type: "response.output_text.done", text },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

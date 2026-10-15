// Fully intercepted source-pattern calls for two owned catalog actions.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const calls = join(dirname(fileURLToPath(import.meta.url)), "catalog-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-pattern-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.match(body.instructions, /NdiffFixPattern/);
  assert.equal((body.tools ?? []).length, 0);
  const count = existsSync(calls)
    ? readFileSync(calls, "utf8").trim().split("\n").filter(Boolean).length
    : 0;
  assert.ok(count < 2);
  appendFileSync(
    calls,
    `${JSON.stringify({
      model: body.model,
      reasoning: body.reasoning,
      toolCount: 0,
      providerOutputCapSupplied: body.max_output_tokens !== undefined,
      liveRequests: 0,
      toolCallsReturned: 0,
    })}\n`,
  );
  const text = JSON.stringify({
    fixShape: "Owned changed greeting marker",
    vulnerableShape: "Owned prior greeting marker",
    cwe: ["CWE-79"],
    languages: ["text"],
    keywords: ["owned"],
    confidence: "MEDIUM",
    description: "Labeled inert catalog pattern. No defect is claimed.",
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

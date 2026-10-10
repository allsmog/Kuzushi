// Every model transport request is intercepted. This fixture has no network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const calls = join(evidence, "provider-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-lesson-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.equal(body.previous_response_id, undefined);
  assert.equal(body.tools, undefined);
  assert.match(body.instructions, /ReviewedLessonDraft/);
  const input = JSON.stringify(body.input);
  assert.ok(input.includes("lesson-observation"));
  assert.ok(input.includes("Synthetic acceptance solely for lesson UI testing"));
  assert.ok(input.includes("not_recorded") || input.includes("blobHash"));
  assert.ok(
    !existsSync(calls) || !readFileSync(calls, "utf8").trim(),
    "Only one fixture request is approved",
  );
  appendFileSync(
    calls,
    `${JSON.stringify({
      model: body.model,
      reasoning: body.reasoning,
      tools: 0,
      fixtureKind: "intercepted OAuth, synthetic defensive lesson",
      liveProviderRequests: 0,
    })}\n`,
  );
  const text = JSON.stringify({
    schemaVersion: 1,
    content: {
      title: "Labeled model lesson",
      text: "Inspect recorded evidence before carrying a historical review claim into new context.",
      applicability: "Defensive review of owned source observations.",
      limitations:
        "Labeled synthetic greeting example. Captured source may be absent. Other source revisions require independent review.",
    },
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

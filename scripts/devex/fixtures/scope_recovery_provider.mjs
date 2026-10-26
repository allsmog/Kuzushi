// Labeled offline proposal. This hook has no network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const calls = join(evidence, "scope-recovery-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-scope-recovery-fixture");
  assert.ok(!existsSync(calls), "Only one intercepted proposal request is permitted");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.ok(!body.tools?.length);
  const text = JSON.stringify(
    JSON.parse(readFileSync(join(evidence, "labeled-invalid-scope.json"), "utf8")),
  );
  appendFileSync(calls, `${JSON.stringify({ interceptedRequests: 1, liveRequests: 0 })}\n`);
  const events = [
    { type: "response.output_text.done", text },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 7, output_tokens: 8 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

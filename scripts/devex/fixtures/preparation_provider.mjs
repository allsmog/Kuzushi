// Owned source-only fixture. Intercept every request; no network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const path = join(evidence, "preparation-calls.jsonl");
globalThis.fetch = async (url, init) => {
  const body = JSON.parse(init.body);
  const input = JSON.stringify(body.input);
  const count = existsSync(path) ? readFileSync(path, "utf8").trim().split("\n").length : 0;
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-investigation-fixture");
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.ok(count < 2, "Only the two approved fixture passes may request a response");
  assert.ok(input.includes("Partial preparation: snippet file limit reached"));
  assert.ok(input.includes("Labeled alternative greeting"));
  assert.equal(body.previous_response_id, undefined);
  assert.ok(!body.input.some((message) => message.role === "assistant"));
  appendFileSync(
    path,
    `${JSON.stringify({
      bridgePid: process.pid,
      model: body.model,
      receiptInPrompt: true,
      liveRequests: 0,
      sourceExecuted: false,
    })}\n`,
  );
  const events = [
    { type: "response.output_text.done", text: JSON.stringify({ findings: [] }) },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

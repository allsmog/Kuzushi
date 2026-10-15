// One intercepted context answer with missing billing telemetry. No network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const calls = join(dirname(fileURLToPath(import.meta.url)), "synthetic-provider-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-fixture");
  assert.equal(existsSync(calls), false, "Only one intercepted request is approved");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert(!body.tools?.length);
  appendFileSync(
    calls,
    `${JSON.stringify({ model: body.model, liveProviderCalls: 0, tools: 0 })}\n`,
  );
  const events = [
    {
      type: "response.output_text.done",
      text: "Labeled synthetic context answer. Billing telemetry is intentionally absent.",
    },
    { type: "response.completed", response: { status: "completed" } },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

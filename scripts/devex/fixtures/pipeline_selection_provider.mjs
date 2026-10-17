// Every provider request is intercepted. No network fallback or source execution.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const calls = join(dirname(fileURLToPath(import.meta.url)), "selection-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert(
    init.headers.authorization === "Bearer fixture-placeholder",
    "Expected owned fixture credential",
  );
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert(!body.tools?.length);
  assert.equal(body.previous_response_id, undefined);
  assert(JSON.stringify(body.input).includes("Owned source marker; never executed."));
  const count = existsSync(calls) ? readFileSync(calls, "utf8").trim().split("\n").length : 0;
  assert.equal(count, 0, "Only one proposal request is available; Review stays protected");
  appendFileSync(
    calls,
    `${JSON.stringify({ model: body.model, reasoning: body.reasoning, tools: 0, sourceMarkerIncluded: true, liveProviderRequests: 0 })}\n`,
  );
  const text = JSON.stringify({
    cwes: [{ id: "CWE-20", name: "Input validation", reason: "Owned source marker" }],
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

// Owned local resource test. Every provider request is intercepted.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const calls = join(dirname(fileURLToPath(import.meta.url)), "catalog-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-catalog-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.equal(body.previous_response_id, undefined);
  assert(body.tools.some((tool) => tool.name === "clang_definition"));
  const count = existsSync(calls) ? readFileSync(calls, "utf8").trim().split("\n").length : 0;
  assert(count < 2, "Only two intercepted requests are approved for this fixed resource test");
  if (count === 1) {
    assert(JSON.stringify(body.input).includes("timed out"));
  }
  appendFileSync(
    calls,
    `${JSON.stringify({
      ordinal: count + 1,
      model: body.model,
      toolNames: body.tools.map((tool) => tool.name),
      liveProviderRequests: 0,
    })}\n`,
  );
  const events =
    count === 0
      ? [
          {
            type: "response.output_item.done",
            item: {
              type: "function_call",
              call_id: "owned-clang-request",
              name: "clang_definition",
              arguments: JSON.stringify({ file: "owned café.c", line: 1, column: 1 }),
            },
          },
        ]
      : [{ type: "response.output_text.done", text: '{"findings":[]}' }];
  events.push({
    type: "response.completed",
    response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
  });
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

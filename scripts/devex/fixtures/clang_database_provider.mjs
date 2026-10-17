// Owned compiler-input test. Every provider request is intercepted.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const folder = dirname(fileURLToPath(import.meta.url));
const calls = join(folder, "catalog-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-catalog-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.equal(body.previous_response_id, undefined);
  assert(body.tools.some((tool) => tool.name === "clang_definition"));
  const count = existsSync(calls) ? readFileSync(calls, "utf8").trim().split("\n").length : 0;
  assert(count < 4, "Only four intercepted requests are allowed for the two fixed tests");
  let navigationLine = null;
  if (count % 2 === 0) {
    writeFileSync(join(folder, "chosen compiler #1.json"), "[]\n");
  } else {
    const outputs = body.input.filter((item) => item.type === "function_call_output");
    assert.equal(outputs.length, 1);
    const output = JSON.parse(outputs[0].output);
    assert.equal(output.locations.length, 1);
    navigationLine = output.locations[0].line;
    assert.equal(navigationLine, 2);
  }
  appendFileSync(
    calls,
    `${JSON.stringify({
      ordinal: count + 1,
      model: body.model,
      navigationLine,
      configurationChangedAfterCapture: count % 2 === 0,
      liveProviderRequests: 0,
    })}\n`,
  );
  const events =
    count % 2 === 0
      ? [
          {
            type: "response.output_item.done",
            item: {
              type: "function_call",
              call_id: "owned-real-clang",
              name: "clang_definition",
              arguments: JSON.stringify({ file: "owned café.c", line: 6, column: 30 }),
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

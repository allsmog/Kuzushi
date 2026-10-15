// Labeled synthetic response at the real native provider boundary. No network.
import assert from "node:assert/strict";
import { appendFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const folder = dirname(fileURLToPath(import.meta.url));
globalThis.fetch = async (_url, init) => {
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert(!body.tools?.length);
  appendFileSync(
    join(folder, "synthetic-provider-calls.jsonl"),
    `${JSON.stringify({ model: body.model, tools: 0 })}\n`,
  );
  const text =
    "Labeled synthetic answer: the accepted context models two HTTP entry points and their application flows. No source execution or finding verdict is established. Inspect the accepted context identifiers before relying on this fixture answer.";
  const done = JSON.stringify({ type: "response.output_text.done", text });
  const completed = JSON.stringify({
    type: "response.completed",
    response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
  });
  return new Response(`data: ${done}\n\ndata: ${completed}\n\n`);
};

// Labeled response intercepted at the native OAuth transport. No network fallback.
import assert from "node:assert/strict";
import { appendFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const folder = dirname(fileURLToPath(import.meta.url));
globalThis.fetch = async (_url, init) => {
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert(!body.tools?.length);
  assert.deepEqual(body.reasoning, { effort: "low" });
  appendFileSync(
    join(folder, "proposal-calls.jsonl"),
    `${JSON.stringify({ model: body.model, tools: 0 })}\n`,
  );
  const text = JSON.stringify({
    summary: "Labeled workflow proposal for the owned repository",
    changes: [{ kind: "note", text: "Inspect context coverage before choosing discovery work" }],
    unsupported: ["Which source scope should the operator approve?"],
  });
  const done = JSON.stringify({ type: "response.output_text.done", text });
  const completed = JSON.stringify({
    type: "response.completed",
    response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
  });
  return new Response(`data: ${done}\n\ndata: ${completed}\n\n`);
};

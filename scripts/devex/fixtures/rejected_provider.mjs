import assert from "node:assert/strict";
import { appendFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const calls = join(evidence, "rejected-provider-calls.jsonl");

function priorCalls() {
  try {
    return readFileSync(calls, "utf8").trim().split("\n").filter(Boolean).length;
  } catch (error) {
    if (error.code === "ENOENT") return 0;
    throw error;
  }
}

globalThis.fetch = async (_url, options) => {
  const body = JSON.parse(options.body);
  assert.equal(body.model, "gpt-5.5");
  assert.ok(!body.tools?.length);
  const count = priorCalls() + 1;
  assert.ok(count <= 2, "Only initial output and one repair are authorized");
  appendFileSync(calls, `${JSON.stringify({ interceptedRequest: count, liveInference: false })}\n`);
  const text = `LABELED_REJECTED_OUTPUT_${count} not JSON.\n${"Labeled unaccepted diagnostic evidence.\n".repeat(45)}`;
  const events = [
    { type: "response.output_text.done", text },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

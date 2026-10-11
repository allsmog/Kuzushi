// Synthetic duplicate proposal on owned observations. Every fetch is intercepted.
import assert from "node:assert/strict";
import { appendFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const directory = dirname(fileURLToPath(import.meta.url));
const fingerprints = JSON.parse(
  readFileSync(join(directory, "relationship-fingerprints.json"), "utf8"),
);
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-relationship-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.ok(fingerprints.every((fp) => JSON.stringify(body.input).includes(fp)));
  appendFileSync(
    join(directory, "relationship-calls.jsonl"),
    `${JSON.stringify({ model: body.model, liveRequests: 0 })}\n`,
  );
  const text = JSON.stringify({
    groups: [
      {
        canonical_fingerprint: fingerprints[0],
        duplicate_fingerprints: [fingerprints[1]],
        root_cause_summary:
          "Labeled synthetic duplicate observations of the owned greeting. No security defect is claimed.",
        confidence: 0.95,
      },
    ],
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

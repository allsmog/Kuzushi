// Complete transport interception for one owned draft. No network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const calls = join(evidence, "pattern-calls.jsonl");
globalThis.fetch = async (url, init) => {
  const observed = JSON.parse(init.body);
  appendFileSync(
    join(evidence, "pattern-attempts.jsonl"),
    `${JSON.stringify({
      origin: new URL(String(url)).origin,
      model: observed.model,
      reasoning: observed.reasoning,
      signatureInstruction: String(observed.instructions).includes("VariantSignature"),
      syntheticConfirmation: JSON.stringify(observed.input).includes(
        "Synthetic acceptance solely for lesson UI testing",
      ),
      humanConfirmation: JSON.stringify(observed.input).includes("Author: human"),
      tools: observed.tools?.length ?? 0,
      liveProviderRequests: 0,
    })}\n`,
  );
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-pattern-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.match(body.instructions, /VariantSignature/);
  const input = JSON.stringify(body.input);
  assert.ok(input.includes("Synthetic acceptance solely for lesson UI testing"));
  assert.ok(input.includes("Author: human"));
  assert.ok(!existsSync(calls) || !readFileSync(calls, "utf8").trim());
  appendFileSync(
    calls,
    `${JSON.stringify({ model: body.model, liveProviderRequests: 0, toolCallsReturned: 0 })}\n`,
  );
  const text = JSON.stringify({
    source: "Owned greeting metadata",
    sink: "Owned greeting output",
    missingGuard: "Owned review condition",
    languages: ["text"],
    keywords: ["owned-greeting"],
    description: "Labeled synthetic source-pattern draft. No defect is claimed.",
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

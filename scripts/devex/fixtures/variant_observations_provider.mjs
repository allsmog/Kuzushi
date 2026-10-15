// Complete transport interception for one owned related-source observation. No network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const calls = join(evidence, "variant-calls.jsonl");
globalThis.fetch = async (url, init) => {
  const observed = JSON.parse(init.body);
  appendFileSync(
    join(evidence, "variant-attempts.jsonl"),
    `${JSON.stringify({
      origin: new URL(String(url)).origin,
      model: observed.model,
      reasoning: observed.reasoning,
      observationInstruction: String(observed.instructions).includes("VariantFindings"),
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
  assert.match(body.instructions, /VariantFindings/);
  const input = JSON.stringify(body.input);
  assert.ok(input.includes("Synthetic acceptance solely for lesson UI testing"));
  assert.ok(input.includes("Author: human"));
  assert.ok(!existsSync(calls) || !readFileSync(calls, "utf8").trim());
  appendFileSync(
    calls,
    `${JSON.stringify({ model: body.model, liveProviderRequests: 0, toolCallsReturned: 0 })}\n`,
  );
  const text = JSON.stringify({
    variants: [
      {
        filePath: "related.txt",
        startLine: 1,
        severity: "INFO",
        confidence: "MEDIUM",
        message: "Labeled synthetic related greeting. No defect is claimed.",
        rationale: "Owned transport fixture only. Requires independent review.",
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

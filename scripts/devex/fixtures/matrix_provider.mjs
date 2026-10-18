// Labeled transport fixture. Every fetch is intercepted; no network fallback.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const calls = join(dirname(fileURLToPath(import.meta.url)), "matrix-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-matrix-fixture");
  const body = JSON.parse(init.body);
  const count = existsSync(calls)
    ? readFileSync(calls, "utf8").trim().split("\n").filter(Boolean).length
    : 0;
  assert.ok(count < 9, "Nine explicitly approved matrix requests only");
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.equal(body.previous_response_id, undefined, "Each pass starts a fresh session");
  const prompt = JSON.stringify(body.input);
  assert.ok(
    !prompt.includes("Query findings:query for prior findings"),
    "Independent discovery must not be instructed to suppress known findings",
  );
  assert.ok(prompt.includes("Independent discovery:"));
  const toolNames = (body.tools ?? []).map((tool) => tool.name ?? tool.function?.name ?? "");
  assert.ok(
    toolNames.every((name) => !/^findings(?:[:_-]|$)/i.test(name)),
    "Discovery must not expose the prior-findings toolset",
  );
  assert.ok(
    !prompt.includes("Labeled synthetic matrix observation"),
    "Fresh discovery must not be seeded with an earlier pass's observation",
  );
  const context = count < 3 ? "Alpha" : count < 6 ? "Beta" : "Gamma";
  assert.ok(prompt.includes(context), `The ${context} context must be supplied to the scanner`);
  if (count < 6) assert.ok(!prompt.includes("Gamma"), "Never substitute globally active context");
  appendFileSync(
    calls,
    `${JSON.stringify({
      call: count + 1,
      context,
      model: body.model,
      reasoning: body.reasoning,
      freshSession: true,
      priorObservationTitleAbsent: true,
      priorHistoryGuidanceAbsent: true,
      toolNames,
      promptSha256: createHash("sha256").update(prompt).digest("hex"),
      liveProviderRequests: 0,
    })}\n`,
  );
  const text = JSON.stringify({
    findings:
      count === 5 || count === 7 || count === 8
        ? []
        : [
            {
              ruleId: "labeled-context-experiment",
              title: "Labeled synthetic matrix observation",
              filePath: "main.rs",
              startLine: 1,
              severity: "info",
              confidence: "low",
              message: "Synthetic receipt and comparison fixture. No security defect is claimed.",
              evidence: "main.rs:1 is an owned greeting fixture; source is never executed.",
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

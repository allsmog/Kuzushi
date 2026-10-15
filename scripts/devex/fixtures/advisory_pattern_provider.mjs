// Complete transport interception for an owned draft and one explicit search.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const calls = join(evidence, "advisory-pattern-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-pattern-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  const prior = existsSync(calls)
    ? readFileSync(calls, "utf8").trim().split("\n").filter(Boolean).length
    : 0;
  assert.ok(prior < 2);
  const draft = body.instructions.includes("NdiffFixPattern");
  assert.equal(draft, prior === 0);
  if (draft) assert.equal((body.tools ?? []).length, 0);
  else assert.match(body.instructions, /NdiffVariantFindings/);
  appendFileSync(
    calls,
    `${JSON.stringify({
      action: draft ? "draft" : "explicit-search",
      model: body.model,
      reasoning: body.reasoning,
      toolCount: (body.tools ?? []).length,
      providerOutputCapSupplied: body.max_output_tokens !== undefined,
      liveProviderRequests: 0,
      toolCallsReturned: 0,
    })}\n`,
  );
  const text = JSON.stringify(
    draft
      ? {
          fixShape: "Owned changed greeting marker",
          vulnerableShape: "Owned prior greeting marker",
          description: "Labeled inert draft. No defect is claimed.",
          confidence: "MEDIUM",
        }
      : { variants: [] },
  );
  const events = [
    { type: "response.output_text.done", text },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

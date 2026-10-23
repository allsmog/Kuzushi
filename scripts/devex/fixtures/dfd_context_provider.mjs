// Owned transport fixture. Every fetch is intercepted; there is no network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const calls = join(dirname(fileURLToPath(import.meta.url)), "dfd-context-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-investigation-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.equal(body.tools, undefined);
  assert.equal(body.previous_response_id, undefined);
  assert.ok(!existsSync(calls), "Exactly one explicitly approved synthesis");
  const input = JSON.stringify(body.input);
  for (const marker of ["SPACED_EVIDENCE", "ORDINARY_EVIDENCE", "Alpha receiver"])
    assert.ok(input.includes(marker));
  for (const marker of ["UNSELECTED_SIBLING", "UNSELECTED_ROOT", "Beta receiver"])
    assert.ok(!input.includes(marker));
  appendFileSync(
    calls,
    `${JSON.stringify({
      model: body.model,
      reasoning: body.reasoning,
      tools: 0,
      liveRequests: 0,
      input: body.input,
    })}\n`,
  );
  const text = JSON.stringify({
    version: "1",
    methodology: "stride",
    systemContext:
      "Labeled transport fixture over two owned inert files. Architecture claims need operator review.",
    dfd: {
      nodes: [
        {
          id: "reader",
          name: "Draft evidence reader",
          type: "process",
          trustZone: "app",
          purpose: "Explain the selected source comments without running them.",
          sourceRefs: [" app /lib.py:1", "app/lib.py:1"],
        },
      ],
      flows: [],
      trustBoundaries: [],
    },
    threats: [],
    summary: {},
    openQuestions: ["Comments alone do not establish runtime flows."],
  });
  const events = [
    { type: "response.output_text.done", text },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 3, output_tokens: 5 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

// Owned fixture only. All requests are intercepted with no network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const calls = join(dirname(fileURLToPath(import.meta.url)), "group-context-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-investigation-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.equal(body.tools, undefined);
  assert.equal(body.previous_response_id, undefined);
  assert.ok(!existsSync(calls), "Exactly one explicit synthesis request");
  const prompt = JSON.stringify(body.input);
  for (const marker of ["OWNED APP", "OWNED ADAPTER", "OWNED SHARED"])
    assert.ok(prompt.includes(marker));
  assert.ok(!prompt.includes("UNSELECTED SIBLING"));
  assert.ok(prompt.includes("shared-context") && prompt.includes("Beta"));
  appendFileSync(
    calls,
    `${JSON.stringify({
      model: body.model,
      reasoning: body.reasoning,
      tools: 0,
      sourceFiles: 3,
      discoveryFiles: 2,
      sharedFiles: 1,
      liveRequests: 0,
      bridgePid: process.pid,
    })}\n`,
  );
  const text = JSON.stringify({
    version: "1",
    methodology: "stride",
    systemContext:
      "Labeled owned group context. Source comments leave integration behavior unproven.",
    dfd: {
      nodes: [
        {
          id: "app",
          type: "process",
          name: "Owned group component",
          trustZone: "internal",
          purpose: "Labeled boundary context",
          sourceRefs: ["app/reader.rs:1", "adapter/entry.rs:1"],
        },
        {
          id: "shared",
          type: "process",
          name: "Owned shared component",
          trustZone: "internal",
          sourceRefs: ["shared/context.rs:1"],
        },
      ],
      flows: [],
      trustBoundaries: [],
    },
    threats: [],
    summary: {},
    openQuestions: [
      "Does the app invoke the shared component? Source comments do not establish a flow.",
    ],
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

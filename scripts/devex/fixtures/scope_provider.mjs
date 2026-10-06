// Offline OAuth transport. Every fetch is intercepted; there is no network fallback.
import assert from "node:assert/strict";
import { appendFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const calls = join(evidence, "provider-calls.jsonl");
function callCount() {
  try {
    return readFileSync(calls, "utf8").trim().split("\n").filter(Boolean).length;
  } catch (error) {
    if (error.code === "ENOENT") return 0;
    throw error;
  }
}

globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-scope-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.equal(body.previous_response_id, undefined);
  assert.equal(body.tools, undefined);
  assert.match(body.instructions, /ScanScopeDraft/);
  assert.equal(callCount(), 0, "Exactly one intercepted proposal request is authorized");
  const input = JSON.stringify(body.input);
  assert.ok(
    input.includes("Alpha") && !input.includes("Beta"),
    "Use accepted context, not the global active context",
  );
  appendFileSync(
    calls,
    `${JSON.stringify({
      model: body.model,
      reasoning: body.reasoning,
      call: 1,
      tools: 0,
      hasAcceptedContext: true,
      liveProviderCalls: 0,
      fixtureKind: "intercepted OAuth; labeled scope suggestion",
    })}\n`,
  );
  const scope = (id, name, paths) => ({
    id,
    name,
    paths,
    rationale: "Labeled fixture boundary for workflow validation.",
    sharedDependencies: [],
    openQuestions: ["Review this synthetic grouping before acceptance."],
  });
  const text = JSON.stringify({
    schemaVersion: 1,
    sharedScope: null,
    sharedDiscovery: false,
    exclusions: [],
    scopes: [
      scope("code", "Labeled code boundary", ["[route].py", "root file.py"]),
      scope("root", "Labeled root material", ["reader.py"]),
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

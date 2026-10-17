// Every provider request is intercepted. There is no network fallback or tool execution.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const folder = dirname(fileURLToPath(import.meta.url));
const calls = join(folder, "compliance-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert(
    init.headers.authorization === "Bearer fixture-placeholder",
    "Expected the owned fixture credential",
  );
  const body = JSON.parse(init.body);
  writeFileSync(
    join(folder, "provider-checks.json"),
    JSON.stringify({
      model: body.model,
      reasoning: body.reasoning,
      toolCount: body.tools?.length ?? 0,
      sourceMarkerIncluded: JSON.stringify(body.input).includes(
        "Owned policy marker. Never executed.",
      ),
      liveProviderRequests: 0,
    }),
  );
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert(!body.tools?.length);
  assert.equal(body.previous_response_id, undefined);
  assert(JSON.stringify(body.input).includes("Owned policy marker. Never executed."));
  const count = existsSync(calls)
    ? readFileSync(calls, "utf8").trim().split("\n").filter(Boolean).length
    : 0;
  assert.equal(count, 0, "Only one discovery call is available; Review stays protected");
  appendFileSync(
    calls,
    `${JSON.stringify({ model: body.model, tools: 0, liveProviderRequests: 0 })}\n`,
  );
  const text = JSON.stringify({
    summary: "Owned policy review",
    findings: [
      {
        ruleId: "owned-policy",
        filePath: "policy.py",
        startLine: 1,
        severity: "info",
        message: "Owned fixture policy marker needs an owner decision",
        evidence: "policy.py:1",
      },
    ],
    controls: [],
    maturity: {},
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

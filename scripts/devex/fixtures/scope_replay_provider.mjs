// Controlled replay of one saved scope draft. No network fallback exists.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const log = join(evidence, "scope-replay-calls.jsonl");

globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-scope-replay-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-6-luna");
  assert.deepEqual(body.reasoning, { effort: "low" });
  assert.equal(body.tools, undefined);
  assert.equal(body.previous_response_id, undefined);
  assert.match(body.instructions, /ScanScopeDraft/);
  assert.ok(!existsSync(log), "Only one saved-response replay is admitted");
  const input = JSON.stringify(body.input);
  assert.ok(input.includes("SCOPE_RESPONSE_REPLAY_WORKFLOW"));
  assert.ok(input.includes("workspace.json"));
  const reply = readFileSync(join(evidence, "saved-scope-draft.json"), "utf8");
  const draft = JSON.parse(reply);
  assert.equal(draft.scopes.length, 7);
  assert.equal(draft.sharedDiscovery, false);
  appendFileSync(
    log,
    `${JSON.stringify({
      fixtureKind: "saved scope response replay",
      model: body.model,
      reasoning: body.reasoning,
      bridgePid: process.pid,
      replySha256: createHash("sha256").update(reply).digest("hex"),
      inputSha256: createHash("sha256").update(input).digest("hex"),
      liveProviderRequests: 0,
      sourceExecuted: false,
    })}\n`,
  );
  const events = [
    { type: "response.output_text.done", text: reply },
    {
      type: "response.completed",
      response: {
        status: "completed",
        usage: { input_tokens: 2, output_tokens: 3 },
      },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

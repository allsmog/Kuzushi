// Owned scope-study fixture. Every request is intercepted; there is no network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const log = join(evidence, "finite-scope-calls.jsonl");
globalThis.fetch = async (url, init) => {
  const body = JSON.parse(init.body);
  const input = JSON.stringify(body.input);
  const count = existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").length : 0;
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-investigation-fixture");
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.ok(count < 6, "Only six fixed fixture scans may request a response");
  assert.deepEqual(
    body.tools.map((tool) => tool.name),
    ["Read", "LS", "Glob", "Grep"],
  );
  assert.equal(body.previous_response_id, undefined);
  const scope = input.includes("Accepted discovery scope: app") ? "app" : "other";
  assert.ok(input.includes(`OWNED ${scope.toUpperCase()}`));
  assert.ok(!input.includes(`OWNED ${scope === "app" ? "OTHER" : "APP"}`));
  assert.ok(input.includes("OWNED SHARED"));
  const findings = [`${scope}/reader.rs`, "shared/context.rs"].map((filePath) => ({
    ruleId: "labeled-finite-scope",
    title: `Labeled ${scope} observation`,
    filePath,
    startLine: 1,
    severity: "INFO",
    message: "Owned workflow fixture. No defect claimed.",
  }));
  appendFileSync(
    log,
    `${JSON.stringify({
      bridgePid: process.pid,
      scope,
      model: body.model,
      liveRequests: 0,
      sourceExecuted: false,
    })}\n`,
  );
  const events = [
    { type: "response.output_text.done", text: JSON.stringify({ findings }) },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

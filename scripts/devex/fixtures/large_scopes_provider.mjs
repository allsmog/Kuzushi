// Owned finite scope fixture. All transport is intercepted without network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const settings = JSON.parse(readFileSync(join(evidence, "large-scope-settings.json"), "utf8"));
const log = join(evidence, "large-scope-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-investigation-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.equal(body.previous_response_id, undefined);
  assert.deepEqual(
    body.tools.map((tool) => tool.name),
    ["Read", "LS", "Glob", "Grep"],
  );
  const prompt = JSON.stringify(body.input);
  const match = prompt.match(/Accepted discovery scope: (m0[1-8]|integration)/);
  assert.ok(match, "An exact accepted boundary is required");
  const scope = match[1];
  assert.ok(prompt.includes(`OWNED ${scope.toUpperCase()}`));
  for (let index = 1; index <= 8; index += 1) {
    const other = `m0${index}`;
    if (other !== scope) assert.ok(!prompt.includes(`OWNED ${other.toUpperCase()}`));
  }
  assert.ok(prompt.includes("OWNED INTEGRATION"));
  const count = existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").length : 0;
  assert.ok(count < (settings.mode === "stop" ? 2 : 27), "No job or request expansion");
  appendFileSync(
    log,
    `${JSON.stringify({ call: count + 1, scope, pid: process.pid, liveRequests: 0 })}\n`,
  );
  if (settings.mode === "stop" && count === 1) {
    writeFileSync(join(evidence, "waiting-bridge.json"), JSON.stringify({ pid: process.pid }));
    await new Promise((resolve) => setTimeout(resolve, 90000));
    throw new Error("The explicit Stop test did not interrupt its owned transport child");
  }
  const findings = [
    {
      ruleId: "labeled-large-scope",
      title: `Labeled ${scope} observation`,
      filePath: `${scope}/reader.rs`,
      startLine: 1,
      severity: "INFO",
      message: "Owned workflow fixture. No defect claimed.",
    },
  ];
  const events = [
    { type: "response.output_text.done", text: JSON.stringify({ findings }) },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

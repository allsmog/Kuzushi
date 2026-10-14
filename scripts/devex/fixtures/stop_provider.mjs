// Synthetic transport on owned greeting source. No live provider requests.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const directory = dirname(fileURLToPath(import.meta.url));
const calls = join(directory, "stop-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-matrix-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.equal(body.previous_response_id, undefined);
  const count = existsSync(calls) ? readFileSync(calls, "utf8").trim().split("\n").length : 0;
  assert.ok(count < 2, "Stop must prevent a third request");
  appendFileSync(
    calls,
    `${JSON.stringify({ call: count + 1, pid: process.pid, liveProviderRequests: 0 })}\n`,
  );
  if (count === 1) {
    writeFileSync(join(directory, "waiting-bridge.json"), JSON.stringify({ pid: process.pid }));
    await new Promise((resolve) => setTimeout(resolve, 90000));
    throw new Error("The bounded Stop fixture was not stopped within 90 seconds");
  }
  const text = JSON.stringify({
    findings: [
      {
        ruleId: "labeled-stop-observation",
        title: "Labeled synthetic Stop observation",
        filePath: "main.rs",
        startLine: 1,
        severity: "info",
        confidence: "low",
        message: "Synthetic cancellation fixture. No security defect is claimed.",
        evidence: "Owned greeting source, never executed.",
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

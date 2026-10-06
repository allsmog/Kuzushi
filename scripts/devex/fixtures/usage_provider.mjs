// Intercepted transport for usage accounting. No network fallback or real claims.
import assert from "node:assert/strict";
import { appendFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const path = join(dirname(fileURLToPath(import.meta.url)), "usage-provider-calls.jsonl");

function callCount() {
  try {
    return readFileSync(path, "utf8").trim().split("\n").filter(Boolean).length;
  } catch (error) {
    if (error.code === "ENOENT") return 0;
    throw error;
  }
}

const observation = {
  ruleId: "labeled-usage-fixture",
  title: "Labeled synthetic usage observation",
  filePath: "main.rs",
  startLine: 1,
  severity: "info",
  confidence: "low",
  message: "Synthetic artifact-consumption fixture. The greeting program has no security defect.",
  evidence:
    "main.rs:1 prints a greeting; this row tests request accounting and makes no vulnerability claim.",
};

globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-usage-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  const call = callCount() + 1;
  assert.ok(call <= 4, "The isolated fixture permits four intercepted requests");
  appendFileSync(
    path,
    `${JSON.stringify({ call, model: body.model, fixture: "intercepted; synthetic observation" })}\n`,
  );
  const text =
    call % 2 ? "Labeled invalid fixture JSON" : JSON.stringify({ findings: [observation] });
  const events = [
    { type: "response.output_text.done", text },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

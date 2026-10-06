// Offline transport fixture. Every fetch is intercepted; no network fallback.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const callsPath = join(evidence, "provider-calls.jsonl");

function previousCalls() {
  try {
    return readFileSync(callsPath, "utf8").trim().split("\n").filter(Boolean).length;
  } catch (error) {
    if (error.code === "ENOENT") return 0;
    throw error;
  }
}

function candidate(call) {
  const recurring = call <= 2;
  return {
    ruleId: recurring ? "offline-recurring" : "offline-later-only",
    title: recurring ? "Offline recurring test observation" : "Offline later-only test observation",
    filePath: "main.rs",
    startLine: 1,
    severity: "info",
    confidence: "low",
    message:
      "Synthetic workflow observation from intercepted transport. This greeting program has no security defect.",
    evidence:
      "main.rs:1 prints a greeting. This is a labeled integration fixture, not a vulnerability claim.",
  };
}

function recordRequest(body, call) {
  const input = JSON.stringify(body.input);
  const receipt = {
    call,
    bridgePid: process.pid,
    model: body.model,
    reasoning: body.reasoning,
    inputSha256: createHash("sha256").update(input).digest("hex"),
    instructionsSha256: createHash("sha256").update(body.instructions).digest("hex"),
    inputMessages: body.input.length,
    hasAssistantHistory: body.input.some((item) => item.role === "assistant"),
    hasOtherActiveContext: input.includes("Other active context"),
    hasGeneratedContext: input.includes("Command line application"),
    store: body.store,
    fixtureKind: "intercepted OAuth transport; synthetic findings",
  };
  appendFileSync(callsPath, `${JSON.stringify(receipt)}\n`);
}

globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-study-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.equal(body.store, false);
  assert.equal(body.previous_response_id, undefined);
  const call = previousCalls() + 1;
  assert.ok(call <= 3, "The approved journey has exactly three discovery calls");
  recordRequest(body, call);
  const text = JSON.stringify({ findings: [candidate(call)] });
  const events = [
    { type: "response.output_text.done", text },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

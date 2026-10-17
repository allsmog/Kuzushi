// Every fetch is intercepted. No network fallback or generated finding.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { decodedThreatContext } from "./untrusted_context.mjs";

const calls = join(dirname(fileURLToPath(import.meta.url)), "learning-calls.jsonl");
const attempts = join(dirname(fileURLToPath(import.meta.url)), "learning-attempts.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-learning-fixture");
  const body = JSON.parse(init.body);
  const count = existsSync(attempts)
    ? readFileSync(attempts, "utf8").trim().split("\n").filter(Boolean).length
    : 0;
  assert.ok(count < 6, "Only three baseline and three candidate requests are allowed");
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.equal(body.previous_response_id, undefined, "Each pass starts a fresh session");
  const input = JSON.stringify(body.input);
  const instructions = body.instructions ?? "";
  appendFileSync(
    attempts,
    `${JSON.stringify({
      attempt: count + 1,
      inputHasLesson: input.includes("Owned greeting review lesson"),
      instructionsHaveLesson: instructions.includes("Owned greeting review lesson"),
      inputHasUnicode: input.includes("Unicode café"),
      instructionsHaveUnicode: instructions.includes("Unicode café"),
      liveProviderRequests: 0,
    })}\n`,
  );
  const prompt = JSON.stringify({ input: body.input, instructions });
  const context = decodedThreatContext(body);
  const reviewed = count >= 3;
  assert.equal(context.includes("Owned greeting review lesson"), reviewed);
  assert.equal(context.includes("Unicode café"), reviewed);
  if (reviewed) {
    const expected = JSON.parse(
      readFileSync(join(dirname(calls), "supplied-context.json"), "utf8"),
    );
    assert.equal(
      context,
      expected.text,
      "The actual request must contain the exact frozen preview",
    );
  }
  assert.ok(prompt.includes("hello.py"));
  appendFileSync(
    calls,
    `${JSON.stringify({
      call: count + 1,
      reviewedLessonSupplied: reviewed,
      freshSession: true,
      model: body.model,
      reasoning: body.reasoning,
      liveProviderRequests: 0,
      contextSha256: `sha256:${createHash("sha256").update(context).digest("hex")}`,
      contextBytes: Buffer.byteLength(context),
      returnedFindings: 0,
    })}\n`,
  );
  const events = [
    { type: "response.output_text.done", text: JSON.stringify({ findings: [] }) },
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

// Every model transport request is intercepted. This fixture has no network fallback.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const calls = join(evidence, "provider-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-lesson-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.equal(body.previous_response_id, undefined);
  assert.equal(body.tools, undefined);
  assert.match(body.instructions, /ReviewedLessonDraft/);
  const payloads = body.input
    .flatMap((message) => message.content ?? [])
    .map((part) => (typeof part === "string" ? part : (part.text ?? "")))
    .filter((text) => text.trim().startsWith("{"))
    .map((text) => ({ text, payload: JSON.parse(text) }))
    .filter(({ payload }) => payload.capturedSource && payload.origin);
  assert.equal(payloads.length, 1, "Exactly one lesson evidence payload is supplied");
  const { text: evidenceText, payload } = payloads[0];
  const expected = JSON.parse(readFileSync(join(evidence, "source-proof.json"), "utf8"));
  assert.equal(payload.origin.finding.runId, "lesson-observation");
  assert.equal(payload.origin.finding.findingId, expected.findingId);
  assert.equal(payload.origin.snapshotHash, expected.snapshotHash);
  assert.equal(payload.origin.observationSeq, expected.observationSeq);
  assert.equal(payload.origin.decision.decision.author, "human");
  assert.equal(payload.capturedSource.status, "included");
  assert.equal(payload.capturedSource.path, expected.path);
  assert.equal(payload.capturedSource.blobHash, expected.blobHash);
  assert.equal(
    payload.capturedSource.text,
    readFileSync(join(evidence, "expected-source.txt"), "utf8"),
  );
  assert.equal(payload.capturedSource.currentSourceRead, false);
  const sourceSha256 = createHash("sha256").update(payload.capturedSource.text).digest("hex");
  assert.equal(sourceSha256, expected.sha256);
  assert.ok(
    !existsSync(calls) || !readFileSync(calls, "utf8").trim(),
    "Only one fixture request is approved",
  );
  appendFileSync(
    calls,
    `${JSON.stringify({
      model: body.model,
      reasoning: body.reasoning,
      tools: 0,
      sourceSha256,
      sourceBytes: Buffer.byteLength(payload.capturedSource.text),
      evidenceTextBytes: Buffer.byteLength(evidenceText),
      sourceCapture: payload.capturedSource.status,
      currentSourceRead: false,
      fixtureKind: "intercepted OAuth, synthetic defensive lesson",
      liveProviderRequests: 0,
    })}\n`,
  );
  const text = JSON.stringify({
    schemaVersion: 1,
    content: {
      title: "Labeled model lesson",
      text: "Inspect recorded evidence before carrying a historical review claim into new context.",
      applicability: "Defensive review of owned source observations.",
      limitations:
        "Labeled synthetic greeting example with captured source. Deployed behavior was not inspected. Other source revisions require independent review.",
    },
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

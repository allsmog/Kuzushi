// Owned offline transport. No network fallback and one intercepted request.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const calls = join(evidence, "partial-generation-calls.jsonl");

function checkedRequest(url, init) {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-investigation-fixture");
  assert.ok(!existsSync(calls), "Only one intercepted request is allowed");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.ok(!body.tools?.length);
  assert.equal(body.previous_response_id, undefined);
  const text = body.input
    .flatMap((message) => message.content ?? [])
    .map((part) => (typeof part === "string" ? part : (part.text ?? "")))
    .join("\n");
  assert.ok(text.includes("per-file inspection cap of 262144"));
  assert.ok(text.includes("unseen entry points remain unknown"));
  assert.ok(!text.includes("Original inactive-test baseline"));
  return { body, text };
}

function checkedGrounding(text) {
  const grounding = text.match(
    /<untrusted-source label="attack-surface-map"[^>]*>\n([\s\S]*?)\n<\/untrusted-source>/,
  );
  assert.ok(grounding);
  const groundedIds = [...grounding[1].matchAll(/^- id=([^\n]+?) ·/gm)].map((row) => row[1]);
  assert.equal(groundedIds.length, 1);
  const catalog = JSON.parse(readFileSync(join(evidence, "partial-catalog.stdout.json"), "utf8"));
  assert.deepEqual(
    groundedIds,
    catalog.data.entryPoints.map((row) => row.id),
  );
  return groundedIds;
}

function responseDocument(groundedIds) {
  const document = JSON.parse(readFileSync(join(evidence, "response-document.json"), "utf8"));
  document.deprioritized = groundedIds.map((entryPointId) => ({
    entryPointId,
    reason:
      "Owned static source fixture. A filename observation establishes no runtime exposure or vulnerability.",
  }));
  return document;
}

function recordRequest(body, text, groundedIds) {
  appendFileSync(
    calls,
    `${JSON.stringify({
      model: body.model,
      reasoning: body.reasoning,
      groundedIds,
      inputSha256: createHash("sha256").update(text).digest("hex"),
      suppliedInspectionLimit: true,
      suppliedUnknownCoverage: true,
      interceptedRequests: 1,
      liveProviderRequests: 0,
    })}\n`,
  );
}

globalThis.fetch = async (url, init) => {
  const { body, text } = checkedRequest(url, init);
  const groundedIds = checkedGrounding(text);
  const document = responseDocument(groundedIds);
  recordRequest(body, text, groundedIds);
  const events = [
    { type: "response.output_text.done", text: JSON.stringify(document) },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 3, output_tokens: 5 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

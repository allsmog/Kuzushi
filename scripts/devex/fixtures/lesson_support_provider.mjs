// Fake credentials, an owned synthetic observation, and no network fallback.
import assert from "node:assert/strict";
import { appendFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

await import("./provider-base.mjs");
const intercepted = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  const body = JSON.parse(init.body);
  const payload = body.input
    .flatMap((message) => message.content ?? [])
    .map((part) => (typeof part === "string" ? part : (part.text ?? "")))
    .filter((text) => text.trim().startsWith("{"))
    .map((text) => JSON.parse(text))
    .find((item) => item.capturedSource && item.origin);
  assert.ok(payload);
  assert.deepEqual(
    payload.supportingSources.map((item) => item.path),
    ["service.txt", "policy.txt", "missing.txt"],
  );
  assert.equal(
    payload.supportingSources[0].text,
    "HISTORICAL_SERVICE: callers supply their tenant.\n",
  );
  assert.equal(
    payload.supportingSources[1].text,
    "HISTORICAL_POLICY: compare the owner with the caller.\n",
  );
  assert.equal(payload.supportingSources[2].status, "not_recorded");
  assert.equal(payload.supportingSources[2].text, null);
  assert.ok(payload.supportingSources.every((item) => item.currentSourceRead === false));
  assert.ok(!JSON.stringify(payload).includes("CURRENT_ONLY"));
  const response = await intercepted(url, init);
  appendFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "supporting-calls.jsonl"),
    `${JSON.stringify({ supportingFiles: 3, historicalFilesIncluded: 2, liveProviderRequests: 0 })}\n`,
  );
  return response;
};

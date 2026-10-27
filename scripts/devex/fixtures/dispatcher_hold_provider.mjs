// Owned transport hold. No network fallback or model response.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const calls = join(evidence, "held-calls.jsonl");

globalThis.fetch = async (url, init) => {
  const body = JSON.parse(init.body);
  const prior = existsSync(calls) ? readFileSync(calls, "utf8").trim().split("\n").length : 0;
  const receipt = {
    bridgePid: process.pid,
    request: prior + 1,
    endpoint: String(url),
    model: body.model,
    inputSha256: createHash("sha256").update(JSON.stringify(body.input)).digest("hex"),
    responseReturned: false,
    liveProviderRequests: 0,
  };
  appendFileSync(calls, `${JSON.stringify(receipt)}\n`);
  assert.equal(prior, 0, "Only one intercepted request is permitted");
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(body.model, "gpt-5.5");
  writeFileSync(join(evidence, "held-request.json"), JSON.stringify(receipt));
  return holdForStop(init.signal);
};

function holdForStop(signal) {
  return new Promise((_, reject) => {
    const timer = setTimeout(() => reject(new Error("Owned hold exceeded 90 seconds")), 90_000);
    const abort = () => {
      clearTimeout(timer);
      reject(new Error("Owned intercepted request aborted"));
    };
    if (signal?.aborted) abort();
    else signal?.addEventListener("abort", abort, { once: true });
  });
}

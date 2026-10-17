// Owned intercepted failure and interruption. No live network fallback.
import assert from "node:assert/strict";
import { appendFileSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-catalog-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert(!body.tools?.length);
  const runs = join(process.cwd(), ".kuzushi/v3/runs");
  const pending = readdirSync(runs).flatMap((name) => {
    try {
      const path = join(runs, name, "prepared-model-input.json");
      const value = JSON.parse(readFileSync(path, "utf8"));
      const run = JSON.parse(readFileSync(join(runs, name, "run.json"), "utf8"));
      return run.status === "running" ? [{ path, value }] : [];
    } catch {
      return [];
    }
  });
  assert.equal(pending.length, 1, "One prepared request must exist before transport");
  const { path, value } = pending[0];
  assert.equal(value.tool, "systems-hunt:deep-semantic-hunt");
  assert.equal(value.data.model, "openai-codex:gpt-5.5");
  assert(value.data.inputDocument.text.includes("Provider delivery is not established"));
  const contents = body.input.flatMap(({ content }) =>
    Array.isArray(content) ? content.map(({ text }) => text ?? "") : [content ?? ""],
  );
  const input = contents.find((text) => text.includes('"supportingContext"'));
  assert.equal(typeof input, "string");
  assert(input.includes(value.data.runtimeRequest.prompt));
  for (const source of value.data.frozenInput.sources) {
    assert(input.includes(JSON.stringify(source.text).slice(1, -1)));
  }
  const mode = readFileSync(join(evidence, "transport-mode.txt"), "utf8").trim();
  assert(["fail", "pause"].includes(mode));
  appendFileSync(
    join(evidence, "prepared-calls.jsonl"),
    `${JSON.stringify({
      mode,
      runId: value.runId,
      retainedPath: path,
      inputPreparedBeforeFetch: true,
      rawRuntimePromptVerified: true,
      model: body.model,
      liveProviderRequests: 0,
      tools: 0,
    })}\n`,
  );
  if (mode === "fail") {
    return new Response(
      JSON.stringify({ error: { message: "Owned intercepted request refusal" } }),
      {
        status: 400,
        headers: { "content-type": "application/json" },
      },
    );
  }
  return new Promise((_, reject) => {
    const timer = setTimeout(() => reject(new Error("Owned paused transport expired")), 30000);
    init.signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        reject(new Error("Owned paused transport canceled"));
      },
      { once: true },
    );
  });
};

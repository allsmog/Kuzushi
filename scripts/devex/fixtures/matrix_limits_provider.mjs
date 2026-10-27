// Owned transport fixture. Every request is intercepted; no network fallback.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const log = join(dirname(fileURLToPath(import.meta.url)), "matrix-calls.jsonl");
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-matrix-fixture");
  const previous = existsSync(log)
    ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map(JSON.parse)
    : [];
  assert.ok(previous.length < 7, "At most seven intercepted requests in the finite test");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.equal(body.previous_response_id, undefined, "Every attempt starts a fresh session");
  const prompt = JSON.stringify({ input: body.input, instructions: body.instructions });
  assert.ok(prompt.includes("Independent discovery:"));
  assert.ok(!prompt.includes("Labeled synthetic bounded matrix signal"));
  assert.ok(!prompt.includes("J363 operator decision"));
  assert.ok(!prompt.includes("Gamma"), "The active context must not replace frozen cases");
  const tools = (body.tools ?? []).map((tool) => tool.name ?? tool.function?.name ?? "");
  assert.ok(tools.every((name) => !/^findings(?:[:_-]|$)/i.test(name)));
  const context = prompt.includes("Alpha labeled experiment context") ? "Alpha" : "Beta";
  assert.ok(prompt.includes(`${context} labeled experiment context`));
  const failed = previous.length === 1;
  const ordinal = previous.filter((row) => row.context === context && !row.failed).length + 1;
  appendFileSync(
    log,
    `${JSON.stringify({
      call: previous.length + 1,
      context,
      failed,
      ordinal,
      freshSession: true,
      model: body.model,
      promptSha256: createHash("sha256").update(prompt).digest("hex"),
      liveProviderRequests: 0,
    })}\n`,
  );
  if (failed) {
    return new Response(
      JSON.stringify({
        error: {
          type: "invalid_request_error",
          code: "owned_fixture_rejection",
          message: "Owned fixture nonretryable request rejection",
        },
      }),
      { status: 400, headers: { "content-type": "application/json" } },
    );
  }
  const findings =
    context === "Beta" && ordinal > 1
      ? []
      : [
          {
            ruleId: "owned-bounded-matrix",
            title: "Labeled synthetic bounded matrix signal",
            filePath: "main.rs",
            startLine: 1,
            severity: "info",
            confidence: "low",
            message: "Synthetic budget and case-receipt fixture. No security defect is asserted.",
            evidence: "main.rs:1 is owned inert source; it is never executed.",
          },
        ];
  const text = JSON.stringify({ findings });
  const events = [
    { type: "response.output_text.done", text },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

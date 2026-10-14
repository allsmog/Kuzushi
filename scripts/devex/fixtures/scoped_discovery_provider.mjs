// Owned source-only fixture. Every request is intercepted, with no network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const path = join(evidence, "scoped-discovery-calls.jsonl");
let turn = 0;

globalThis.fetch = async (url, init) => {
  const body = JSON.parse(init.body);
  const input = JSON.stringify(body.input);
  const count = existsSync(path) ? readFileSync(path, "utf8").trim().split("\n").length : 0;
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-investigation-fixture");
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.deepEqual(
    body.tools.map((tool) => tool.name),
    ["Read", "LS", "Glob", "Grep"],
  );
  assert.ok(count < 6, "Only six explicitly allowed fixture calls may request responses");
  assert.ok(input.includes("OWNED DISCOVERY") && input.includes("OWNED CONTEXT"));
  assert.ok(!input.includes("UNAPPROVED SOURCE"));
  assert.equal(body.previous_response_id, undefined);
  if (turn === 1) {
    const outputs = body.input.filter((item) => item.type === "function_call_output");
    assert.ok(
      outputs.some((item) => item.call_id === "context" && item.output.includes("OWNED CONTEXT")),
    );
    assert.ok(
      outputs.some(
        (item) => item.call_id === "outside" && item.output.includes("outside accepted"),
      ),
    );
  }
  const observations = ["app/[route]/reader.rs", "shared/context.rs", "other/unapproved.rs"].map(
    (filePath) => ({
      ruleId: "labeled-scope",
      title: "Labeled scope observation",
      filePath,
      startLine: 1,
      severity: "INFO",
      message: "Owned workflow fixture. No security defect claimed.",
    }),
  );
  const output =
    turn === 0
      ? [
          {
            type: "response.output_item.done",
            item: {
              type: "function_call",
              call_id: "context",
              name: "Read",
              arguments: JSON.stringify({ file_path: "shared/context.rs" }),
            },
          },
          {
            type: "response.output_item.done",
            item: {
              type: "function_call",
              call_id: "outside",
              name: "Read",
              arguments: JSON.stringify({ file_path: "other/unapproved.rs" }),
            },
          },
        ]
      : [{ type: "response.output_text.done", text: JSON.stringify({ findings: observations }) }];
  appendFileSync(
    path,
    `${JSON.stringify({
      bridgePid: process.pid,
      turn,
      model: body.model,
      contextReadAndOutsideDenied: turn === 1,
      liveRequests: 0,
      sourceExecuted: false,
    })}\n`,
  );
  turn += 1;
  output.push({
    type: "response.completed",
    response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
  });
  return new Response(output.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

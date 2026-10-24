// Owned offline workflow. All requests are intercepted without network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { optionalThreatContext } from "./untrusted_context.mjs";

const evidence = dirname(fileURLToPath(import.meta.url));
const log = join(evidence, "generated-scope-calls.jsonl");

function priorCalls() {
  return existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").map(JSON.parse) : [];
}

function sourceText(body) {
  return body.input
    .flatMap((message) => message.content ?? [])
    .map((part) => (typeof part === "string" ? part : (part.text ?? "")))
    .join("\n");
}

function contextReply(body, text, prior) {
  assert.equal(prior.length, 0, "Only the first fixed request can generate context");
  assert.ok(!body.tools?.length);
  for (const marker of ["OWNED APP", "OWNED ADAPTER", "OWNED SHARED", "ROOT_ACCEPTED_CONTEXT"])
    assert.ok(text.includes(marker), marker);
  assert.ok(!text.includes("UNSELECTED SIBLING"));
  assert.ok(!text.includes("Offline fixture Beta"));
  return { kind: "context", result: contextDocument() };
}

function contextDocument() {
  return {
    version: "1",
    methodology: "stride",
    title: "Owned generated boundary context",
    systemContext:
      "APP_ONLY_CONTEXT_BOUNDARY. Owned static source needs an operator decision. No runtime architecture or defect is established.",
    dfd: {
      nodes: [
        {
          id: "app",
          name: "Owned group component",
          type: "data-store",
          trustZone: "repository",
          description: "Two disjoint files contain owned source comments.",
          purpose: "Supplies bounded source evidence.",
          sourceRefs: ["app/reader.rs:1", "adapter/entry.rs:1"],
        },
        {
          id: "shared",
          name: "Owned shared context",
          type: "data-store",
          trustZone: "repository",
          description: "Shared source comment supplies context only.",
          purpose: "Retains an explicit shared boundary.",
          sourceRefs: ["shared/context.rs:1"],
        },
      ],
      flows: [],
      trustBoundaries: [],
    },
    threats: [],
    openQuestions: ["Source comments establish no execution flow."],
    summary: {},
  };
}

function scanReply(body, text, prior) {
  assert.equal(prior.filter((row) => row.kind === "context").length, 1);
  assert.ok(prior.filter((row) => row.kind === "scan").length < 6);
  assert.deepEqual(
    body.tools.map((tool) => tool.name),
    ["Read", "LS", "Glob", "Grep"],
  );
  const scope = text.includes("Accepted discovery scope: app") ? "app" : "other";
  assert.ok(text.includes(`Accepted discovery scope: ${scope}`));
  assert.ok(text.includes("OWNED SHARED"));
  const context = optionalThreatContext(body) ?? "";
  assert.equal(context.includes("APP_ONLY_CONTEXT_BOUNDARY"), scope === "app");
  assert.ok(!context.includes("ROOT_ACCEPTED_CONTEXT"));
  assert.ok(!context.includes("Beta"));
  assertSelectedSource(scope, text);
  return {
    kind: "scan",
    scope,
    contextBinding: scope === "app" ? "selected" : "omitted",
    result: {
      findings: [`${scope}/reader.rs`, "shared/context.rs"].map((filePath) => ({
        ruleId: "owned-generated-scope",
        title: `Owned ${scope} policy observation`,
        filePath,
        startLine: 1,
        severity: "INFO",
        message: "Labeled workflow fixture. No vulnerability is claimed.",
      })),
    },
  };
}

function assertSelectedSource(scope, text) {
  if (scope === "app") {
    assert.ok(text.includes("OWNED APP") && text.includes("OWNED ADAPTER"));
    assert.ok(!text.includes("UNSELECTED SIBLING"));
  } else {
    assert.ok(text.includes("UNSELECTED SIBLING"));
    assert.ok(!text.includes("OWNED APP") && !text.includes("OWNED ADAPTER"));
  }
}

globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-investigation-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.equal(body.previous_response_id, undefined);
  const prior = priorCalls();
  assert.ok(prior.length < 7, "Seven fixed offline requests maximum");
  const text = sourceText(body);
  const reply = body.tools?.length ? scanReply(body, text, prior) : contextReply(body, text, prior);
  appendFileSync(
    log,
    `${JSON.stringify({
      kind: reply.kind,
      scope: reply.scope,
      model: body.model,
      contextBinding: reply.contextBinding,
      bridgePid: process.pid,
      liveRequests: 0,
      sourceExecuted: false,
    })}\n`,
  );
  const events = [
    { type: "response.output_text.done", text: JSON.stringify(reply.result) },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 3, output_tokens: 5 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};

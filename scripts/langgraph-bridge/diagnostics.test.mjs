import assert from "node:assert/strict";
import test from "node:test";

import { bridgeDiagnosticMetadata, transcriptToolCalls } from "./diagnostics.mjs";

test("diagnostics name the tools a response called without any content", () => {
  const response = {
    content: "secret reasoning text",
    tool_calls: [
      { name: "cpg.taint_paths", args: { source: "req.query" } },
      { name: "tree_sitter:callers", args: { file: "a.ts" } },
    ],
  };

  const metadata = bridgeDiagnosticMetadata("query", { prompt: "p" }, [], "sys", response);

  assert.equal(metadata.responseToolCount, 2);
  assert.deepEqual(metadata.responseToolNames, ["cpg.taint_paths", "tree_sitter:callers"]);
  assert.ok(!JSON.stringify(metadata).includes("req.query"));
  assert.ok(!JSON.stringify(metadata).includes("secret reasoning"));
});

test("diagnostics report no tool names when the response called none", () => {
  const metadata = bridgeDiagnosticMetadata("query", {}, [], "", { content: "done" });

  assert.deepEqual(metadata.responseToolNames, []);
});

test("transcript tool calls count every turn by tool name", () => {
  const messages = [
    { content: "prompt" },
    { tool_calls: [{ name: "cpg.taint_paths", args: {} }] },
    { content: "result" },
    { tool_calls: [{ name: "cpg.taint_paths", args: {} }, { name: "read_file", args: {} }] },
    { content: "final" },
  ];

  assert.deepEqual(transcriptToolCalls(messages), { "cpg.taint_paths": 2, read_file: 1 });
  assert.deepEqual(transcriptToolCalls(undefined), {});
});

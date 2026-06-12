import { AIMessage, HumanMessage, SystemMessage, ToolMessage } from "@langchain/core/messages";
import { afterEach, describe, expect, it, vi } from "vitest";
// @ts-expect-error -- plain .mjs bridge module without type declarations
import { oauthModelForRequest } from "../../scripts/langgraph-bridge/oauth-models.mjs";

const toolSchema = { type: "object", properties: { q: { type: "string" } } };

function openAiModel(tools: Array<{ name: string; description?: string }>) {
  return oauthModelForRequest("openai-codex", "gpt-test", "token", {}).bindTools(
    tools.map((tool) => ({ ...tool, schema: toolSchema })),
  ) as any;
}

describe("OpenAI Codex OAuth model tool-name mapping", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("sanitizes tool definitions and preserves collision-safe names", () => {
    const model = openAiModel([{ name: "codeql:query" }, { name: "codeql_query" }]);

    const body = model.body([new HumanMessage("inspect")]);
    const names = body.tools.map((tool: { name: string }) => tool.name);

    expect(names).toEqual(["codeql_query", "codeql_query_2"]);
    expect(names.every((name: string) => name.length <= 64)).toBe(true);
  });

  it("encodes assistant tool-call history with safe names and matching call ids", () => {
    const model = openAiModel([{ name: "codeql:query" }]);
    const assistant = new AIMessage({
      content: "checking",
      tool_calls: [
        { id: "call_1", name: "codeql:query", args: { q: "select" }, type: "tool_call" },
      ],
    });
    const tool = new ToolMessage({ tool_call_id: "call_1", content: "[]" });

    const body = model.body([new SystemMessage("system"), assistant, tool]);

    expect(body.input).toEqual([
      { role: "assistant", content: "checking" },
      {
        type: "function_call",
        call_id: "call_1",
        name: "codeql_query",
        arguments: '{"q":"select"}',
      },
      { type: "function_call_output", call_id: "call_1", output: "[]" },
    ]);
  });

  it("does not emit empty assistant text for tool-call-only messages", () => {
    const model = openAiModel([{ name: "tree_sitter:node_at" }]);
    const assistant = new AIMessage({
      content: "",
      tool_calls: [
        { id: "call_2", name: "tree_sitter:node_at", args: { file: "a.rs" }, type: "tool_call" },
      ],
    });

    const body = model.body([assistant]);

    expect(body.input).toEqual([
      {
        type: "function_call",
        call_id: "call_2",
        name: "tree_sitter_node_at",
        arguments: '{"file":"a.rs"}',
      },
    ]);
  });

  it("maps streamed function calls back to original tool names per model instance", async () => {
    const model = openAiModel([{ name: "codeql:query" }, { name: "codeql_query" }]);
    const sse = [
      'data: {"type":"response.output_item.done","item":{"type":"function_call","name":"codeql_query_2","call_id":"call_3","arguments":"{\\"q\\":\\"select\\"}"}}',
      'data: {"response":{"usage":{"input_tokens":7,"output_tokens":3}}}',
    ].join("\n\n");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(sse, { status: 200 }) as never);

    const response = await model.invoke([new HumanMessage("inspect")]);

    expect(response.tool_calls).toEqual([
      { id: "call_3", name: "codeql_query", args: { q: "select" }, type: "tool_call" },
    ]);
    expect(response.usage_metadata).toEqual({ input_tokens: 7, output_tokens: 3 });
  });
});

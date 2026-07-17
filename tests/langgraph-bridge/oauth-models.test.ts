import { AIMessage, HumanMessage, SystemMessage, ToolMessage } from "@langchain/core/messages";
import { afterEach, describe, expect, it, vi } from "vitest";
// @ts-expect-error -- plain .mjs bridge module without type declarations
import { oauthModelForRequest } from "../../scripts/langgraph-bridge/oauth-models.mjs";

const toolSchema = { type: "object", properties: { q: { type: "string" } } };

function openAiModel(
  tools: Array<{ name: string; description?: string }>,
  request: Record<string, unknown> = {},
) {
  return oauthModelForRequest("openai-codex", "gpt-test", "token", request).bindTools(
    tools.map((tool) => ({ ...tool, schema: toolSchema })),
  ) as any;
}

function anthropicModel(request: Record<string, unknown> = {}) {
  return oauthModelForRequest("anthropic", "claude-test", "token", request) as any;
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

  it("does not send unsupported sampling temperature", () => {
    const model = openAiModel([], { temperature: 0 });

    const body = model.body([new HumanMessage("inspect")]);

    expect(body).not.toHaveProperty("temperature");
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

describe("Anthropic OAuth model request options", () => {
  it("continues to send supported sampling temperature", () => {
    const model = anthropicModel({ temperature: 0 });

    const body = model.body([new HumanMessage("inspect")]);

    expect(body.temperature).toBe(0);
  });
});

describe("OAuth provider error redaction", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it.each([
    ["Anthropic", () => anthropicModel()],
    ["OpenAI Codex", () => openAiModel([])],
  ])("does not expose a non-2xx %s response body", async (_provider, createModel) => {
    const sentinel = "raw-provider-body-and-model-content-sentinel";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(`{"error":"${sentinel}"}`, { status: 503 }) as never,
    );

    const error = await createModel()
      .invoke([new HumanMessage("inspect")])
      .catch((failure: unknown) => failure);
    const serialized = JSON.stringify(error, Object.getOwnPropertyNames(error));

    expect(String(error)).toBe(
      "BridgePublicError: Provider is temporarily unavailable (HTTP 503).",
    );
    expect(serialized).not.toContain(sentinel);
  });

  it("does not expose malformed Anthropic success content", async () => {
    const sentinel = "raw-malformed-provider-response-sentinel";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(`not-json ${sentinel}`, { status: 200 }) as never,
    );

    const error = await anthropicModel()
      .invoke([new HumanMessage("inspect")])
      .catch((failure: unknown) => failure);

    expect(String(error)).toBe("BridgePublicError: Provider returned an invalid response.");
    expect(JSON.stringify(error, Object.getOwnPropertyNames(error))).not.toContain(sentinel);
  });
});

function stripCacheControl(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripCacheControl);
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([key]) => key !== "cache_control")
      .map(([key, entry]) => [key, stripCacheControl(entry)]);
    return Object.fromEntries(entries);
  }
  return value;
}

describe("Anthropic OAuth model prompt caching", () => {
  it("marks only the last tool definition as cacheable", () => {
    const model = anthropicModel().bindTools([
      { name: "tree_sitter:query", description: "AST query", schema: toolSchema },
      { name: "joern:taint_paths", description: "taint paths", schema: toolSchema },
    ]);

    const body = model.body([new HumanMessage("inspect")]);

    expect(body.tools[0]).not.toHaveProperty("cache_control");
    expect(body.tools[1].cache_control).toEqual({ type: "ephemeral" });
    expect(body.tools[1].name).toBe("joern:taint_paths");
    expect(body.tools[1].input_schema).toEqual(toolSchema);
  });

  it("keeps the cached system prompt text byte-identical", () => {
    const body = anthropicModel().body([new SystemMessage("Do the task."), new HumanMessage("go")]);

    expect(body.system).toEqual([
      { type: "text", text: "You are Claude Code, Anthropic's official CLI for Claude." },
      { type: "text", text: "Do the task.", cache_control: { type: "ephemeral" } },
    ]);
  });

  it("leaves a single-shot user prompt unmarked", () => {
    const body = anthropicModel().body([new HumanMessage("one-off finding text")]);

    expect(body.messages).toEqual([{ role: "user", content: "one-off finding text" }]);
  });

  it("marks the last turn of a multi-turn history without changing content", () => {
    const body = anthropicModel().body([
      new HumanMessage("start"),
      new AIMessage("calling tool"),
      new ToolMessage({ tool_call_id: "call_1", content: "tool output" }),
    ]);

    expect(body.messages[0]).toEqual({ role: "user", content: "start" });
    expect(body.messages[1]).toEqual({ role: "assistant", content: "calling tool" });
    expect(body.messages[2]).toEqual({
      role: "user",
      content: [
        {
          type: "tool_result",
          tool_use_id: "call_1",
          content: "tool output",
          cache_control: { type: "ephemeral" },
        },
      ],
    });
  });

  it("adds at most three breakpoints and changes nothing but cache markers", () => {
    const model = anthropicModel({ maxTokens: 512 }).bindTools([
      { name: "codeql:query", description: "run query", schema: toolSchema },
    ]);

    const body = model.body([
      new SystemMessage("Hunt for taint flows."),
      new HumanMessage("start"),
      new AIMessage("answer"),
      new HumanMessage("follow-up"),
    ]);

    const breakpoints = JSON.stringify(body).split('"cache_control"').length - 1;
    expect(breakpoints).toBeLessThanOrEqual(4);
    expect(breakpoints).toBe(3);
    expect(stripCacheControl(body)).toEqual({
      model: "claude-test",
      max_tokens: 512,
      system: [
        { type: "text", text: "You are Claude Code, Anthropic's official CLI for Claude." },
        { type: "text", text: "Hunt for taint flows." },
      ],
      tools: [{ name: "codeql:query", description: "run query", input_schema: toolSchema }],
      messages: [
        { role: "user", content: "start" },
        { role: "assistant", content: "answer" },
        { role: "user", content: [{ type: "text", text: "follow-up" }] },
      ],
    });
  });
});

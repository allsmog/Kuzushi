import { beforeEach, describe, expect, it, vi } from "vitest";
import { CodexAgentRuntime } from "../../src/agent-runtime/codex.js";
import type { AgentMessage, AgentQueryOptions } from "../../src/agent-runtime/types.js";

const codexMock = vi.hoisted(() => {
  type Event = Record<string, unknown>;

  const state = {
    constructorOptions: [] as unknown[],
    startThreadOptions: [] as unknown[],
    runStreamedCalls: [] as Array<{ input: unknown; options: unknown; threadId: number }>,
    eventBatches: [] as Event[][],
    nextThreadId: 1,
  };

  class MockThread {
    readonly mockId = state.nextThreadId++;

    async runStreamed(
      input: unknown,
      options: unknown,
    ): Promise<{ events: AsyncGenerator<Event> }> {
      state.runStreamedCalls.push({ input, options, threadId: this.mockId });
      const batch = state.eventBatches.shift() ?? [];
      return {
        events: (async function* () {
          for (const event of batch) {
            yield event;
          }
        })(),
      };
    }
  }

  class MockCodex {
    constructor(options?: unknown) {
      state.constructorOptions.push(options);
    }

    startThread(options?: unknown): MockThread {
      state.startThreadOptions.push(options);
      return new MockThread();
    }
  }

  return { state, MockCodex };
});

vi.mock("@openai/codex-sdk", () => ({
  Codex: codexMock.MockCodex,
}));

function baseOptions(overrides: Partial<AgentQueryOptions> = {}): AgentQueryOptions {
  return {
    cwd: "/tmp/repo",
    model: "openai:gpt-5.5",
    permissionMode: "dontAsk",
    ...overrides,
  };
}

async function collect(iterable: AsyncIterable<AgentMessage>): Promise<AgentMessage[]> {
  const messages: AgentMessage[] = [];
  for await (const message of iterable) {
    messages.push(message);
  }
  return messages;
}

describe("CodexAgentRuntime", () => {
  beforeEach(() => {
    codexMock.state.constructorOptions.length = 0;
    codexMock.state.startThreadOptions.length = 0;
    codexMock.state.runStreamedCalls.length = 0;
    codexMock.state.eventBatches.length = 0;
    codexMock.state.nextThreadId = 1;
  });

  it("maps query options to a read-only Codex streamed turn", async () => {
    codexMock.state.eventBatches.push([
      { type: "thread.started", thread_id: "thread-1" },
      {
        type: "item.completed",
        item: { id: "msg-1", type: "agent_message", text: "done" },
      },
      {
        type: "turn.completed",
        usage: {
          input_tokens: 10,
          cached_input_tokens: 0,
          output_tokens: 4,
          reasoning_output_tokens: 2,
        },
      },
    ]);

    const runtime = new CodexAgentRuntime({ apiKey: "sk-test", baseUrl: "https://example.test" });
    const messages = await collect(
      runtime.query({
        prompt: "review",
        options: baseOptions({ effort: "max" }),
      }),
    );

    expect(codexMock.state.constructorOptions[0]).toEqual({
      apiKey: "sk-test",
      baseUrl: "https://example.test",
    });
    expect(codexMock.state.startThreadOptions[0]).toMatchObject({
      model: "gpt-5.5",
      workingDirectory: "/tmp/repo",
      approvalPolicy: "never",
      sandboxMode: "read-only",
      modelReasoningEffort: "xhigh",
    });
    expect(codexMock.state.runStreamedCalls[0]?.input).toBe("review");
    expect(messages).toContainEqual({
      type: "assistant",
      content: [{ type: "text", text: "done" }],
    });
    expect(messages.at(-1)).toMatchObject({
      type: "result",
      subtype: "success",
      result: "done",
      totalCostUsd: 0,
    });
  });

  it("passes output schemas and parses structured JSON responses", async () => {
    const schema = {
      type: "object",
      properties: { ok: { type: "boolean" } },
      required: ["ok"],
    };
    codexMock.state.eventBatches.push([
      {
        type: "item.completed",
        item: { id: "msg-1", type: "agent_message", text: '```json\n{"ok":true}\n```' },
      },
      {
        type: "turn.completed",
        usage: {
          input_tokens: 1,
          cached_input_tokens: 0,
          output_tokens: 1,
          reasoning_output_tokens: 0,
        },
      },
    ]);

    const runtime = new CodexAgentRuntime();
    const messages = await collect(
      runtime.query({
        prompt: "json",
        options: baseOptions({
          outputFormat: { type: "json_schema", schema },
        }),
      }),
    );

    expect(codexMock.state.runStreamedCalls[0]?.options).toMatchObject({
      outputSchema: schema,
    });
    expect(messages.at(-1)).toMatchObject({
      type: "result",
      subtype: "success",
      structuredOutput: { ok: true },
    });
  });

  it("surfaces command activity as tool messages", async () => {
    codexMock.state.eventBatches.push([
      {
        type: "item.started",
        item: {
          id: "cmd-1",
          type: "command_execution",
          command: "rg TODO",
          aggregated_output: "",
          status: "in_progress",
        },
      },
      {
        type: "item.updated",
        item: {
          id: "cmd-1",
          type: "command_execution",
          command: "rg TODO",
          aggregated_output: "src/a.ts:TODO",
          status: "in_progress",
        },
      },
      {
        type: "item.completed",
        item: {
          id: "cmd-1",
          type: "command_execution",
          command: "rg TODO",
          aggregated_output: "src/a.ts:TODO",
          exit_code: 0,
          status: "completed",
        },
      },
      {
        type: "item.completed",
        item: { id: "msg-1", type: "agent_message", text: "ok" },
      },
    ]);

    const runtime = new CodexAgentRuntime();
    const messages = await collect(runtime.query({ prompt: "tools", options: baseOptions() }));

    expect(messages).toContainEqual({
      type: "tool-call-start",
      toolUseId: "cmd-1",
      toolName: "Bash",
    });
    expect(messages).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "tool-progress",
          toolUseId: "cmd-1",
          toolName: "Bash",
        }),
        {
          type: "tool-result",
          toolUseId: "cmd-1",
          isError: false,
          content: "src/a.ts:TODO",
        },
      ]),
    );
  });

  it("returns runtime errors for failed turns", async () => {
    codexMock.state.eventBatches.push([
      { type: "turn.failed", error: { message: "model unavailable" } },
    ]);

    const runtime = new CodexAgentRuntime();
    const messages = await collect(runtime.query({ prompt: "fail", options: baseOptions() }));

    expect(messages.at(-1)).toMatchObject({
      type: "result",
      subtype: "error_runtime",
      errors: ["model unavailable"],
    });
  });

  it("returns an aborted result when the caller signal is already aborted", async () => {
    codexMock.state.eventBatches.push([]);
    const abortController = new AbortController();
    abortController.abort();

    const runtime = new CodexAgentRuntime();
    const messages = await collect(
      runtime.query({
        prompt: "abort",
        options: baseOptions({ abortController }),
      }),
    );

    expect(codexMock.state.runStreamedCalls[0]?.options).toMatchObject({
      signal: abortController.signal,
    });
    expect(messages.at(-1)).toMatchObject({
      type: "result",
      subtype: "error_aborted",
    });
  });

  it("reuses one Codex thread for session queries", async () => {
    codexMock.state.eventBatches.push(
      [{ type: "item.completed", item: { id: "msg-1", type: "agent_message", text: "one" } }],
      [{ type: "item.completed", item: { id: "msg-2", type: "agent_message", text: "two" } }],
    );

    const runtime = new CodexAgentRuntime();
    const session = runtime.createSession(baseOptions());
    const first = await collect(session.query("first"));
    const second = await collect(session.query("second"));
    await session.close();

    expect(codexMock.state.startThreadOptions).toHaveLength(1);
    expect(codexMock.state.runStreamedCalls.map((call) => call.threadId)).toEqual([1, 1]);
    expect(first.at(-1)).toMatchObject({ type: "result", subtype: "success", result: "one" });
    expect(second.at(-1)).toMatchObject({ type: "result", subtype: "success", result: "two" });
  });
});

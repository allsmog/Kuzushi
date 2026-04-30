import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AgentMessage, AgentQueryRequest } from "../../src/agent-runtime/types.js";

const ORIGINAL_ANTHROPIC_API_KEY = process.env["ANTHROPIC_API_KEY"];
const ORIGINAL_ANTHROPIC_AUTH_TOKEN = process.env["ANTHROPIC_AUTH_TOKEN"];
const ORIGINAL_ANTHROPIC_OAUTH_TOKEN = process.env["ANTHROPIC_OAUTH_TOKEN"];
const ORIGINAL_ANTHROPIC_BASE_URL = process.env["ANTHROPIC_BASE_URL"];

const { completeMock, getModelMock, validateToolCallMock, streamMock } = vi.hoisted(() => ({
  completeMock: vi.fn(),
  getModelMock: vi.fn(),
  validateToolCallMock: vi.fn(),
  streamMock: vi.fn(),
}));

vi.mock("@mariozechner/pi-ai", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@mariozechner/pi-ai")>();
  return {
    ...actual,
    complete: completeMock,
    getModel: getModelMock,
    validateToolCall: validateToolCallMock,
    stream: streamMock,
  };
});

/**
 * Build a mock AssistantMessageEventStream that yields scripted events
 * (including the terminal `done`) and resolves `.result()` with the
 * AssistantMessage from the `done` event. Used by tests that previously
 * drove the runtime via completeMock — after the streaming migration,
 * runTurnLoop calls stream() instead of complete().
 */
function _makeEventStream(assistant: ReturnType<typeof makeAssistantMessage>) {
  const events: Array<Record<string, unknown>> = [
    { type: "done", reason: assistant.stopReason, message: assistant },
  ];
  return {
    [Symbol.asyncIterator]: async function* () {
      for (const e of events) yield e;
    },
    result: async () => assistant,
  };
}

/**
 * Adapter for legacy tests: each call to streamMock consumes the next
 * scripted return from completeMock and wraps it as a done-only event
 * stream. Tests that previously set up `completeMock.mockResolvedValueOnce`
 * keep working; tests that want mid-stream events can `streamMock.mockReturnValueOnce`
 * with a richer event list.
 */
function wireCompleteMockToStreamMock(): void {
  streamMock.mockImplementation((...args: unknown[]) => {
    // Delegate to completeMock so the per-call return-value queue
    // (mockResolvedValueOnce / mockImplementationOnce) is honored.
    const msgPromise = Promise.resolve(
      (completeMock as unknown as (...a: unknown[]) => unknown)(...args) as ReturnType<
        typeof makeAssistantMessage
      >,
    );
    return {
      [Symbol.asyncIterator]: async function* () {
        const msg = await msgPromise;
        yield { type: "done", reason: msg.stopReason, message: msg };
      },
      result: () => msgPromise,
    };
  });
}

import { isTransientError, PiAiAgentRuntime } from "../../src/agent-runtime/pi-ai.js";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-piai-test-"));
  tempDirs.push(dir);
  return dir;
}

function makeModel() {
  return {
    id: "gpt-4o",
    name: "gpt-4o",
    api: "openai-responses",
    provider: "openai",
    baseUrl: "https://api.openai.com/v1",
    reasoning: false,
    input: ["text"],
    cost: {
      input: 0,
      output: 0,
      cacheRead: 0,
      cacheWrite: 0,
    },
    contextWindow: 128000,
    maxTokens: 16384,
  };
}

function makeAssistantMessage(
  content: Array<Record<string, unknown>>,
  options: {
    stopReason?: "stop" | "length" | "toolUse" | "error" | "aborted";
    totalCost?: number;
    errorMessage?: string;
  } = {},
) {
  return {
    role: "assistant",
    content,
    api: "openai-responses",
    provider: "openai",
    model: "gpt-4o",
    usage: {
      input: 100,
      output: 50,
      cacheRead: 0,
      cacheWrite: 0,
      totalTokens: 150,
      cost: {
        input: 0,
        output: 0,
        cacheRead: 0,
        cacheWrite: 0,
        total: options.totalCost ?? 0,
      },
    },
    stopReason: options.stopReason ?? "stop",
    ...(options.errorMessage ? { errorMessage: options.errorMessage } : {}),
    timestamp: Date.now(),
  };
}

function makeRequest(
  cwd: string,
  overrides: Partial<AgentQueryRequest["options"]> = {},
): AgentQueryRequest {
  return {
    prompt: "Analyze this repository.",
    options: {
      cwd,
      model: "openai:gpt-4o",
      ...overrides,
    },
  };
}

async function collectMessages(runtime: PiAiAgentRuntime, request: AgentQueryRequest) {
  const messages: AgentMessage[] = [];
  for await (const message of runtime.query(request)) {
    messages.push(message);
  }
  return messages;
}

beforeEach(() => {
  completeMock.mockReset();
  getModelMock.mockReset();
  validateToolCallMock.mockReset();
  streamMock.mockReset();
  getModelMock.mockReturnValue(makeModel());
  validateToolCallMock.mockImplementation((_tools, toolCall) => toolCall.arguments);
  // Default streamMock delegates to completeMock's scripted return values so
  // tests that only set up completeMock.mockResolvedValue(...) keep working
  // after the runtime switched from complete() to stream().
  wireCompleteMockToStreamMock();
});

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }

  if (ORIGINAL_ANTHROPIC_API_KEY === undefined) {
    delete process.env["ANTHROPIC_API_KEY"];
  } else {
    process.env["ANTHROPIC_API_KEY"] = ORIGINAL_ANTHROPIC_API_KEY;
  }

  if (ORIGINAL_ANTHROPIC_AUTH_TOKEN === undefined) {
    delete process.env["ANTHROPIC_AUTH_TOKEN"];
  } else {
    process.env["ANTHROPIC_AUTH_TOKEN"] = ORIGINAL_ANTHROPIC_AUTH_TOKEN;
  }

  if (ORIGINAL_ANTHROPIC_OAUTH_TOKEN === undefined) {
    delete process.env["ANTHROPIC_OAUTH_TOKEN"];
  } else {
    process.env["ANTHROPIC_OAUTH_TOKEN"] = ORIGINAL_ANTHROPIC_OAUTH_TOKEN;
  }

  if (ORIGINAL_ANTHROPIC_BASE_URL === undefined) {
    delete process.env["ANTHROPIC_BASE_URL"];
  } else {
    process.env["ANTHROPIC_BASE_URL"] = ORIGINAL_ANTHROPIC_BASE_URL;
  }
});

describe("PiAiAgentRuntime", () => {
  it("returns a single-turn successful result", async () => {
    const cwd = makeTempDir();
    completeMock.mockResolvedValue(
      makeAssistantMessage([{ type: "text", text: '{"ok":true}' }], { totalCost: 0.0123 }),
    );

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));

    expect(getModelMock).toHaveBeenCalledWith("openai", "gpt-4o");
    expect(messages.some((message) => message.type === "assistant")).toBe(true);
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "success",
      result: '{"ok":true}',
      numTurns: 1,
      totalCostUsd: 0.0123,
    });
  });

  it("applies configured anthropic credentials from runtime config", async () => {
    const cwd = makeTempDir();
    const originalApiKey = process.env["ANTHROPIC_API_KEY"];
    const originalAuthToken = process.env["ANTHROPIC_AUTH_TOKEN"];
    const originalOauthToken = process.env["ANTHROPIC_OAUTH_TOKEN"];
    const originalBaseUrl = process.env["ANTHROPIC_BASE_URL"];
    completeMock.mockImplementation(async () => {
      expect(process.env["ANTHROPIC_API_KEY"]).toBe("sk-config");
      expect(process.env["ANTHROPIC_AUTH_TOKEN"]).toBe("sk-ant-oat-config");
      expect(process.env["ANTHROPIC_OAUTH_TOKEN"]).toBe("sk-ant-oat-config");
      expect(process.env["ANTHROPIC_BASE_URL"]).toBe("https://api.example.com/");
      return makeAssistantMessage([{ type: "text", text: '{"ok":true}' }]);
    });

    const runtime = new PiAiAgentRuntime({
      apiKey: "sk-config",
      authToken: "sk-ant-oat-config",
      baseUrl: "https://api.example.com/",
    });
    await collectMessages(runtime, makeRequest(cwd));

    expect(process.env["ANTHROPIC_API_KEY"]).toBe(originalApiKey);
    expect(process.env["ANTHROPIC_AUTH_TOKEN"]).toBe(originalAuthToken);
    expect(process.env["ANTHROPIC_OAUTH_TOKEN"]).toBe(originalOauthToken);
    expect(process.env["ANTHROPIC_BASE_URL"]).toBe(originalBaseUrl);
  });

  it("handles multi-turn tool loop and emits tool events", async () => {
    const cwd = makeTempDir();
    writeFileSync(path.join(cwd, "target.ts"), "line1\nline2\nline3\n", "utf8");

    completeMock
      .mockResolvedValueOnce(
        makeAssistantMessage(
          [
            {
              type: "toolCall",
              id: "tool-read-1",
              name: "Read",
              arguments: { path: "target.ts", offset: 1, limit: 1 },
            },
          ],
          { stopReason: "toolUse", totalCost: 0.004 },
        ),
      )
      .mockResolvedValueOnce(
        makeAssistantMessage([{ type: "text", text: '{"verdict":"fp"}' }], { totalCost: 0.006 }),
      );

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));

    expect(completeMock).toHaveBeenCalledTimes(2);
    expect(messages.some((message) => message.type === "tool-progress")).toBe(true);
    expect(messages.some((message) => message.type === "tool-summary")).toBe(true);
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "success",
      result: '{"verdict":"fp"}',
      numTurns: 2,
      totalCostUsd: 0.01,
    });

    const secondContext = completeMock.mock.calls[1]?.[1];
    expect(
      secondContext.messages.some((message: { role: string }) => message.role === "toolResult"),
    ).toBe(true);
  });

  it("executes module-scoped custom tools", async () => {
    const cwd = makeTempDir();
    completeMock
      .mockResolvedValueOnce(
        makeAssistantMessage(
          [
            {
              type: "toolCall",
              id: "kb-1",
              name: "ThreatKbSearch",
              arguments: { query: "tenant reset", actorId: "actor-user" },
            },
          ],
          { stopReason: "toolUse" },
        ),
      )
      .mockResolvedValueOnce(makeAssistantMessage([{ type: "text", text: '{"ok":true}' }]));

    const runtime = new PiAiAgentRuntime();
    await collectMessages(
      runtime,
      makeRequest(cwd, {
        allowedTools: ["ThreatKbSearch"],
        customTools: [
          {
            name: "ThreatKbSearch",
            description: "Search threat model KB.",
            parameters: { type: "object", properties: {} },
            execute(input, options) {
              expect(options.cwd).toBe(cwd);
              expect(options.toolUseId).toBe("kb-1");
              return JSON.stringify({ input, hits: [{ id: "threat:t1" }] });
            },
          },
        ],
      }),
    );

    const firstContext = completeMock.mock.calls[0]?.[1];
    expect(firstContext.systemPrompt).toContain("ThreatKbSearch");
    expect(firstContext.tools?.map((tool: { name: string }) => tool.name)).toEqual([
      "ThreatKbSearch",
    ]);
    const secondContext = completeMock.mock.calls[1]?.[1];
    const toolResult = secondContext.messages.find(
      (message: { role?: string; toolName?: string }) =>
        message.role === "toolResult" && message.toolName === "ThreatKbSearch",
    );
    expect(JSON.stringify(toolResult)).toContain("threat:t1");
  });

  it("enables xhigh thinking options for pi-ai providers", async () => {
    const cwd = makeTempDir();
    completeMock.mockResolvedValue(
      makeAssistantMessage([{ type: "text", text: '{"ok":true}' }], { totalCost: 0.0123 }),
    );

    const runtime = new PiAiAgentRuntime();
    await collectMessages(runtime, makeRequest(cwd, { effort: "xhigh" }));

    const streamOptions = completeMock.mock.calls[0]?.[2];
    expect(streamOptions).toMatchObject({
      thinkingEnabled: true,
      thinkingDisplay: "summarized",
      effort: "xhigh",
      reasoning: "xhigh",
      reasoningEffort: "xhigh",
    });
  });

  it("treats allowedTools=[] as explicit no-tools mode", async () => {
    const cwd = makeTempDir();
    completeMock
      .mockResolvedValueOnce(
        makeAssistantMessage(
          [
            {
              type: "toolCall",
              id: "tool-read-1",
              name: "Read",
              arguments: { path: "target.ts" },
            },
          ],
          { stopReason: "toolUse" },
        ),
      )
      .mockResolvedValueOnce(makeAssistantMessage([{ type: "text", text: '{"ok":true}' }]));

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd, { allowedTools: [] }));

    expect(completeMock).toHaveBeenCalledTimes(2);
    const firstContext = completeMock.mock.calls[0]?.[1];
    expect(firstContext.tools).toBeUndefined();
    const secondContext = completeMock.mock.calls[1]?.[1];
    const deniedToolResult = secondContext.messages.find(
      (message: { role?: string; content?: unknown }) =>
        message.role === "toolResult" &&
        Array.isArray(message.content) &&
        message.content.some(
          (block) =>
            typeof block === "object" &&
            block !== null &&
            "text" in block &&
            typeof (block as { text?: unknown }).text === "string" &&
            (block as { text: string }).text.includes('Tool "Read" is not enabled'),
        ),
    );
    expect(deniedToolResult).toBeDefined();
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "success",
    });
  });

  it("returns aborted result when signal is already aborted", async () => {
    const cwd = makeTempDir();
    const abortController = new AbortController();
    abortController.abort();

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd, { abortController }));

    expect(completeMock).not.toHaveBeenCalled();
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "error_aborted",
    });
  });

  it("enforces max budget when another tool turn would be required", async () => {
    const cwd = makeTempDir();
    completeMock.mockResolvedValue(
      makeAssistantMessage(
        [
          {
            type: "toolCall",
            id: "tool-read-1",
            name: "Read",
            arguments: { path: "target.ts" },
          },
        ],
        { stopReason: "toolUse", totalCost: 1.2 },
      ),
    );

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd, { maxBudgetUsd: 1 }));

    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "error_budget_exceeded",
    });
  });

  it("returns success for final responses even if they exceed budget", async () => {
    const cwd = makeTempDir();
    completeMock.mockResolvedValue(
      makeAssistantMessage([{ type: "text", text: '{"ok":true}' }], { totalCost: 1.2 }),
    );

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd, { maxBudgetUsd: 1 }));

    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "success",
      result: '{"ok":true}',
    });
  });

  it("returns tool deny as error to LLM instead of hard-stopping", async () => {
    const cwd = makeTempDir();
    completeMock
      .mockResolvedValueOnce(
        makeAssistantMessage(
          [
            {
              type: "toolCall",
              id: "tool-read-1",
              name: "Read",
              arguments: { path: "target.ts" },
            },
          ],
          { stopReason: "toolUse", totalCost: 0.01 },
        ),
      )
      .mockResolvedValueOnce(
        makeAssistantMessage([{ type: "text", text: "Understood, Read is not allowed." }]),
      );

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(
      runtime,
      makeRequest(cwd, {
        canUseTool: () => ({
          behavior: "deny",
          message: "Read is not permitted in this run.",
        }),
      }),
    );

    expect(completeMock).toHaveBeenCalledTimes(2);
    const toolSummary = messages.find((m) => m.type === "tool-summary");
    expect(toolSummary).toBeDefined();
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "success",
    });
  });

  it("generates unique fallback tool IDs when provider omits tool call IDs", async () => {
    const cwd = makeTempDir();
    writeFileSync(path.join(cwd, "target.ts"), "line1\nline2\n", "utf8");

    completeMock
      .mockResolvedValueOnce(
        makeAssistantMessage(
          [
            {
              type: "toolCall",
              name: "Read",
              arguments: { path: "target.ts", offset: 0, limit: 1 },
            },
            {
              type: "toolCall",
              name: "Read",
              arguments: { path: "target.ts", offset: 1, limit: 1 },
            },
          ],
          { stopReason: "toolUse" },
        ),
      )
      .mockResolvedValueOnce(makeAssistantMessage([{ type: "text", text: '{"ok":true}' }]));

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));

    const toolProgressIds = messages
      .filter(
        (message): message is Extract<AgentMessage, { type: "tool-progress" }> =>
          message.type === "tool-progress",
      )
      .map((message) => message.toolUseId);

    expect(toolProgressIds).toHaveLength(2);
    expect(new Set(toolProgressIds).size).toBe(2);
  });

  it("parses structured output from final text when outputFormat is provided", async () => {
    const cwd = makeTempDir();
    completeMock.mockResolvedValue(
      makeAssistantMessage([
        {
          type: "text",
          text: '```json\n{"fingerprint":"abc","verdict":"fp"}\n```',
        },
      ]),
    );

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(
      runtime,
      makeRequest(cwd, {
        outputFormat: {
          type: "json_schema",
          schema: {
            type: "object",
            properties: {
              fingerprint: { type: "string" },
              verdict: { type: "string" },
            },
            required: ["fingerprint", "verdict"],
          },
        },
      }),
    );

    const result = messages[messages.length - 1];
    expect(result).toMatchObject({
      type: "result",
      subtype: "success",
      structuredOutput: {
        fingerprint: "abc",
        verdict: "fp",
      },
    });

    const firstContext = completeMock.mock.calls[0]?.[1];
    expect(firstContext.systemPrompt).toContain("must match this schema");
    expect(firstContext.systemPrompt).toContain('"fingerprint"');
  });

  it("retries strict structured output when the first response is invalid", async () => {
    const cwd = makeTempDir();
    completeMock
      .mockResolvedValueOnce(
        makeAssistantMessage([
          {
            type: "text",
            text: "not valid json",
          },
        ]),
      )
      .mockResolvedValueOnce(
        makeAssistantMessage([
          {
            type: "text",
            text: '{"fingerprint":"abc","verdict":"tp"}',
          },
        ]),
      );

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(
      runtime,
      makeRequest(cwd, {
        outputFormat: {
          type: "json_schema",
          schema: {
            type: "object",
            properties: {
              fingerprint: { type: "string" },
              verdict: { type: "string" },
            },
            required: ["fingerprint", "verdict"],
          },
          strict: true,
          retryInvalidStructuredOutput: 1,
        },
      }),
    );

    expect(completeMock).toHaveBeenCalledTimes(2);
    const secondContext = completeMock.mock.calls[1]?.[1];
    const correctiveUserMessage = secondContext.messages.find(
      (message: { role?: string; content?: unknown }) =>
        message.role === "user" &&
        typeof message.content === "string" &&
        message.content.includes("Return JSON only matching schema; no prose/code fences."),
    );
    expect(correctiveUserMessage).toBeDefined();
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "success",
      structuredOutput: {
        fingerprint: "abc",
        verdict: "tp",
      },
    });
  });

  it("returns error_output_format when strict structured output retries are exhausted", async () => {
    const cwd = makeTempDir();
    completeMock
      .mockResolvedValueOnce(
        makeAssistantMessage([
          {
            type: "text",
            text: "still not json",
          },
        ]),
      )
      .mockResolvedValueOnce(
        makeAssistantMessage([
          {
            type: "text",
            text: "still invalid",
          },
        ]),
      );

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(
      runtime,
      makeRequest(cwd, {
        outputFormat: {
          type: "json_schema",
          schema: {
            type: "object",
            properties: {
              fingerprint: { type: "string" },
              verdict: { type: "string" },
            },
            required: ["fingerprint", "verdict"],
          },
          strict: true,
          retryInvalidStructuredOutput: 1,
        },
      }),
    );

    expect(completeMock).toHaveBeenCalledTimes(2);
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "error_output_format",
    });
  });

  it("retries transient errors from complete() and succeeds", async () => {
    vi.useFakeTimers();
    try {
      const cwd = makeTempDir();
      completeMock
        .mockRejectedValueOnce(new Error("503 Service Temporarily Unavailable"))
        .mockResolvedValueOnce(
          makeAssistantMessage([{ type: "text", text: '{"ok":true}' }], { totalCost: 0.01 }),
        );

      const runtime = new PiAiAgentRuntime();
      const done = collectMessages(runtime, makeRequest(cwd));

      // Advance past the retry backoff delay
      await vi.advanceTimersByTimeAsync(10_000);

      const messages = await done;

      expect(completeMock).toHaveBeenCalledTimes(2);
      expect(messages[messages.length - 1]).toMatchObject({
        type: "result",
        subtype: "success",
        result: '{"ok":true}',
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not retry non-transient errors from complete()", async () => {
    const cwd = makeTempDir();
    completeMock.mockRejectedValue(new Error("Invalid API key"));

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));

    expect(completeMock).toHaveBeenCalledTimes(1);
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "error_runtime",
    });
  });

  it("retries transient soft errors (stopReason=error) and succeeds", async () => {
    vi.useFakeTimers();
    try {
      const cwd = makeTempDir();
      completeMock
        .mockResolvedValueOnce(
          makeAssistantMessage([{ type: "text", text: "" }], {
            stopReason: "error",
            errorMessage: "overloaded",
          }),
        )
        .mockResolvedValueOnce(
          makeAssistantMessage([{ type: "text", text: '{"ok":true}' }], { totalCost: 0.01 }),
        );

      const runtime = new PiAiAgentRuntime();
      const done = collectMessages(runtime, makeRequest(cwd));

      // Advance past the retry backoff delay
      await vi.advanceTimersByTimeAsync(10_000);

      const messages = await done;

      expect(completeMock).toHaveBeenCalledTimes(2);
      expect(messages[messages.length - 1]).toMatchObject({
        type: "result",
        subtype: "success",
        result: '{"ok":true}',
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("translates context-overflow errors into error_context_overflow with actionable hint", async () => {
    const cwd = makeTempDir();
    // Simulate the exact Anthropic/Vertex provider response for a
    // single request exceeding the 1M input-context cap.
    completeMock.mockResolvedValue(
      makeAssistantMessage([{ type: "text", text: "" }], {
        stopReason: "error",
        errorMessage:
          '400 {"error":{"message":"prompt is too long: 1355012 tokens > 1000000 maximum"}}',
      }),
    );

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));

    const final = messages[messages.length - 1] as Extract<AgentMessage, { type: "result" }> & {
      errors?: string[];
      subtype: string;
    };
    expect(final.subtype).toBe("error_context_overflow");
    // Hint must point to the two knobs that actually fix the overflow.
    const err = final.errors?.[0] ?? "";
    expect(err).toContain("1M-token input limit");
    expect(err).toMatch(/maxTurnsPerHunt/);
    // Raw provider error is preserved so operators can see the token count.
    expect(err).toContain("prompt is too long");
  });

  it("auto-compacts old tool-results when input tokens cross the context-window threshold", async () => {
    // Goal: simulate a multi-turn run where turn 1 reports input usage
    // > 75% of contextWindow. The context.messages array is shared
    // across turns; after turn 1's assistant is appended, pi-ai compacts
    // any already-present old toolResult entries so turn 2's request
    // stays under the cap.
    const cwd = makeTempDir();
    writeFileSync(path.join(cwd, "big.ts"), "x\n".repeat(10), "utf8");

    // Small contextWindow → threshold easy to trigger with mock usage.
    getModelMock.mockReturnValue({
      ...makeModel(),
      contextWindow: 1_000,
    });

    const assistantWithToolCall = (id: string, usageInput: number) => {
      const a = makeAssistantMessage(
        [{ type: "toolCall", id, name: "Read", arguments: { path: "big.ts" } }],
        { stopReason: "toolUse" },
      );
      a.usage.input = usageInput;
      return a;
    };

    // Observe the context fed into each complete call BEFORE any
    // compaction. We snapshot each turn's tool-result state so we can
    // compare turn 2 vs turn 1.
    const observed: Array<Array<{ toolCallId: string; textLen: number }>> = [];
    // Turn-specific assistant responses — each with high usage.input to
    // force compaction between turns.
    const scripted = [
      assistantWithToolCall("t1", 900),
      assistantWithToolCall("t2", 900),
      makeAssistantMessage([{ type: "text", text: "done" }]),
    ];
    let call = 0;
    completeMock.mockImplementation(async (_m: unknown, context: unknown) => {
      const ctx = context as { messages: Array<Record<string, unknown>> };
      observed.push(
        ctx.messages
          .filter((m) => m.role === "toolResult")
          .map((m) => {
            const content = (m as { content: unknown }).content;
            const firstText = Array.isArray(content)
              ? (content.find((c: { type?: string }) => c.type === "text") as
                  | { text?: string }
                  | undefined)
              : undefined;
            return {
              toolCallId: (m as { toolCallId: string }).toolCallId,
              textLen: firstText?.text?.length ?? 0,
            };
          }),
      );
      return scripted[call++] ?? scripted[scripted.length - 1];
    });

    const runtime = new PiAiAgentRuntime();
    await collectMessages(runtime, makeRequest(cwd));

    // At turn 2's request, turn 1's toolResult ("t1") should already
    // be compacted to the elided stub (well under 200 chars).
    expect(observed.length).toBeGreaterThanOrEqual(2);
    const turn2 = observed[1]!;
    const t1Result = turn2.find((r) => r.toolCallId === "t1");
    expect(t1Result).toBeDefined();
    expect(t1Result!.textLen).toBeLessThan(200);
  });

  it("detects multiple provider context-overflow phrasings", async () => {
    const cwd = makeTempDir();
    // "request_too_large" appears in Anthropic responses for oversized
    // prompts — same bucket, same translation.
    completeMock.mockResolvedValue(
      makeAssistantMessage([{ type: "text", text: "" }], {
        stopReason: "error",
        errorMessage: "request_too_large: payload exceeded",
      }),
    );
    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));
    const final = messages[messages.length - 1] as Extract<AgentMessage, { type: "result" }> & {
      subtype: string;
    };
    expect(final.subtype).toBe("error_context_overflow");
  });

  it("does not retry non-transient soft errors (stopReason=error)", async () => {
    const cwd = makeTempDir();
    completeMock.mockResolvedValue(
      makeAssistantMessage([{ type: "text", text: "" }], {
        stopReason: "error",
        errorMessage: "content policy violation",
      }),
    );

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));

    expect(completeMock).toHaveBeenCalledTimes(1);
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "error_runtime",
    });
  });

  // ── Tool-input normalization + retry cap + tool-result yielding ──

  it("normalizes camelCase tool args before validateToolCall", async () => {
    const cwd = makeTempDir();
    writeFileSync(path.join(cwd, "target.ts"), "x\n", "utf8");
    completeMock
      .mockResolvedValueOnce(
        makeAssistantMessage(
          [
            {
              type: "toolCall",
              id: "tool-1",
              name: "Write",
              // camelCase aliases — what weaker models actually emit.
              arguments: { filePath: path.join(cwd, "out.txt"), text: "hello" },
            },
          ],
          { stopReason: "toolUse" },
        ),
      )
      .mockResolvedValueOnce(makeAssistantMessage([{ type: "text", text: "done" }]));

    const runtime = new PiAiAgentRuntime();
    await collectMessages(runtime, makeRequest(cwd));

    // The normalizer rewrote filePath→file_path / text→content BEFORE AJV saw
    // the args, so validateToolCall received the canonical shape.
    expect(validateToolCallMock).toHaveBeenCalled();
    const firstCall = validateToolCallMock.mock.calls[0];
    const receivedToolCall = firstCall?.[1] as { arguments?: Record<string, unknown> };
    expect(receivedToolCall.arguments).toEqual({
      file_path: path.join(cwd, "out.txt"),
      content: "hello",
    });
    expect(receivedToolCall.arguments).not.toHaveProperty("filePath");
    expect(receivedToolCall.arguments).not.toHaveProperty("text");
  });

  it("yields tool-result isError:true for validation failures", async () => {
    const cwd = makeTempDir();
    completeMock
      .mockResolvedValueOnce(
        makeAssistantMessage(
          [
            {
              type: "toolCall",
              id: "tu-1",
              name: "Write",
              arguments: { garbage: "x" },
            },
          ],
          { stopReason: "toolUse" },
        ),
      )
      .mockResolvedValueOnce(makeAssistantMessage([{ type: "text", text: "done" }]));
    validateToolCallMock.mockImplementationOnce(() => {
      throw new Error(
        "Validation failed for tool \"Write\":\n  - : must have required property 'file_path'",
      );
    });

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));

    const toolResults = messages.filter((m) => m.type === "tool-result");
    expect(toolResults).toHaveLength(1);
    const [failure] = toolResults as Array<Extract<AgentMessage, { type: "tool-result" }>>;
    expect(failure.toolUseId).toBe("tu-1");
    expect(failure.isError).toBe(true);
    expect(failure.content).toContain("Validation failed for tool");
  });

  it("yields tool-result for permission deny", async () => {
    const cwd = makeTempDir();
    completeMock
      .mockResolvedValueOnce(
        makeAssistantMessage(
          [
            {
              type: "toolCall",
              id: "tu-deny",
              name: "Read",
              arguments: { path: "target.ts" },
            },
          ],
          { stopReason: "toolUse" },
        ),
      )
      .mockResolvedValueOnce(makeAssistantMessage([{ type: "text", text: "ok" }]));

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(
      runtime,
      makeRequest(cwd, {
        canUseTool: () => ({ behavior: "deny", message: "nope" }),
      }),
    );

    const toolResults = messages.filter((m) => m.type === "tool-result");
    expect(toolResults).toHaveLength(1);
    expect(toolResults[0]).toMatchObject({
      type: "tool-result",
      toolUseId: "tu-deny",
      isError: true,
      content: "nope",
    });
  });

  it("yields tool-result for successful tool execution (isError:false)", async () => {
    const cwd = makeTempDir();
    writeFileSync(path.join(cwd, "target.ts"), "line1\n", "utf8");
    completeMock
      .mockResolvedValueOnce(
        makeAssistantMessage(
          [
            {
              type: "toolCall",
              id: "tu-ok",
              name: "Read",
              arguments: { path: "target.ts" },
            },
          ],
          { stopReason: "toolUse" },
        ),
      )
      .mockResolvedValueOnce(makeAssistantMessage([{ type: "text", text: "done" }]));

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));

    const toolResults = messages.filter((m) => m.type === "tool-result");
    expect(toolResults).toHaveLength(1);
    expect(toolResults[0]).toMatchObject({
      type: "tool-result",
      toolUseId: "tu-ok",
      isError: false,
    });
  });

  it("aborts the turn loop after 3 same-tool validation failures", async () => {
    const cwd = makeTempDir();
    for (let i = 0; i < 5; i++) {
      completeMock.mockResolvedValueOnce(
        makeAssistantMessage(
          [
            {
              type: "toolCall",
              id: `tu-${i}`,
              name: "Write",
              arguments: { filePath: "/x" },
            },
          ],
          { stopReason: "toolUse" },
        ),
      );
    }
    // Force every validation call to fail (the normalizer makes filePath
    // canonical first, so this is a pure schema-level failure for the test).
    validateToolCallMock.mockImplementation(() => {
      throw new Error('Validation failed for tool "Write":\n  - extra: unknown property');
    });

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));

    // The cap fires after 3 same-tool failures — the LLM is only called 3
    // times (1 per turn) before we bail. The 4th+ mocks are never consumed.
    expect(completeMock).toHaveBeenCalledTimes(3);
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "error_tool_loop",
    });
    const finalErrorResult = messages[messages.length - 1] as Extract<
      AgentMessage,
      { type: "result" }
    > & {
      errors?: string[];
    };
    expect(finalErrorResult.errors?.[0] ?? "").toContain("3 times this turn");
    expect(finalErrorResult.errors?.[0] ?? "").toContain("Write");
  });

  it("interleaved successful OTHER tool does NOT reset the stuck tool's counter", async () => {
    // Write fail → Read success → Write fail → Read success → Write fail
    // should trip the Write cap at 3, because a Read success must NOT
    // reset Write's counter. This is the real-world PASTA S4 symptom.
    const cwd = makeTempDir();
    writeFileSync(path.join(cwd, "target.ts"), "x\n", "utf8");
    for (let i = 1; i <= 5; i++) {
      const name = i % 2 === 1 ? "Write" : "Read";
      const args = i % 2 === 1 ? { filePath: "/x" } : { path: "target.ts" };
      completeMock.mockResolvedValueOnce(
        makeAssistantMessage([{ type: "toolCall", id: `tu-${i}`, name, arguments: args }], {
          stopReason: "toolUse",
        }),
      );
    }
    validateToolCallMock.mockImplementation((_tools, tc) => {
      if (tc.name === "Write") {
        throw new Error('Validation failed for tool "Write":\n  - x: y');
      }
      return tc.arguments;
    });

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));

    // Cap trips on the 3rd Write failure. That's turn #5 (W/R/W/R/W),
    // so completeMock is called 5 times, not 6.
    expect(completeMock).toHaveBeenCalledTimes(5);
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "error_tool_loop",
    });
    const finalError = messages[messages.length - 1] as Extract<
      AgentMessage,
      { type: "result" }
    > & { errors?: string[] };
    expect(finalError.errors?.[0] ?? "").toContain("3 times this turn");
    expect(finalError.errors?.[0] ?? "").toContain("Write");
  });

  // ── Streaming migration ──

  it("yields text-delta AgentMessages as the stream emits text chunks", async () => {
    const cwd = makeTempDir();
    const assistant = makeAssistantMessage([{ type: "text", text: "hello world" }], {
      stopReason: "stop",
    });
    streamMock.mockReturnValueOnce({
      [Symbol.asyncIterator]: async function* () {
        yield { type: "text_start", contentIndex: 0, partial: assistant };
        yield { type: "text_delta", contentIndex: 0, delta: "hello ", partial: assistant };
        yield { type: "text_delta", contentIndex: 0, delta: "world", partial: assistant };
        yield { type: "text_end", contentIndex: 0, content: "hello world", partial: assistant };
        yield { type: "done", reason: "stop", message: assistant };
      },
      result: async () => assistant,
    });

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));

    const deltas = messages.filter((m) => m.type === "text-delta");
    expect(deltas.length).toBe(2);
    expect(deltas).toEqual([
      { type: "text-delta", delta: "hello " },
      { type: "text-delta", delta: "world" },
    ]);
    // Final assistant + result still arrive downstream of the deltas.
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "success",
      result: "hello world",
    });
  });

  it("yields tool-call-start + tool-call-delta events for streamed tool calls", async () => {
    const cwd = makeTempDir();
    const finalAssistant = makeAssistantMessage(
      [
        {
          type: "toolCall",
          id: "tu-1",
          name: "Write",
          arguments: { file_path: "/tmp/x", content: "hi" },
        },
      ],
      { stopReason: "toolUse" },
    );
    const resolveAssistant = makeAssistantMessage([{ type: "text", text: "done" }]);

    streamMock
      .mockReturnValueOnce({
        [Symbol.asyncIterator]: async function* () {
          const partialFirst = {
            ...finalAssistant,
            content: [{ type: "toolCall" as const, id: "tu-1", name: "Write", arguments: {} }],
          };
          yield { type: "toolcall_start", contentIndex: 0, partial: partialFirst };
          yield {
            type: "toolcall_delta",
            contentIndex: 0,
            delta: '{"file_path":"/tmp/x"',
            partial: partialFirst,
          };
          yield {
            type: "toolcall_delta",
            contentIndex: 0,
            delta: ',"content":"hi"}',
            partial: partialFirst,
          };
          yield {
            type: "toolcall_end",
            contentIndex: 0,
            toolCall: finalAssistant.content[0],
            partial: finalAssistant,
          };
          yield { type: "done", reason: "toolUse", message: finalAssistant };
        },
        result: async () => finalAssistant,
      })
      .mockReturnValueOnce({
        [Symbol.asyncIterator]: async function* () {
          yield { type: "done", reason: "stop", message: resolveAssistant };
        },
        result: async () => resolveAssistant,
      });

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));

    const starts = messages.filter((m) => m.type === "tool-call-start");
    const deltas = messages.filter((m) => m.type === "tool-call-delta");
    expect(starts).toEqual([{ type: "tool-call-start", toolUseId: "tu-1", toolName: "Write" }]);
    expect(deltas).toEqual([
      { type: "tool-call-delta", toolUseId: "tu-1", delta: '{"file_path":"/tmp/x"' },
      { type: "tool-call-delta", toolUseId: "tu-1", delta: ',"content":"hi"}' },
    ]);
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "success",
    });
  });

  it("emits tool-result with truncation guidance when stopReason=length for a tool call", async () => {
    const cwd = makeTempDir();
    // First turn: provider truncates the tool call mid-argument (stopReason=length,
    // but the toolCall block is still present with partial args).
    const truncated = makeAssistantMessage(
      [
        {
          type: "toolCall",
          id: "tu-trunc",
          name: "Write",
          arguments: { file_path: "/huge.json" }, // content missing — truncated
        },
      ],
      { stopReason: "length" },
    );
    // Second turn: recovers with a small Write.
    const recovered = makeAssistantMessage([{ type: "text", text: "ok" }]);

    completeMock.mockResolvedValueOnce(truncated).mockResolvedValueOnce(recovered);

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));

    // No AJV validation attempted on the truncated call — assertion: we
    // see a tool-result with the truncation-guidance content, not a
    // "missing required property" message.
    const toolResults = messages.filter(
      (m): m is Extract<AgentMessage, { type: "tool-result" }> => m.type === "tool-result",
    );
    expect(toolResults).toHaveLength(1);
    expect(toolResults[0]!.toolUseId).toBe("tu-trunc");
    expect(toolResults[0]!.isError).toBe(true);
    expect(toolResults[0]!.content).toContain("truncated");
    // Guidance explicitly names smaller-payload strategies (Edit-append,
    // reducing content) so the model knows HOW to fix it next turn.
    expect(toolResults[0]!.content).toMatch(/Edit-append|smaller payload|fewer items/);

    // validateToolCall must NOT have been invoked on the truncated call.
    // The recovered second turn has no tool calls, so 0 total validations.
    expect(validateToolCallMock).not.toHaveBeenCalled();

    // Final result is success (recovery turn).
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "success",
    });
  });

  it("trips error_tool_loop after 3 same-tool truncations", async () => {
    const cwd = makeTempDir();
    for (let i = 0; i < 4; i++) {
      completeMock.mockResolvedValueOnce(
        makeAssistantMessage(
          [
            {
              type: "toolCall",
              id: `tu-${i}`,
              name: "Write",
              arguments: { file_path: "/x" },
            },
          ],
          { stopReason: "length" },
        ),
      );
    }

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));

    // 3 truncations → cap trips. completeMock only called 3 times, not 4.
    expect(completeMock).toHaveBeenCalledTimes(3);
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "error_tool_loop",
    });
    const finalError = messages[messages.length - 1] as Extract<
      AgentMessage,
      { type: "result" }
    > & { errors?: string[] };
    expect(finalError.errors?.[0] ?? "").toContain("truncated 3 times");
    expect(finalError.errors?.[0] ?? "").toContain("Write");
  });

  it("a tool's own success resets ONLY its own counter", async () => {
    const cwd = makeTempDir();
    writeFileSync(path.join(cwd, "target.ts"), "x\n", "utf8");
    // Write fail → Write success → Write fail: final Write counter = 1.
    completeMock
      .mockResolvedValueOnce(
        makeAssistantMessage(
          [{ type: "toolCall", id: "tu-1", name: "Write", arguments: { filePath: "/x" } }],
          { stopReason: "toolUse" },
        ),
      )
      .mockResolvedValueOnce(
        makeAssistantMessage(
          [
            {
              type: "toolCall",
              id: "tu-2",
              name: "Write",
              arguments: { file_path: "/y", content: "ok" },
            },
          ],
          { stopReason: "toolUse" },
        ),
      )
      .mockResolvedValueOnce(
        makeAssistantMessage(
          [{ type: "toolCall", id: "tu-3", name: "Write", arguments: { filePath: "/z" } }],
          { stopReason: "toolUse" },
        ),
      )
      .mockResolvedValueOnce(makeAssistantMessage([{ type: "text", text: "done" }]));
    let call = 0;
    validateToolCallMock.mockImplementation((_tools, tc) => {
      call += 1;
      // Fail on calls 1 and 3, succeed on call 2.
      if (call === 2) return tc.arguments;
      throw new Error('Validation failed for tool "Write":\n  - : bad');
    });

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));

    // All four turns consumed — cap did NOT trip because Write's own
    // success between the two failures reset its counter.
    expect(completeMock).toHaveBeenCalledTimes(4);
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "success",
    });
  });
});

describe("isTransientError", () => {
  it("detects HTTP 503 errors", () => {
    expect(isTransientError(new Error("503 Service Temporarily Unavailable"))).toBe(true);
  });

  it("detects HTTP 429 errors", () => {
    expect(isTransientError(new Error("rate limited: 429"))).toBe(true);
  });

  it("detects network errors", () => {
    expect(isTransientError(new Error("ETIMEDOUT"))).toBe(true);
    expect(isTransientError(new Error("ECONNRESET"))).toBe(true);
    expect(isTransientError(new Error("fetch failed"))).toBe(true);
    expect(isTransientError(new Error("socket hang up"))).toBe(true);
  });

  it("detects overloaded errors", () => {
    expect(isTransientError(new Error("Anthropic API is overloaded"))).toBe(true);
  });

  it("does not match non-transient errors", () => {
    expect(isTransientError(new Error("Invalid API key"))).toBe(false);
    expect(isTransientError(new Error("content policy violation"))).toBe(false);
  });
});

describe("PiAiSession", () => {
  async function collectSessionMessages(
    session: { query: (prompt: string) => AsyncIterable<AgentMessage> },
    prompt: string,
  ): Promise<AgentMessage[]> {
    const collected: AgentMessage[] = [];
    for await (const message of session.query(prompt)) {
      collected.push(message);
    }
    return collected;
  }

  it("preserves conversation context across successive queries", async () => {
    const cwd = makeTempDir();
    completeMock
      .mockResolvedValueOnce(
        makeAssistantMessage([{ type: "text", text: "first-reply" }], { totalCost: 0.002 }),
      )
      .mockResolvedValueOnce(
        makeAssistantMessage([{ type: "text", text: "second-reply" }], { totalCost: 0.003 }),
      );

    const runtime = new PiAiAgentRuntime();
    const session = runtime.createSession?.({ cwd, model: "openai:gpt-4o" });
    if (!session) throw new Error("createSession returned undefined");

    const firstMessages = await collectSessionMessages(session, "first user prompt");
    const secondMessages = await collectSessionMessages(session, "second user prompt");

    expect(completeMock).toHaveBeenCalledTimes(2);

    // The second complete() call must see the prior user prompt AND the first
    // assistant reply in context.messages. That's the whole point of sessions.
    // (Note: `context.messages` is mutated in place by the loop after each LLM
    // call, so by assertion time the array has grown past the snapshot we want
    // to check. Assert the first three slots are what the LLM saw on turn 2.)
    const secondContext = completeMock.mock.calls[1]?.[1];
    const messagesAtCall = secondContext.messages.slice(0, 3);
    const roles = messagesAtCall.map((m: { role: string }) => m.role);
    expect(roles).toEqual(["user", "assistant", "user"]);
    expect(messagesAtCall[0].content).toBe("first user prompt");
    const priorAssistantText = messagesAtCall[1].content.find(
      (b: { type: string }) => b.type === "text",
    );
    expect(priorAssistantText.text).toBe("first-reply");
    expect(messagesAtCall[2].content).toBe("second user prompt");

    expect(firstMessages[firstMessages.length - 1]).toMatchObject({
      type: "result",
      subtype: "success",
      result: "first-reply",
      numTurns: 1,
    });
    expect(secondMessages[secondMessages.length - 1]).toMatchObject({
      type: "result",
      subtype: "success",
      result: "second-reply",
      numTurns: 1,
    });

    await session.close();
  });

  it("carries tool-result messages across turns", async () => {
    const cwd = makeTempDir();
    writeFileSync(path.join(cwd, "target.ts"), "line1\nline2\n", "utf8");

    completeMock
      // Turn 1 invokes a tool, then the model produces its final reply.
      .mockResolvedValueOnce(
        makeAssistantMessage(
          [
            {
              type: "toolCall",
              id: "tool-read-1",
              name: "Read",
              arguments: { path: "target.ts", offset: 1, limit: 1 },
            },
          ],
          { stopReason: "toolUse", totalCost: 0.001 },
        ),
      )
      .mockResolvedValueOnce(
        makeAssistantMessage([{ type: "text", text: "ack" }], { totalCost: 0.001 }),
      )
      // Turn 2 should see the previous toolResult in context when it runs.
      .mockResolvedValueOnce(
        makeAssistantMessage([{ type: "text", text: "follow-up" }], { totalCost: 0.001 }),
      );

    const runtime = new PiAiAgentRuntime();
    const session = runtime.createSession?.({ cwd, model: "openai:gpt-4o" });
    if (!session) throw new Error("createSession returned undefined");

    await collectSessionMessages(session, "please read target.ts");
    await collectSessionMessages(session, "now summarise it");

    const lastCallContext = completeMock.mock.calls.at(-1)?.[1];
    const hasToolResult = lastCallContext.messages.some(
      (m: { role: string }) => m.role === "toolResult",
    );
    expect(hasToolResult).toBe(true);

    await session.close();
  });

  it("refuses to run after close()", async () => {
    const cwd = makeTempDir();
    completeMock.mockResolvedValue(
      makeAssistantMessage([{ type: "text", text: "hello" }], { totalCost: 0 }),
    );

    const runtime = new PiAiAgentRuntime();
    const session = runtime.createSession?.({ cwd, model: "openai:gpt-4o" });
    if (!session) throw new Error("createSession returned undefined");

    await collectSessionMessages(session, "hi");
    await session.close();

    await expect(collectSessionMessages(session, "again")).rejects.toThrow(/closed/);
  });

  it("rejects concurrent query() calls on the same session", async () => {
    const cwd = makeTempDir();
    let release: (() => void) | undefined;
    completeMock.mockImplementation(
      () =>
        new Promise((resolve) => {
          release = () => resolve(makeAssistantMessage([{ type: "text", text: "done" }]));
        }),
    );

    const runtime = new PiAiAgentRuntime();
    const session = runtime.createSession?.({ cwd, model: "openai:gpt-4o" });
    if (!session) throw new Error("createSession returned undefined");

    const first = collectSessionMessages(session, "first");
    // Yield once so the generator starts and flips inFlight=true before
    // the second attempt.
    await new Promise((resolve) => setImmediate(resolve));

    await expect(collectSessionMessages(session, "second")).rejects.toThrow(/in flight/);

    release?.();
    await first;
    await session.close();
  });

  it("close() aborts an in-flight query", async () => {
    const cwd = makeTempDir();
    let capturedSignal: AbortSignal | undefined;
    completeMock.mockImplementation(async (_model, _context, options) => {
      capturedSignal = options?.signal;
      await new Promise<void>((resolve) => {
        if (capturedSignal?.aborted) {
          resolve();
          return;
        }
        capturedSignal?.addEventListener("abort", () => resolve(), { once: true });
      });
      return makeAssistantMessage([], { stopReason: "aborted", errorMessage: "aborted" });
    });

    const runtime = new PiAiAgentRuntime();
    const session = runtime.createSession?.({ cwd, model: "openai:gpt-4o" });
    if (!session) throw new Error("createSession returned undefined");

    const queryPromise = collectSessionMessages(session, "hang please");
    await new Promise((resolve) => setImmediate(resolve));
    await session.close();

    const messages = await queryPromise;
    expect(capturedSignal?.aborted).toBe(true);
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "error_aborted",
    });
  });

  it("forwards an externally-aborted controller into the session signal", async () => {
    const cwd = makeTempDir();
    const abortController = new AbortController();
    abortController.abort();
    completeMock.mockResolvedValue(
      makeAssistantMessage([{ type: "text", text: "should-not-run" }]),
    );

    const runtime = new PiAiAgentRuntime();
    const session = runtime.createSession?.({ cwd, model: "openai:gpt-4o", abortController });
    if (!session) throw new Error("createSession returned undefined");

    const messages = await collectSessionMessages(session, "hello");
    expect(completeMock).not.toHaveBeenCalled();
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "error_aborted",
    });

    await session.close();
  });
});

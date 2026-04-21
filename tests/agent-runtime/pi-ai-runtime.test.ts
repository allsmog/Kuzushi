import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AgentMessage, AgentQueryRequest } from "../../src/agent-runtime/types.js";

const ORIGINAL_ANTHROPIC_API_KEY = process.env["ANTHROPIC_API_KEY"];
const ORIGINAL_ANTHROPIC_BASE_URL = process.env["ANTHROPIC_BASE_URL"];

const { completeMock, getModelMock, validateToolCallMock } = vi.hoisted(() => ({
  completeMock: vi.fn(),
  getModelMock: vi.fn(),
  validateToolCallMock: vi.fn(),
}));

vi.mock("@mariozechner/pi-ai", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@mariozechner/pi-ai")>();
  return {
    ...actual,
    complete: completeMock,
    getModel: getModelMock,
    validateToolCall: validateToolCallMock,
  };
});

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
  getModelMock.mockReturnValue(makeModel());
  validateToolCallMock.mockImplementation((_tools, toolCall) => toolCall.arguments);
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
    const originalBaseUrl = process.env["ANTHROPIC_BASE_URL"];
    completeMock.mockImplementation(async () => {
      expect(process.env["ANTHROPIC_API_KEY"]).toBe("sk-config");
      expect(process.env["ANTHROPIC_BASE_URL"]).toBe("https://api.example.com/");
      return makeAssistantMessage([{ type: "text", text: '{"ok":true}' }]);
    });

    const runtime = new PiAiAgentRuntime({
      apiKey: "sk-config",
      baseUrl: "https://api.example.com/",
    });
    await collectMessages(runtime, makeRequest(cwd));

    expect(process.env["ANTHROPIC_API_KEY"]).toBe(originalApiKey);
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

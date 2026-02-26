import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AgentMessage, AgentQueryRequest } from "../../src/agent-runtime/types.js";

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

import { PiAiAgentRuntime } from "../../src/agent-runtime/pi-ai.js";

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
      maxTurns: 3,
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
});

describe("PiAiAgentRuntime", () => {
  it("returns a single-turn successful result", async () => {
    const cwd = makeTempDir();
    completeMock.mockResolvedValue(
      makeAssistantMessage(
        [{ type: "text", text: "{\"ok\":true}" }],
        { totalCost: 0.0123 },
      ),
    );

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));

    expect(getModelMock).toHaveBeenCalledWith("openai", "gpt-4o");
    expect(messages.some((message) => message.type === "assistant")).toBe(true);
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "success",
      result: "{\"ok\":true}",
      numTurns: 1,
      totalCostUsd: 0.0123,
    });
  });

  it("handles multi-turn tool loop and emits tool events", async () => {
    const cwd = makeTempDir();
    writeFileSync(path.join(cwd, "target.ts"), "line1\nline2\nline3\n", "utf8");

    completeMock
      .mockResolvedValueOnce(makeAssistantMessage(
        [
          {
            type: "toolCall",
            id: "tool-read-1",
            name: "Read",
            arguments: { path: "target.ts", offset: 1, limit: 1 },
          },
        ],
        { stopReason: "toolUse", totalCost: 0.004 },
      ))
      .mockResolvedValueOnce(makeAssistantMessage(
        [{ type: "text", text: "{\"verdict\":\"fp\"}" }],
        { totalCost: 0.006 },
      ));

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));

    expect(completeMock).toHaveBeenCalledTimes(2);
    expect(messages.some((message) => message.type === "tool-progress")).toBe(true);
    expect(messages.some((message) => message.type === "tool-summary")).toBe(true);
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "success",
      result: "{\"verdict\":\"fp\"}",
      numTurns: 2,
      totalCostUsd: 0.01,
    });

    const secondContext = completeMock.mock.calls[1]?.[1];
    expect(secondContext.messages.some((message: { role: string }) => message.role === "toolResult")).toBe(true);
  });

  it("returns max-turns error when tool loop does not converge", async () => {
    const cwd = makeTempDir();
    completeMock.mockResolvedValue(makeAssistantMessage(
      [{
        type: "toolCall",
        id: "tool-read-1",
        name: "Read",
        arguments: { path: "target.ts" },
      }],
      { stopReason: "toolUse" },
    ));

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd, { maxTurns: 1 }));
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "error_max_turns",
    });
  });

  it("returns aborted result when signal is already aborted", async () => {
    const cwd = makeTempDir();
    const abortController = new AbortController();
    abortController.abort();

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(
      runtime,
      makeRequest(cwd, { abortController }),
    );

    expect(completeMock).not.toHaveBeenCalled();
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "error_aborted",
    });
  });

  it("enforces max budget when another tool turn would be required", async () => {
    const cwd = makeTempDir();
    completeMock.mockResolvedValue(makeAssistantMessage(
      [{
        type: "toolCall",
        id: "tool-read-1",
        name: "Read",
        arguments: { path: "target.ts" },
      }],
      { stopReason: "toolUse", totalCost: 1.2 },
    ));

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(
      runtime,
      makeRequest(cwd, { maxBudgetUsd: 1 }),
    );

    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "error_budget_exceeded",
    });
  });

  it("returns success for final responses even if they exceed budget", async () => {
    const cwd = makeTempDir();
    completeMock.mockResolvedValue(
      makeAssistantMessage(
        [{ type: "text", text: "{\"ok\":true}" }],
        { totalCost: 1.2 },
      ),
    );

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(
      runtime,
      makeRequest(cwd, { maxBudgetUsd: 1 }),
    );

    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "success",
      result: "{\"ok\":true}",
    });
  });

  it("hard-stops when canUseTool denies a tool call", async () => {
    const cwd = makeTempDir();
    completeMock.mockResolvedValue(makeAssistantMessage(
      [{
        type: "toolCall",
        id: "tool-read-1",
        name: "Read",
        arguments: { path: "target.ts" },
      }],
      { stopReason: "toolUse", totalCost: 0.01 },
    ));

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

    expect(completeMock).toHaveBeenCalledTimes(1);
    expect(messages[messages.length - 1]).toMatchObject({
      type: "result",
      subtype: "error_permission_denied",
      errors: ["Read is not permitted in this run."],
    });
  });

  it("generates unique fallback tool IDs when provider omits tool call IDs", async () => {
    const cwd = makeTempDir();
    writeFileSync(path.join(cwd, "target.ts"), "line1\nline2\n", "utf8");

    completeMock
      .mockResolvedValueOnce(makeAssistantMessage(
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
      ))
      .mockResolvedValueOnce(makeAssistantMessage(
        [{ type: "text", text: "{\"ok\":true}" }],
      ));

    const runtime = new PiAiAgentRuntime();
    const messages = await collectMessages(runtime, makeRequest(cwd));

    const toolProgressIds = messages
      .filter((message): message is Extract<AgentMessage, { type: "tool-progress" }> => (
        message.type === "tool-progress"
      ))
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
          text: "```json\n{\"fingerprint\":\"abc\",\"verdict\":\"fp\"}\n```",
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
    expect(firstContext.systemPrompt).toContain("\"fingerprint\"");
  });
});

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { AcpAgentRuntime } from "../../src/agent-runtime/acp.js";
import type { AgentQueryRequest } from "../../src/agent-runtime/types.js";

function createTestRequest(prompt = "Test prompt"): AgentQueryRequest {
  return {
    prompt,
    options: {
      cwd: "/tmp/test",
      model: "anthropic:claude-sonnet-4-6",
      allowedTools: ["Read", "Grep"],
    },
  };
}

describe("AcpAgentRuntime", () => {
  it("has id 'acp'", () => {
    const runtime = new AcpAgentRuntime("echo test");
    expect(runtime.id).toBe("acp");
  });

  it("yields error when adapter command is unreachable", async () => {
    const runtime = new AcpAgentRuntime("__nonexistent_binary_12345__");
    const request = createTestRequest();

    const messages: any[] = [];
    for await (const msg of runtime.query(request)) {
      messages.push(msg);
    }

    expect(messages.length).toBeGreaterThan(0);
    const last = messages[messages.length - 1];
    expect(last.type).toBe("result");
    expect(last.subtype).toMatch(/error/);
  });

  it("yields error when aborted", async () => {
    const controller = new AbortController();
    controller.abort();

    const runtime = new AcpAgentRuntime("cat");
    const request: AgentQueryRequest = {
      prompt: "test",
      options: {
        cwd: "/tmp",
        model: "anthropic:claude-sonnet-4-6",
        abortController: controller,
      },
    };

    const messages: any[] = [];
    for await (const msg of runtime.query(request)) {
      messages.push(msg);
    }

    expect(messages.length).toBeGreaterThan(0);
    const last = messages[messages.length - 1];
    expect(last.type).toBe("result");
    expect(last.subtype).toContain("abort");
  });

  it("shutdown is idempotent", async () => {
    const runtime = new AcpAgentRuntime("echo test");
    await runtime.shutdown();
    await runtime.shutdown();
    // Should not throw
  });
});

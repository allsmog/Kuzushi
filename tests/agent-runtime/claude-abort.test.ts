import { afterEach, describe, expect, it, vi } from "vitest";

const { claudeQueryMock } = vi.hoisted(() => ({
  claudeQueryMock: vi.fn(),
}));

vi.mock("@anthropic-ai/claude-agent-sdk", () => ({
  query: claudeQueryMock,
}));

import { ClaudeAgentRuntime } from "../../src/agent-runtime/claude.js";

async function collect<T>(iterable: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const item of iterable) out.push(item);
  return out;
}

describe("claude runtime abort handling", () => {
  afterEach(() => {
    claudeQueryMock.mockReset();
    vi.restoreAllMocks();
  });

  it("treats SDK abort throws as an expected aborted result without stderr logging", async () => {
    // biome-ignore lint/correctness/useYield: error-first generator — throw surfaces on first iter.
    async function* abortedSdkStream() {
      throw new Error("Claude Code process aborted by user");
    }
    claudeQueryMock.mockReturnValue(abortedSdkStream());
    const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
    const abortController = new AbortController();
    abortController.abort();

    const runtime = new ClaudeAgentRuntime();
    const messages = await collect(
      runtime.query({
        prompt: "stop",
        options: {
          cwd: process.cwd(),
          model: "anthropic:claude-sonnet-4-6",
          abortController,
        },
      }),
    );

    expect(messages).toHaveLength(1);
    expect(messages[0]).toMatchObject({
      type: "result",
      subtype: "error_aborted",
      errors: ["Aborted by operator"],
    });
    expect(stderr).not.toHaveBeenCalled();
  });
});

/**
 * Adapter-level enforcement tests. Each runtime must reject incompatible
 * model/runtime pairs and unsanctioned `fallbackModel` *before* any
 * provider/SDK call. We exercise the user-facing surface: `query()`,
 * `queryBatch()` (where supported), and `createSession()`/`session.query()`.
 *
 * The tests deliberately don't mock the providers — if enforcement is
 * working, the throw fires before any subprocess/SDK call is attempted.
 * If enforcement is broken, the test will time out or surface a different
 * error from the SDK, which is a clear signal the regression slipped in.
 */
import { describe, expect, it } from "vitest";
import { ClaudeAgentRuntime } from "../../src/agent-runtime/claude.js";
import { KuzushiSilentFallbackError } from "../../src/agent-runtime/enforcement.js";
import { PiAiAgentRuntime } from "../../src/agent-runtime/pi-ai.js";
import type { AgentQueryOptions } from "../../src/agent-runtime/types.js";

function baseOptions(overrides: Partial<AgentQueryOptions> = {}): AgentQueryOptions {
  return {
    cwd: "/tmp",
    model: "anthropic:claude-sonnet-4-6",
    ...overrides,
  };
}

async function expectIterableThrows(
  iter: AsyncIterable<unknown>,
  matcher: RegExp | string,
): Promise<void> {
  try {
    for await (const _msg of iter) {
      // drain
    }
    throw new Error("iterable did not throw");
  } catch (err) {
    expect(err).toBeInstanceOf(KuzushiSilentFallbackError);
    if (typeof matcher === "string") {
      expect((err as Error).message).toContain(matcher);
    } else {
      expect((err as Error).message).toMatch(matcher);
    }
  }
}

describe("ClaudeAgentRuntime — enforcement", () => {
  it("query() throws on incompatible model (openai:* on claude backend)", async () => {
    const runtime = new ClaudeAgentRuntime();
    await expectIterableThrows(
      runtime.query({
        prompt: "x",
        options: baseOptions({ model: "openai:gpt-4" }),
      }),
      /Kuzushi will not silently switch runtimes/,
    );
  });

  it("query() throws on empty model", async () => {
    const runtime = new ClaudeAgentRuntime();
    await expectIterableThrows(
      runtime.query({
        prompt: "x",
        options: baseOptions({ model: "" }),
      }),
      /model is required/,
    );
  });

  it("query() throws on fallbackModel without consent", async () => {
    const runtime = new ClaudeAgentRuntime();
    await expectIterableThrows(
      runtime.query({
        prompt: "x",
        options: baseOptions({ fallbackModel: "anthropic:claude-haiku-4-5" }),
      }),
      /Kuzushi will not silently switch models/,
    );
  });

  it("queryBatch() rejects fallbackModel without consent before any API call", async () => {
    const runtime = new ClaudeAgentRuntime();
    await expect(
      runtime.queryBatch(
        [{ id: "a", prompt: "p" }],
        baseOptions({ fallbackModel: "anthropic:claude-haiku-4-5" }),
      ),
    ).rejects.toThrow(KuzushiSilentFallbackError);
  });

  it("queryBatch() rejects incompatible model before any API call", async () => {
    const runtime = new ClaudeAgentRuntime();
    await expect(
      runtime.queryBatch([{ id: "a", prompt: "p" }], baseOptions({ model: "openai:gpt-4" })),
    ).rejects.toThrow(/Kuzushi will not silently switch runtimes/);
  });

  it("session.query() throws on incompatible model", async () => {
    const runtime = new ClaudeAgentRuntime();
    const session = runtime.createSession(baseOptions({ model: "openai:gpt-4" }));
    await expectIterableThrows(session.query("hi"), /Kuzushi will not silently switch runtimes/);
    await session.close();
  });
});

describe("PiAiAgentRuntime — enforcement", () => {
  it("query() throws on incompatible model (bare ID without provider prefix)", async () => {
    const runtime = new PiAiAgentRuntime();
    await expectIterableThrows(
      runtime.query({
        prompt: "x",
        options: baseOptions({ model: "claude-sonnet-4-6" }),
      }),
      /Kuzushi will not silently switch runtimes/,
    );
  });

  it("query() throws on empty model", async () => {
    const runtime = new PiAiAgentRuntime();
    await expectIterableThrows(
      runtime.query({
        prompt: "x",
        options: baseOptions({ model: "" }),
      }),
      /model is required/,
    );
  });

  it("query() throws on fallbackModel without consent", async () => {
    const runtime = new PiAiAgentRuntime();
    await expectIterableThrows(
      runtime.query({
        prompt: "x",
        options: baseOptions({ fallbackModel: "anthropic:claude-haiku-4-5" }),
      }),
      /Kuzushi will not silently switch models/,
    );
  });

  it("createSession() throws synchronously on incompatible model", () => {
    const runtime = new PiAiAgentRuntime();
    expect(() => runtime.createSession(baseOptions({ model: "claude-sonnet-4-6" }))).toThrow(
      KuzushiSilentFallbackError,
    );
  });

  it("createSession() throws synchronously on fallbackModel without consent", () => {
    const runtime = new PiAiAgentRuntime();
    expect(() =>
      runtime.createSession(baseOptions({ fallbackModel: "anthropic:claude-haiku-4-5" })),
    ).toThrow(/Kuzushi will not silently switch models/);
  });
});

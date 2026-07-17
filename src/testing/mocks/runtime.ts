/**
 * Scripted `AgentRuntime` stub for unit-testing LLM-driven tools.
 *
 * `createFakeRuntime(responses)` returns a runtime whose `query()` matches
 * the caller's prompt against each response spec (`match: string | RegExp`)
 * and yields an assistant+result pair scripted by the first match. Falls
 * back to yielding an empty text assistant + success result so callers
 * never receive an unhandled stream.
 */

import type { AgentMessage, AgentQueryRequest, AgentRuntime } from "../../agent-runtime/types.js";
import { repeatableRegexTest } from "../regex.js";

export interface FakeRuntimeResponse {
  /**
   * Substring or RegExp tested against `request.prompt`. First match wins.
   * Use `/./` to match everything.
   */
  match: string | RegExp;
  /** Assistant text to yield before the `result` message. */
  output: string;
  /**
   * Optional single `tool-use` content block to yield as part of the
   * assistant message (before `tool-result` / `result` are emitted by the
   * caller). When set, the fake also yields a synthetic `tool-result`
   * with `isError: false` and empty content.
   */
  toolUse?: {
    name: string;
    input: Record<string, unknown>;
    toolUseId?: string;
  };
  /** Optional structured-output payload for the final `result` message. */
  structuredOutput?: unknown;
  /** Optional cost to report on the final `result`. */
  costUsd?: number;
}

export interface FakeRuntime extends AgentRuntime {
  /** Every `query()` call observed, in order. */
  readonly calls: AgentQueryRequest[];
  /** Drop recorded calls. */
  clear(): void;
}

const matches = (prompt: string, match: string | RegExp): boolean =>
  typeof match === "string" ? prompt.includes(match) : repeatableRegexTest(match, prompt);

/**
 * Build an `AgentRuntime` that scripts assistant output by prompt match.
 *
 * Permissive by design: if no response matches, yields a single empty
 * assistant message + a `success` result. Tests that need strict matching
 * should assert on `.calls` afterwards.
 *
 * @example
 *   const runtime = createFakeRuntime([
 *     { match: /triage/i, output: '{"verdict":"true-positive"}' },
 *     { match: "recon", output: "scanned 0 hosts" },
 *   ]);
 *   const ctx = createMockToolContext({ runtime });
 *   await myLlmTool.execute({ prompt: "run triage" }, ctx);
 *   expect(runtime.calls).toHaveLength(1);
 */
export function createFakeRuntime(responses: FakeRuntimeResponse[] = []): FakeRuntime {
  const calls: AgentQueryRequest[] = [];

  const runtime: FakeRuntime = {
    id: "fake-runtime",
    calls,
    clear() {
      calls.length = 0;
    },
    async *query(request: AgentQueryRequest): AsyncIterable<AgentMessage> {
      calls.push(request);
      const hit = responses.find((r) => matches(request.prompt, r.match));
      const output = hit?.output ?? "";

      // Assistant message — text + optional tool-use block.
      const content: Array<Record<string, unknown>> = [];
      if (output) content.push({ type: "text", text: output });
      if (hit?.toolUse) {
        const toolUseId = hit.toolUse.toolUseId ?? `tu_${calls.length}`;
        content.push({
          type: "tool_use",
          id: toolUseId,
          name: hit.toolUse.name,
          input: hit.toolUse.input,
        });
      }
      yield {
        type: "assistant",
        content,
      };

      // Synthetic tool-result to close the loop.
      if (hit?.toolUse) {
        const toolUseId = hit.toolUse.toolUseId ?? `tu_${calls.length}`;
        yield {
          type: "tool-result",
          toolUseId,
          isError: false,
          content: "",
        };
      }

      yield {
        type: "result",
        subtype: "success",
        result: output,
        structuredOutput: hit?.structuredOutput,
        totalCostUsd: hit?.costUsd ?? 0,
      };
    },
  };

  return runtime;
}

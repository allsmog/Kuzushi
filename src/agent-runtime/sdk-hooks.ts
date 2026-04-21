/**
 * Claude Agent SDK `hooks` config builders for the ClaudeRuntime.
 *
 * Right now we wire a single PreToolUse hook that normalizes tool inputs
 * (filePath → file_path, etc.) so the SDK's built-in Zod schemas don't
 * reject perfectly reasonable tool calls from weaker sub-Claude models.
 *
 * Kept separate from `claude.ts` so both the one-shot `query()` path and
 * the long-lived `ClaudeSession.ensureStarted()` path can share the exact
 * same hook set without duplicating logic.
 */
import { createLogger } from "../logger.js";
import { normalizeToolInput } from "./tool-input-normalizer.js";

const log = createLogger({ stage: "sdk-hooks" });

export interface SdkHookOptions {
  /**
   * Fires every time the normalizer rewrites a tool input. Used by the
   * caller to surface the rewrite on the shell's activity rail so the
   * operator sees "Write filePath→file_path normalized" instead of a
   * silent schema fix.
   */
  onNormalize?: (toolName: string, renames: string[]) => void;
}

/**
 * Build the SDK `hooks` argument. Shape matches
 * `Partial<Record<HookEvent, HookCallbackMatcher[]>>` from @anthropic-ai/claude-agent-sdk.
 * Typed as `unknown` to avoid a hard dependency on SDK internals here.
 */
export function buildSdkHooks(opts: SdkHookOptions = {}): Record<string, unknown> {
  return {
    PreToolUse: [
      {
        // Match every tool — the normalizer is a no-op for tools without
        // an alias map, so cost is a single Map lookup per tool call.
        hooks: [
          async (input: unknown) => {
            if (
              !input ||
              typeof input !== "object" ||
              (input as { hook_event_name?: string }).hook_event_name !== "PreToolUse"
            ) {
              return {};
            }
            const event = input as {
              tool_name?: unknown;
              tool_input?: unknown;
            };
            const toolName = typeof event.tool_name === "string" ? event.tool_name : "";
            if (!toolName) return {};

            const {
              input: normalized,
              changed,
              renames,
            } = normalizeToolInput(toolName, event.tool_input);
            if (!changed) return {};

            log.debug(`normalized ${toolName} input: ${renames.join(", ")}`);
            opts.onNormalize?.(toolName, renames);
            return {
              hookSpecificOutput: {
                hookEventName: "PreToolUse",
                updatedInput: normalized,
              },
            };
          },
        ],
      },
    ],
  };
}

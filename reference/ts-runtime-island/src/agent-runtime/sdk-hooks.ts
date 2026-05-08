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
import { toErrorMessage } from "../utils.js";
import { normalizeToolInput } from "./tool-input-normalizer.js";
import type { AgentQueryOptions } from "./types.js";

const log = createLogger({ stage: "sdk-hooks" });

export interface SdkHookOptions {
  /**
   * Fires every time the normalizer rewrites a tool input. Used by the
   * caller to surface the rewrite on the shell's activity rail so the
   * operator sees "Write filePath→file_path normalized" instead of a
   * silent schema fix.
   */
  onNormalize?: (toolName: string, renames: string[]) => void;
  /**
   * Optional runtime policy hook. Claude Code's native tools do not go
   * through `agent-runtime/tools.ts`, so this is where shared path/scope
   * guards get enforced for the Claude backend.
   */
  canUseTool?: AgentQueryOptions["canUseTool"];
}

function fallbackSignal(): AbortSignal {
  return new AbortController().signal;
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
          async (
            input: unknown,
            toolUseId: string | undefined,
            hookOptions?: { signal?: AbortSignal },
          ) => {
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
              tool_use_id?: unknown;
              blocked_path?: unknown;
              decision_reason?: unknown;
            };
            const toolName = typeof event.tool_name === "string" ? event.tool_name : "";
            if (!toolName) return {};

            const {
              input: normalized,
              changed,
              renames,
            } = normalizeToolInput(toolName, event.tool_input);
            let decision: Awaited<ReturnType<NonNullable<SdkHookOptions["canUseTool"]>>> | null =
              null;
            if (opts.canUseTool) {
              try {
                decision = await opts.canUseTool(toolName, normalized, {
                  signal: hookOptions?.signal ?? fallbackSignal(),
                  toolUseId:
                    typeof event.tool_use_id === "string" ? event.tool_use_id : (toolUseId ?? ""),
                  blockedPath:
                    typeof event.blocked_path === "string" ? event.blocked_path : undefined,
                  decisionReason:
                    typeof event.decision_reason === "string" ? event.decision_reason : undefined,
                });
              } catch (err) {
                decision = {
                  behavior: "deny",
                  message: `Tool policy error: ${toErrorMessage(err)}`,
                };
              }
            }

            if (decision?.behavior === "deny") {
              return {
                hookSpecificOutput: {
                  hookEventName: "PreToolUse",
                  permissionDecision: "deny",
                  permissionDecisionReason:
                    decision.message ?? `Tool "${toolName}" denied by policy.`,
                },
              };
            }

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

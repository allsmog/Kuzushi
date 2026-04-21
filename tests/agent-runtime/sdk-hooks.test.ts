import { describe, expect, it, vi } from "vitest";
import { buildSdkHooks } from "../../src/agent-runtime/sdk-hooks.js";

/**
 * Extract the single PreToolUse callback from the hooks config. The SDK's
 * shape is Record<HookEvent, HookCallbackMatcher[]>, where each matcher has
 * a `hooks: HookCallback[]`. We wire exactly one matcher with one callback.
 */
function getPreToolUseCallback(cfg: Record<string, unknown>): (input: unknown) => Promise<unknown> {
  const matchers =
    (cfg.PreToolUse as Array<{ hooks: Array<(input: unknown) => Promise<unknown>> }>) ?? [];
  const cb = matchers[0]?.hooks?.[0];
  if (!cb) throw new Error("no PreToolUse callback");
  return cb;
}

describe("buildSdkHooks — PreToolUse normalizer", () => {
  it("rewrites Write filePath → file_path via updatedInput", async () => {
    const cb = getPreToolUseCallback(buildSdkHooks());
    const result = (await cb({
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { filePath: "/abs", content: "body" },
    })) as {
      hookSpecificOutput?: { hookEventName?: string; updatedInput?: Record<string, unknown> };
    };
    expect(result.hookSpecificOutput?.hookEventName).toBe("PreToolUse");
    expect(result.hookSpecificOutput?.updatedInput).toEqual({
      file_path: "/abs",
      content: "body",
    });
  });

  it("returns empty object when input is already canonical (no-op)", async () => {
    const cb = getPreToolUseCallback(buildSdkHooks());
    const result = await cb({
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: "/abs", content: "body" },
    });
    expect(result).toEqual({});
  });

  it("returns empty object for unknown tool names", async () => {
    const cb = getPreToolUseCallback(buildSdkHooks());
    const result = await cb({
      hook_event_name: "PreToolUse",
      tool_name: "SomeCustomMcpTool",
      tool_input: { filePath: "/abs" },
    });
    expect(result).toEqual({});
  });

  it("ignores non-PreToolUse events", async () => {
    const cb = getPreToolUseCallback(buildSdkHooks());
    const result = await cb({
      hook_event_name: "PostToolUse",
      tool_name: "Write",
      tool_input: { filePath: "/abs" },
    });
    expect(result).toEqual({});
  });

  it("fires onNormalize callback with tool name + renames", async () => {
    const spy = vi.fn();
    const cb = getPreToolUseCallback(buildSdkHooks({ onNormalize: spy }));
    await cb({
      hook_event_name: "PreToolUse",
      tool_name: "Edit",
      tool_input: { filePath: "/a", oldString: "x", newString: "y" },
    });
    expect(spy).toHaveBeenCalledTimes(1);
    const [toolName, renames] = spy.mock.calls[0] as [string, string[]];
    expect(toolName).toBe("Edit");
    expect(renames.sort()).toEqual([
      "filePath→file_path",
      "newString→new_string",
      "oldString→old_string",
    ]);
  });

  it("does not fire onNormalize when input was already canonical", async () => {
    const spy = vi.fn();
    const cb = getPreToolUseCallback(buildSdkHooks({ onNormalize: spy }));
    await cb({
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: "/abs", content: "x" },
    });
    expect(spy).not.toHaveBeenCalled();
  });
});

import {
  query,
  type CanUseTool,
  type PermissionResult,
  type SDKMessage,
} from "@anthropic-ai/claude-agent-sdk";
import type {
  AgentMessage,
  AgentQueryRequest,
  AgentRuntime,
  AgentToolDecision,
} from "./types.js";

export class ClaudeSdkAgentRuntime implements AgentRuntime {
  readonly id = "claude-sdk";

  async *query(request: AgentQueryRequest): AsyncIterable<AgentMessage> {
    const canUseTool = request.options.canUseTool
      ? adaptCanUseTool(request.options.canUseTool)
      : undefined;

    for await (const message of query({
      prompt: request.prompt,
      options: {
        cwd: request.options.cwd,
        model: request.options.model,
        maxTurns: request.options.maxTurns,
        allowedTools: request.options.allowedTools,
        disallowedTools: request.options.disallowedTools,
        permissionMode: request.options.permissionMode,
        maxBudgetUsd: request.options.maxBudgetUsd,
        abortController: request.options.abortController,
        outputFormat: request.options.outputFormat
          ? {
            type: "json_schema",
            schema: request.options.outputFormat.schema,
          }
          : undefined,
        canUseTool,
      },
    })) {
      yield mapMessage(message);
    }
  }
}

function mapMessage(message: SDKMessage): AgentMessage {
  if (message.type === "result") {
    if (message.subtype === "success") {
      return {
        type: "result",
        subtype: "success",
        result: message.result,
        structuredOutput: message.structured_output,
        durationMs: message.duration_ms,
        numTurns: message.num_turns,
        totalCostUsd: message.total_cost_usd,
      };
    }

    return {
      type: "result",
      subtype: message.subtype,
      errors: [...message.errors],
      durationMs: message.duration_ms,
      numTurns: message.num_turns,
      totalCostUsd: message.total_cost_usd,
    };
  }

  if (message.type === "assistant") {
    const content = Array.isArray(message.message.content)
      ? message.message.content.filter(isRecord)
      : [];
    return {
      type: "assistant",
      content,
    };
  }

  if (message.type === "tool_progress") {
    return {
      type: "tool-progress",
      toolUseId: message.tool_use_id,
      toolName: message.tool_name,
      elapsedSeconds: message.elapsed_time_seconds,
    };
  }

  if (message.type === "tool_use_summary") {
    return {
      type: "tool-summary",
      summary: message.summary,
      precedingToolUseIds: [...message.preceding_tool_use_ids],
    };
  }

  return {
    type: "unknown",
    raw: message,
  };
}

function adaptCanUseTool(
  handler: NonNullable<AgentQueryRequest["options"]["canUseTool"]>,
): CanUseTool {
  return async (toolName, input, options) => {
    const decision = await handler(toolName, input, {
      signal: options.signal,
      toolUseId: options.toolUseID,
      blockedPath: options.blockedPath,
      decisionReason: options.decisionReason,
    });
    return toPermissionResult(decision);
  };
}

function toPermissionResult(decision: AgentToolDecision): PermissionResult {
  if (decision.behavior === "allow") {
    return {
      behavior: "allow",
      updatedInput: undefined,
      updatedPermissions: undefined,
    };
  }

  return {
    behavior: "deny",
    message: decision.message ?? "Permission denied",
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object";
}

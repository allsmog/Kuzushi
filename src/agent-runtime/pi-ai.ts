import {
  complete,
  getModel,
  type AssistantMessage as PiAiAssistantMessage,
  type Context as PiAiContext,
  type KnownProvider,
  type Tool,
  type ToolCall as PiAiToolCall,
  validateToolCall,
} from "@mariozechner/pi-ai";
import { isRecord, normalizeCostUsd, toErrorMessage } from "../utils.js";
import { parsePiAiModelSpec } from "./model-spec.js";
import { executeTool, PI_AI_TOOL_DEFINITIONS } from "./tools.js";
import type { AgentMessage, AgentQueryRequest, AgentRuntime } from "./types.js";

const DEFAULT_MAX_TURNS = 10;
const KNOWN_TOOL_NAMES = new Set(["Read", "Glob", "Grep"]);

export class PiAiAgentRuntime implements AgentRuntime {
  readonly id = "pi-ai";

  async *query(request: AgentQueryRequest): AsyncIterable<AgentMessage> {
    const startedAtMs = Date.now();
    const maxTurns = normalizeMaxTurns(request.options.maxTurns);
    const signal = request.options.abortController?.signal;
    const maxBudgetUsd = normalizeBudget(request.options.maxBudgetUsd);
    let totalCostUsd = 0;
    let generatedToolCallCounter = 0;

    try {
      const model = resolveModel(request.options.model);
      const enabledTools = resolveEnabledTools(
        request.options.allowedTools,
        request.options.disallowedTools,
      );
      const context: PiAiContext = {
        systemPrompt: buildSystemPrompt(request.options.outputFormat?.schema),
        messages: [
          {
            role: "user",
            content: request.prompt,
            timestamp: Date.now(),
          },
        ],
        ...(enabledTools.length > 0 ? { tools: enabledTools } : {}),
      };

      const toolsByName = new Map(enabledTools.map((tool) => [tool.name, tool]));

      for (let turn = 1; turn <= maxTurns; turn++) {
        if (signal?.aborted) {
          yield errorResult(
            "error_aborted",
            "pi-ai agent run aborted",
            startedAtMs,
            turn - 1,
            totalCostUsd,
          );
          return;
        }

        const assistant = await complete(model, context, { signal });
        context.messages.push(assistant);
        totalCostUsd += extractCostUsd(assistant);

        const assistantContent = mapAssistantContent(assistant);
        if (assistantContent.length > 0) {
          yield {
            type: "assistant",
            content: assistantContent,
          };
        }

        if (assistant.stopReason === "aborted" || signal?.aborted) {
          yield errorResult(
            "error_aborted",
            assistant.errorMessage ?? "pi-ai agent run aborted",
            startedAtMs,
            turn,
            totalCostUsd,
          );
          return;
        }

        if (assistant.stopReason === "error") {
          yield errorResult(
            "error_runtime",
            assistant.errorMessage ?? "pi-ai request failed",
            startedAtMs,
            turn,
            totalCostUsd,
          );
          return;
        }

        const toolCalls = assistant.content.filter((block): block is PiAiToolCall => (
          block.type === "toolCall"
        ));

        if (toolCalls.length === 0) {
          const resultText = extractText(assistant);
          const structuredOutput = request.options.outputFormat
            ? parseStructuredOutput(resultText)
            : undefined;

          yield {
            type: "result",
            subtype: "success",
            result: resultText,
            structuredOutput,
            durationMs: Date.now() - startedAtMs,
            numTurns: turn,
            totalCostUsd: normalizeCostUsd(totalCostUsd),
          };
          return;
        }

        if (maxBudgetUsd != null && totalCostUsd > maxBudgetUsd) {
          yield errorResult(
            "error_budget_exceeded",
            `pi-ai budget exceeded: cost $${normalizeCostUsd(totalCostUsd).toFixed(4)} > max $${maxBudgetUsd.toFixed(4)}`,
            startedAtMs,
            turn,
            totalCostUsd,
          );
          return;
        }

        if (turn >= maxTurns) {
          yield errorResult(
            "error_max_turns",
            `pi-ai agent exceeded max turns (${maxTurns}) before producing a final response`,
            startedAtMs,
            turn,
            totalCostUsd,
          );
          return;
        }

        for (const toolCall of toolCalls) {
          const toolUseId = toolCall.id || `${toolCall.name}_${Date.now()}_${++generatedToolCallCounter}`;
          const startedToolMs = Date.now();

          const tool = toolsByName.get(toolCall.name);
          if (!tool) {
            const unknownToolMessage = `Tool "${toolCall.name}" is not enabled`;
            const elapsedSeconds = Math.max(0, (Date.now() - startedToolMs) / 1000);
            yield {
              type: "tool-progress",
              toolUseId,
              toolName: toolCall.name,
              elapsedSeconds,
            };
            yield {
              type: "tool-summary",
              summary: summarizeToolResult(toolCall.name, unknownToolMessage, true),
              precedingToolUseIds: [toolUseId],
            };
            context.messages.push({
              role: "toolResult",
              toolCallId: toolUseId,
              toolName: toolCall.name,
              content: [{ type: "text", text: unknownToolMessage }],
              isError: true,
              timestamp: Date.now(),
            });
            continue;
          }

          let validatedArgs: Record<string, unknown>;
          try {
            validatedArgs = validateToolCall(enabledTools, toolCall) as Record<string, unknown>;
          } catch (error) {
            const validationError = toErrorMessage(error);
            const elapsedSeconds = Math.max(0, (Date.now() - startedToolMs) / 1000);
            yield {
              type: "tool-progress",
              toolUseId,
              toolName: toolCall.name,
              elapsedSeconds,
            };
            yield {
              type: "tool-summary",
              summary: summarizeToolResult(toolCall.name, validationError, true),
              precedingToolUseIds: [toolUseId],
            };
            context.messages.push({
              role: "toolResult",
              toolCallId: toolUseId,
              toolName: toolCall.name,
              content: [{ type: "text", text: validationError }],
              isError: true,
              timestamp: Date.now(),
            });
            continue;
          }

          const permission = await canUseTool(
            request,
            toolCall.name,
            validatedArgs,
            signal,
            toolUseId,
          );

          if (permission.behavior === "deny") {
            yield errorResult(
              "error_permission_denied",
              permission.message ?? `Permission denied for tool "${toolCall.name}"`,
              startedAtMs,
              turn,
              totalCostUsd,
            );
            return;
          }

          let isToolError = false;
          let toolResultText = "";
          try {
            toolResultText = await executeTool(
              toolCall.name,
              validatedArgs,
              request.options.cwd,
            );
          } catch (error) {
            isToolError = true;
            toolResultText = toErrorMessage(error);
          }

          const elapsedSeconds = Math.max(0, (Date.now() - startedToolMs) / 1000);
          yield {
            type: "tool-progress",
            toolUseId,
            toolName: toolCall.name,
            elapsedSeconds,
          };
          yield {
            type: "tool-summary",
            summary: summarizeToolResult(toolCall.name, toolResultText, isToolError),
            precedingToolUseIds: [toolUseId],
          };

          context.messages.push({
            role: "toolResult",
            toolCallId: toolUseId,
            toolName: toolCall.name,
            content: [{ type: "text", text: toolResultText }],
            isError: isToolError,
            timestamp: Date.now(),
          });
        }
      }

      yield errorResult(
        "error_max_turns",
        `pi-ai agent exceeded max turns (${maxTurns})`,
        startedAtMs,
        maxTurns,
        totalCostUsd,
      );
    } catch (error) {
      const aborted = signal?.aborted === true;
      yield errorResult(
        aborted ? "error_aborted" : "error_runtime",
        toErrorMessage(error),
        startedAtMs,
        0,
        totalCostUsd,
      );
    }
  }
}

function resolveModel(modelSpec: string) {
  const { provider, modelId } = parsePiAiModelSpec(modelSpec);

  try {
    return getModel(provider as KnownProvider, modelId as never);
  } catch (error) {
    throw new Error(
      `Unable to resolve pi-ai model "${modelSpec}": ${toErrorMessage(error)}`,
    );
  }
}

function resolveEnabledTools(
  allowedTools: string[] | undefined,
  disallowedTools: string[] | undefined,
): Tool[] {
  const allowSet = new Set<string>();
  if (Array.isArray(allowedTools) && allowedTools.length > 0) {
    for (const toolName of allowedTools) {
      if (KNOWN_TOOL_NAMES.has(toolName)) {
        allowSet.add(toolName);
      }
    }
  } else {
    for (const toolName of KNOWN_TOOL_NAMES) {
      allowSet.add(toolName);
    }
  }

  if (Array.isArray(disallowedTools)) {
    for (const toolName of disallowedTools) {
      allowSet.delete(toolName);
    }
  }

  return PI_AI_TOOL_DEFINITIONS.filter((tool) => allowSet.has(tool.name));
}

function buildSystemPrompt(schema: Record<string, unknown> | undefined): string {
  const lines = [
    "You are a code security agent operating on a local repository.",
    "Use available tools (Read, Glob, Grep) when code inspection is required.",
    "When you call tools, pass valid JSON arguments.",
  ];

  if (schema) {
    lines.push(
      "",
      "Return the final answer as JSON only (no markdown fences).",
      "The JSON must match this schema exactly:",
      JSON.stringify(schema),
    );
  }

  return lines.join("\n");
}

function mapAssistantContent(
  assistant: PiAiAssistantMessage,
): Array<Record<string, unknown>> {
  const content: Array<Record<string, unknown>> = [];

  for (const block of assistant.content) {
    if (block.type === "text") {
      content.push({
        type: "text",
        text: block.text,
      });
      continue;
    }

    if (block.type === "thinking") {
      content.push({
        type: "text",
        text: block.thinking,
      });
      continue;
    }

    if (block.type === "toolCall") {
      content.push({
        type: "tool_use",
        id: block.id,
        name: block.name,
        input: isRecord(block.arguments) ? block.arguments : {},
      });
    }
  }

  return content;
}

function extractText(assistant: PiAiAssistantMessage): string {
  const textBlocks = assistant.content
    .filter((block): block is Extract<PiAiAssistantMessage["content"][number], { type: "text" }> => (
      block.type === "text"
    ))
    .map((block) => block.text.trim())
    .filter(Boolean);

  return textBlocks.join("\n\n");
}

function parseStructuredOutput(resultText: string): unknown {
  const extracted = extractJsonObject(resultText);
  if (!extracted) {
    return undefined;
  }

  try {
    return JSON.parse(extracted);
  } catch {
    return undefined;
  }
}

function extractJsonObject(text: string): string | null {
  const trimmed = text.trim();
  if (!trimmed) {
    return null;
  }

  const fenceMatch = trimmed.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (fenceMatch) {
    return fenceMatch[1].trim();
  }

  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start !== -1 && end > start) {
    return trimmed.slice(start, end + 1);
  }

  return trimmed;
}

function extractCostUsd(message: PiAiAssistantMessage): number {
  return normalizeCostUsd(message.usage?.cost?.total);
}

function normalizeMaxTurns(value: number | undefined): number {
  if (!Number.isFinite(value) || value == null || value < 1) {
    return DEFAULT_MAX_TURNS;
  }

  return Math.floor(value);
}

function normalizeBudget(value: number | undefined): number | undefined {
  if (!Number.isFinite(value) || value == null || value < 0) {
    return undefined;
  }

  return value;
}

async function canUseTool(
  request: AgentQueryRequest,
  toolName: string,
  args: Record<string, unknown>,
  signal: AbortSignal | undefined,
  toolUseId: string,
) {
  if (!request.options.canUseTool) {
    return { behavior: "allow" } as const;
  }

  return request.options.canUseTool(toolName, args, {
    signal: signal ?? new AbortController().signal,
    toolUseId,
  });
}

function summarizeToolResult(toolName: string, toolResult: string, isError: boolean): string {
  const firstLine = toolResult
    .split("\n")
    .map((line) => line.trim())
    .find(Boolean);

  if (isError) {
    return `${toolName} failed${firstLine ? `: ${firstLine}` : ""}`;
  }

  return `${toolName} completed${firstLine ? `: ${firstLine}` : ""}`;
}

function errorResult(
  subtype: string,
  error: string,
  startedAtMs: number,
  numTurns: number,
  totalCostUsd: number,
): AgentMessage {
  return {
    type: "result",
    subtype,
    errors: [error],
    durationMs: Date.now() - startedAtMs,
    numTurns,
    totalCostUsd: normalizeCostUsd(totalCostUsd),
  };
}

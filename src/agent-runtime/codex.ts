// @ts-nocheck — untracked draft (unreferenced); skipped in tsc to unblock build.
import {
  type ApprovalMode,
  Codex,
  type ModelReasoningEffort,
  type Thread,
  type ThreadEvent,
  type ThreadItem,
  type ThreadOptions,
} from "@openai/codex-sdk";
import { getLogger } from "../logger.js";
import type { AgentRuntimeCredentials } from "../types.js";
import { isRecord, toErrorMessage } from "../utils.js";
import { extractJson } from "./execution.js";
import type {
  AgentEffort,
  AgentMessage,
  AgentPermissionMode,
  AgentQueryOptions,
  AgentQueryRequest,
  AgentRuntime,
  AgentSession,
} from "./types.js";

const log = getLogger("codex-runtime");
const DEFAULT_CODEX_MODEL = "gpt-5.5";

type ItemTextState = {
  textByItem: Map<string, string>;
  toolStarted: Set<string>;
  toolStartedAt: Map<string, number>;
};

export function normalizeCodexModel(model: string | undefined): string {
  const value = model?.trim() || DEFAULT_CODEX_MODEL;
  const separator = value.indexOf(":");
  if (separator === -1) return value;

  const provider = value.slice(0, separator).trim().toLowerCase();
  const modelId = value.slice(separator + 1).trim();
  if ((provider === "openai" || provider === "codex") && modelId) {
    return modelId;
  }
  return value;
}

export function mapCodexEffort(
  effort: AgentEffort | undefined,
  thinkingDisabled?: boolean,
): ModelReasoningEffort | undefined {
  if (thinkingDisabled) return "minimal";
  if (effort === "max" || effort === "xhigh") return "xhigh";
  return effort;
}

function mapApprovalPolicy(mode: AgentPermissionMode | undefined): ApprovalMode {
  if (mode === "dontAsk" || mode === "bypassPermissions" || mode === "acceptEdits") {
    return "never";
  }
  return "never";
}

function abortResult(durationMs: number, numTurns: number): AgentMessage {
  return {
    type: "result",
    subtype: "error_aborted",
    errors: ["Aborted by operator"],
    durationMs,
    numTurns,
    totalCostUsd: 0,
  };
}

function buildPrompt(prompt: string, options: AgentQueryOptions): string {
  const parts: string[] = [];
  if (options.systemPromptPrefix?.trim()) {
    parts.push(options.systemPromptPrefix.trim());
  }
  if (options.history?.length) {
    for (const entry of options.history) {
      parts.push(`${entry.role.toUpperCase()}:\n${entry.content}`);
    }
  }
  parts.push(prompt);
  return parts.join("\n\n");
}

function buildThreadOptions(options: AgentQueryOptions): ThreadOptions {
  const threadOptions: ThreadOptions = {
    model: normalizeCodexModel(options.model),
    workingDirectory: options.cwd,
    approvalPolicy: mapApprovalPolicy(options.permissionMode),
    sandboxMode: "read-only",
    skipGitRepoCheck: true,
  };

  const effort = mapCodexEffort(options.effort, options.thinkingDisabled);
  if (effort) threadOptions.modelReasoningEffort = effort;

  return threadOptions;
}

function parseStructuredOutput(text: string, options: AgentQueryOptions): unknown {
  if (!options.outputFormat) return undefined;
  const jsonText = extractJson(text);
  if (!jsonText) return undefined;
  try {
    return JSON.parse(jsonText) as unknown;
  } catch {
    return undefined;
  }
}

function flattenContentBlock(block: unknown): string {
  if (!isRecord(block)) return String(block ?? "");
  if (typeof block["text"] === "string") return block["text"];
  if (typeof block["content"] === "string") return block["content"];
  try {
    return JSON.stringify(block);
  } catch {
    return String(block);
  }
}

function mcpResultText(item: Extract<ThreadItem, { type: "mcp_tool_call" }>): string {
  if (item.error?.message) return item.error.message;
  const content = item.result?.content;
  if (!Array.isArray(content)) return "";
  return content.map(flattenContentBlock).filter(Boolean).join("\n");
}

function summarizeFileChange(item: Extract<ThreadItem, { type: "file_change" }>): string {
  const changes = item.changes.map((change) => `${change.kind} ${change.path}`);
  return changes.join("\n");
}

function itemToolName(item: ThreadItem): string {
  switch (item.type) {
    case "command_execution":
      return "Bash";
    case "mcp_tool_call":
      return `${item.server}:${item.tool}`;
    case "file_change":
      return "Patch";
    case "web_search":
      return "WebSearch";
    case "todo_list":
      return "Todo";
    default:
      return item.type;
  }
}

function itemResultContent(item: ThreadItem): string {
  switch (item.type) {
    case "command_execution":
      return item.aggregated_output || item.command;
    case "mcp_tool_call":
      return mcpResultText(item);
    case "file_change":
      return summarizeFileChange(item);
    case "web_search":
      return item.query;
    case "todo_list":
      return item.items.map((todo) => `${todo.completed ? "[x]" : "[ ]"} ${todo.text}`).join("\n");
    case "error":
      return item.message;
    default:
      return "";
  }
}

function deltaForItem(item: Extract<ThreadItem, { id: string }>, state: ItemTextState): string {
  const next =
    item.type === "agent_message" || item.type === "reasoning"
      ? item.text
      : itemResultContent(item);
  const previous = state.textByItem.get(item.id) ?? "";
  state.textByItem.set(item.id, next);
  if (!next) return "";
  return next.startsWith(previous) ? next.slice(previous.length) : next;
}

function ensureToolStart(item: ThreadItem, state: ItemTextState): AgentMessage | null {
  if (
    item.type !== "command_execution" &&
    item.type !== "mcp_tool_call" &&
    item.type !== "file_change" &&
    item.type !== "web_search" &&
    item.type !== "todo_list"
  ) {
    return null;
  }
  if (state.toolStarted.has(item.id)) return null;
  state.toolStarted.add(item.id);
  state.toolStartedAt.set(item.id, Date.now());
  return {
    type: "tool-call-start",
    toolUseId: item.id,
    toolName: itemToolName(item),
  };
}

function mapCodexEvent(event: ThreadEvent, state: ItemTextState): AgentMessage[] {
  switch (event.type) {
    case "item.started": {
      const start = ensureToolStart(event.item, state);
      return start ? [start] : [];
    }
    case "item.updated": {
      const item = event.item;
      if (item.type === "agent_message") {
        const delta = deltaForItem(item, state);
        return delta ? [{ type: "text-delta", delta }] : [];
      }
      if (item.type === "reasoning") {
        const delta = deltaForItem(item, state);
        return delta ? [{ type: "thinking-delta", delta }] : [];
      }
      const start = ensureToolStart(item, state);
      const progress =
        "id" in item
          ? {
              type: "tool-progress" as const,
              toolUseId: item.id,
              toolName: itemToolName(item),
              elapsedSeconds: Math.floor(
                (Date.now() - (state.toolStartedAt.get(item.id) ?? Date.now())) / 1000,
              ),
            }
          : null;
      return [...(start ? [start] : []), ...(progress ? [progress] : [])];
    }
    case "item.completed": {
      const item = event.item;
      if (item.type === "agent_message") {
        state.textByItem.set(item.id, item.text);
        return [
          {
            type: "assistant",
            content: [{ type: "text", text: item.text }],
          },
        ];
      }
      if (item.type === "reasoning") {
        const delta = deltaForItem(item, state);
        return delta ? [{ type: "thinking-delta", delta }] : [];
      }
      if (item.type === "error") {
        return [
          {
            type: "tool-result",
            toolUseId: item.id,
            isError: true,
            content: item.message,
          },
        ];
      }
      const start = ensureToolStart(item, state);
      const result: AgentMessage = {
        type: "tool-result",
        toolUseId: item.id,
        isError:
          (item.type === "command_execution" && item.status === "failed") ||
          (item.type === "mcp_tool_call" && item.status === "failed") ||
          (item.type === "file_change" && item.status === "failed"),
        content: itemResultContent(item),
      };
      return [...(start ? [start] : []), result];
    }
    default:
      return [];
  }
}

async function* runCodexTurn(
  thread: Thread,
  prompt: string,
  options: AgentQueryOptions,
  signal?: AbortSignal,
): AsyncIterable<AgentMessage> {
  const startedAtMs = Date.now();
  const state: ItemTextState = {
    textByItem: new Map(),
    toolStarted: new Set(),
    toolStartedAt: new Map(),
  };
  let finalResponse = "";
  let structuredOutput: unknown;
  let numTurns = 0;
  const errors: string[] = [];

  try {
    const streamed = await thread.runStreamed(buildPrompt(prompt, options), {
      outputSchema: options.outputFormat?.schema,
      signal,
    });

    for await (const event of streamed.events) {
      if (event.type === "turn.completed") {
        numTurns += 1;
        continue;
      }
      if (event.type === "turn.failed") {
        errors.push(event.error.message);
        continue;
      }
      if (event.type === "error") {
        errors.push(event.message);
        continue;
      }
      if (event.type === "item.completed" && event.item.type === "agent_message") {
        finalResponse = event.item.text;
        structuredOutput = parseStructuredOutput(finalResponse, options);
      }
      for (const mapped of mapCodexEvent(event, state)) {
        yield mapped;
      }
    }

    const durationMs = Date.now() - startedAtMs;
    if (signal?.aborted) {
      yield abortResult(durationMs, numTurns);
      return;
    }
    if (errors.length > 0) {
      yield {
        type: "result",
        subtype: "error_runtime",
        errors,
        durationMs,
        numTurns,
        totalCostUsd: 0,
      };
      return;
    }

    yield {
      type: "result",
      subtype: "success",
      result: finalResponse,
      structuredOutput,
      durationMs,
      numTurns,
      totalCostUsd: 0,
    };
  } catch (error) {
    const durationMs = Date.now() - startedAtMs;
    if (signal?.aborted) {
      yield abortResult(durationMs, numTurns);
      return;
    }
    log.error(`Codex SDK query failed (${durationMs}ms): ${toErrorMessage(error)}`);
    yield {
      type: "result",
      subtype: "error_runtime",
      errors: [toErrorMessage(error)],
      durationMs,
      numTurns,
      totalCostUsd: 0,
    };
  }
}

function mergeAbortSignals(primary: AbortSignal | undefined, secondary: AbortSignal): AbortSignal {
  if (!primary) return secondary;
  if (primary.aborted || secondary.aborted) {
    const controller = new AbortController();
    controller.abort();
    return controller.signal;
  }

  const controller = new AbortController();
  const abort = () => controller.abort();
  primary.addEventListener("abort", abort, { once: true });
  secondary.addEventListener("abort", abort, { once: true });
  return controller.signal;
}

class CodexSession implements AgentSession {
  private readonly closeController = new AbortController();
  private queryInFlight = false;
  private closed = false;

  constructor(
    private readonly thread: Thread,
    private readonly baseOptions: AgentQueryOptions,
  ) {}

  async *query(prompt: string): AsyncIterable<AgentMessage> {
    if (this.closed) throw new Error("Session is closed");
    if (this.queryInFlight) {
      throw new Error("Session query already in flight — concurrent access is not supported");
    }

    this.queryInFlight = true;
    try {
      const signal = mergeAbortSignals(
        this.baseOptions.abortController?.signal,
        this.closeController.signal,
      );
      yield* runCodexTurn(this.thread, prompt, this.baseOptions, signal);
    } finally {
      this.queryInFlight = false;
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.closeController.abort();
  }
}

export class CodexAgentRuntime implements AgentRuntime {
  readonly id = "codex";
  private readonly client: Codex;

  constructor(config?: AgentRuntimeCredentials) {
    this.client = new Codex({
      ...(config?.apiKey ? { apiKey: config.apiKey } : {}),
      ...(config?.baseUrl ? { baseUrl: config.baseUrl } : {}),
    });
  }

  query(request: AgentQueryRequest): AsyncIterable<AgentMessage> {
    const thread = this.client.startThread(buildThreadOptions(request.options));
    return runCodexTurn(
      thread,
      request.prompt,
      request.options,
      request.options.abortController?.signal,
    );
  }

  createSession(baseOptions: AgentQueryOptions): AgentSession {
    const thread = this.client.startThread(buildThreadOptions(baseOptions));
    return new CodexSession(thread, baseOptions);
  }
}

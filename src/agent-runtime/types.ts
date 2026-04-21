export type AgentPermissionMode =
  | "default"
  | "acceptEdits"
  | "bypassPermissions"
  | "plan"
  | "dontAsk";

export type AgentToolDecision = { behavior: "allow" } | { behavior: "deny"; message?: string };

export interface AgentHistoryEntry {
  role: "user" | "assistant";
  content: string;
}

export type AgentEffort = "low" | "medium" | "high" | "max";

export interface AgentQueryOptions {
  cwd: string;
  model: string;
  temperature?: number;
  maxOutputTokens?: number;
  allowedTools?: string[];
  disallowedTools?: string[];
  permissionMode?: AgentPermissionMode;
  maxBudgetUsd?: number;
  abortController?: AbortController;
  history?: AgentHistoryEntry[];
  outputFormat?: {
    type: "json_schema";
    schema: Record<string, unknown>;
    strict?: boolean;
    retryInvalidStructuredOutput?: number;
  };
  /** Static content prepended to the system prompt. Cached by Anthropic's prompt caching. */
  systemPromptPrefix?: string;
  /** Controls thinking depth. low = fast/cheap, high = deep reasoning. */
  effort?: AgentEffort;
  /** Disable extended thinking entirely (overrides effort). */
  thinkingDisabled?: boolean;
  /** Fallback model if primary fails or is unavailable. */
  fallbackModel?: string;
  /** Claude Code plugins to load in the subprocess. */
  plugins?: Array<{ type: "local"; path: string }>;
  canUseTool?: (
    toolName: string,
    input: Record<string, unknown>,
    options: {
      signal: AbortSignal;
      toolUseId: string;
      blockedPath?: string;
      decisionReason?: string;
    },
  ) => Promise<AgentToolDecision> | AgentToolDecision;
}

export interface AgentQueryRequest {
  prompt: string;
  options: AgentQueryOptions;
}

export interface AgentResultSuccessMessage {
  type: "result";
  subtype: "success";
  result: string;
  structuredOutput?: unknown;
  durationMs?: number;
  numTurns?: number;
  totalCostUsd?: number;
}

export interface AgentResultErrorMessage {
  type: "result";
  subtype: Exclude<string, "success"> | "error_tool_loop" | "error_timeout";
  errors: string[];
  durationMs?: number;
  numTurns?: number;
  totalCostUsd?: number;
}

export interface AgentAssistantMessage {
  type: "assistant";
  content: Array<Record<string, unknown>>;
}

export interface AgentToolProgressMessage {
  type: "tool-progress";
  toolUseId: string;
  toolName: string;
  elapsedSeconds: number;
}

export interface AgentToolSummaryMessage {
  type: "tool-summary";
  summary: string;
  precedingToolUseIds: string[];
}

export interface AgentToolResultMessage {
  type: "tool-result";
  toolUseId: string;
  /** True when the tool returned an error (SDK Zod validation, execution error, etc.). */
  isError: boolean;
  /** Text content of the tool_result block, already flattened to a string. */
  content: string;
}

/**
 * Streaming deltas surfaced by the pi-ai runtime while an assistant turn
 * is building. Consumers are free to ignore them; they carry no semantic
 * state the final `assistant` / `tool-result` yields don't already cover.
 *
 * Exists so UIs can show forward motion during a slow turn (e.g. a 20-second
 * Write emitting a 30KB JSON) instead of a silent spinner.
 */
export interface AgentTextDeltaMessage {
  type: "text-delta";
  delta: string;
}

export interface AgentToolCallStartMessage {
  type: "tool-call-start";
  toolUseId: string;
  toolName: string;
}

export interface AgentToolCallDeltaMessage {
  type: "tool-call-delta";
  toolUseId: string;
  /** Raw JSON fragment appended to the tool call's input-so-far. */
  delta: string;
}

export interface AgentThinkingDeltaMessage {
  type: "thinking-delta";
  delta: string;
}

export interface AgentUnknownMessage {
  type: "unknown";
  raw: unknown;
}

export type AgentMessage =
  | AgentResultSuccessMessage
  | AgentResultErrorMessage
  | AgentAssistantMessage
  | AgentToolProgressMessage
  | AgentToolSummaryMessage
  | AgentToolResultMessage
  | AgentTextDeltaMessage
  | AgentToolCallStartMessage
  | AgentToolCallDeltaMessage
  | AgentThinkingDeltaMessage
  | AgentUnknownMessage;

export interface AgentSession {
  /** Send a prompt and stream back results within the same subprocess. */
  query(prompt: string): AsyncIterable<AgentMessage>;
  /** Close the subprocess. */
  close(): Promise<void>;
}

export interface AgentBatchRequest {
  id: string;
  prompt: string;
  systemPrompt?: string;
}

export interface AgentRuntime {
  readonly id: string;
  query(request: AgentQueryRequest): AsyncIterable<AgentMessage>;
  /** Create a reusable session backed by a single subprocess. */
  createSession?(baseOptions: AgentQueryOptions): AgentSession;
  /** Submit multiple prompts as a batch for async processing at 50% cost. */
  queryBatch?(
    requests: AgentBatchRequest[],
    baseOptions: AgentQueryOptions,
  ): Promise<
    Map<
      string,
      {
        resultText: string;
        structuredOutput: unknown;
        executionError: string | null;
        costUsd: number;
      }
    >
  >;
}

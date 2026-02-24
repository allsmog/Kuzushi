export type AgentPermissionMode =
  | "default"
  | "acceptEdits"
  | "bypassPermissions"
  | "plan"
  | "dontAsk";

export type AgentToolDecision =
  | { behavior: "allow" }
  | { behavior: "deny"; message?: string };

export interface AgentQueryOptions {
  cwd: string;
  model: string;
  maxTurns?: number;
  allowedTools?: string[];
  disallowedTools?: string[];
  permissionMode?: AgentPermissionMode;
  maxBudgetUsd?: number;
  abortController?: AbortController;
  outputFormat?: {
    type: "json_schema";
    schema: Record<string, unknown>;
  };
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
  subtype: Exclude<string, "success">;
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
  | AgentUnknownMessage;

export interface AgentRuntime {
  readonly id: string;
  query(request: AgentQueryRequest): AsyncIterable<AgentMessage>;
}

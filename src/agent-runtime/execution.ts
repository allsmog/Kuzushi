import type { RepoContext } from "../types.js";
import { isRecord } from "../utils.js";
import { getAgentRuntime, type AgentRuntime } from "./index.js";

export const DEFAULT_READ_ONLY_TOOLS = ["Read", "Glob", "Grep"] as const;

export interface AgentActivity {
  kind: "tool-start" | "tool-progress" | "tool-complete" | "reasoning";
  toolName?: string;
  toolInput?: Record<string, unknown>;
  summary?: string;
  elapsedSeconds?: number;
}

export type AgentActivityCallback = (
  activity: AgentActivity,
) => Promise<void> | void;

export interface AgentRuntimeOptions {
  runtime?: AgentRuntime;
  abortController?: AbortController;
  maxBudgetUsd?: number;
  activityCallback?: AgentActivityCallback;
}

export interface AgentQueryExecutionResult {
  resultText: string;
  structuredOutput: unknown;
  executionError: string | null;
  costUsd: number;
}

export interface StructuredAgentQueryArgs {
  prompt: string;
  cwd: string;
  model: string;
  maxTurns?: number | null;
  allowedTools: string[];
  runtimeOptions?: AgentRuntimeOptions;
  schema: Record<string, unknown>;
  strict?: boolean;
  retryInvalidStructuredOutput?: number;
}

/** Extract JSON from agent text, handling markdown fences and prose wrappers. */
export function extractJson(text: string): string {
  const fenceMatch = text.match(/```(?:json)?\s*\n([\s\S]*?)\n\s*```/);
  if (fenceMatch) {
    return fenceMatch[1].trim();
  }

  const braceStart = text.indexOf("{");
  const braceEnd = text.lastIndexOf("}");
  if (braceStart !== -1 && braceEnd > braceStart) {
    return text.slice(braceStart, braceEnd + 1);
  }

  return text.trim();
}

export async function runStructuredAgentQuery(
  args: StructuredAgentQueryArgs,
): Promise<AgentQueryExecutionResult> {
  const runtime = args.runtimeOptions?.runtime ?? getAgentRuntime();
  let resultText = "";
  let structuredOutput: unknown = undefined;
  let executionError: string | null = null;
  let costUsd = 0;

  for await (const message of runtime.query({
    prompt: args.prompt,
    options: {
      cwd: args.cwd,
      model: args.model,
      maxTurns: args.maxTurns,
      allowedTools: [...args.allowedTools],
      permissionMode: "dontAsk",
      maxBudgetUsd: args.runtimeOptions?.maxBudgetUsd,
      abortController: args.runtimeOptions?.abortController,
      outputFormat: {
        type: "json_schema",
        schema: args.schema,
        strict: args.strict,
        retryInvalidStructuredOutput: args.retryInvalidStructuredOutput,
      },
    },
  })) {
    if (message.type === "assistant") {
      await emitAssistantActivity(message.content, args.runtimeOptions?.activityCallback);
      continue;
    }

    if (message.type === "tool-progress") {
      await args.runtimeOptions?.activityCallback?.({
        kind: "tool-progress",
        toolName: message.toolName,
        elapsedSeconds: message.elapsedSeconds,
      });
      continue;
    }

    if (message.type === "tool-summary") {
      await args.runtimeOptions?.activityCallback?.({
        kind: "tool-complete",
        summary: message.summary,
      });
      continue;
    }

    if (message.type !== "result") {
      continue;
    }

    if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
      costUsd = message.totalCostUsd;
    }

    if ("result" in message) {
      resultText = message.result;
      structuredOutput = message.structuredOutput;
      continue;
    }

    executionError = (Array.isArray(message.errors) ? message.errors.join("; ") : "")
      || message.subtype
      || "unknown error";
  }

  return {
    resultText,
    structuredOutput,
    executionError,
    costUsd,
  };
}

export function resolveRepoContextAndRuntimeOptions<T extends AgentRuntimeOptions>(
  repoContextOrRuntimeOptions: RepoContext | T | undefined,
  maybeRuntimeOptions: T,
): { repoContext?: RepoContext; runtimeOptions: T } {
  if (!repoContextOrRuntimeOptions) {
    return { runtimeOptions: maybeRuntimeOptions };
  }

  if (looksLikeRuntimeOptions(repoContextOrRuntimeOptions)) {
    return {
      runtimeOptions: repoContextOrRuntimeOptions,
    };
  }

  return {
    repoContext: repoContextOrRuntimeOptions,
    runtimeOptions: maybeRuntimeOptions,
  };
}

function looksLikeRuntimeOptions<T extends AgentRuntimeOptions>(
  value: RepoContext | T,
): value is T {
  const runtimeOptions = value as T;
  return (
    "runtime" in runtimeOptions
    || "abortController" in runtimeOptions
    || "maxBudgetUsd" in runtimeOptions
    || "activityCallback" in runtimeOptions
  );
}

async function emitAssistantActivity(
  blocks: Array<Record<string, unknown>>,
  callback: AgentActivityCallback | undefined,
): Promise<void> {
  if (!callback) {
    return;
  }

  for (const block of blocks) {
    const blockType = asString(block["type"], "");

    if (blockType === "tool_use") {
      const toolName = asString(block["name"], "");
      const input = isRecord(block["input"]) ? block["input"] : undefined;
      await callback({
        kind: "tool-start",
        toolName: toolName || undefined,
        toolInput: input,
      });
      continue;
    }

    if (blockType === "text") {
      const text = asString(block["text"], "").trim();
      if (!text) {
        continue;
      }

      await callback({
        kind: "reasoning",
        summary: text,
      });
    }
  }
}

function asString(value: unknown, fallback: string): string {
  if (typeof value === "string") {
    return value;
  }
  if (value == null) {
    return fallback;
  }
  return String(value);
}

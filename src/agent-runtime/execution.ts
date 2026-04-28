import type { LlmCallCompleteEvent, LlmCallErrorEvent, LlmCallStartEvent } from "../bus/events.js";
import type { MessageBus } from "../bus/types.js";
import { inflightCache } from "../cache.js";
import { getLogger } from "../logger.js";
import type { RepoContext } from "../types.js";
import { isRecord, toErrorMessage } from "../utils.js";
import type { AgentActivityPhase, AgentHistoryEntry, AgentSession } from "./types.js";

const log = getLogger("batch-fallback");

import type { AgentEffort, AgentRuntime } from "./types.js";

export const DEFAULT_READ_ONLY_TOOLS = [
  "Read",
  "Glob",
  "Grep",
  "GetCallers",
  "GetCallees",
  "GetFunctionBody",
] as const;

export const SEMANTIC_NAVIGATION_TOOLS = [
  "GoToDefinition",
  "FindReferences",
  "TypeAtPosition",
] as const;

export function resolveDefaultReadOnlyTools(_runtime?: Pick<AgentRuntime, "id">): string[] {
  return [...DEFAULT_READ_ONLY_TOOLS, ...SEMANTIC_NAVIGATION_TOOLS];
}

export interface AgentActivity {
  kind: "tool-start" | "tool-progress" | "tool-complete" | "reasoning";
  toolName?: string;
  toolInput?: Record<string, unknown>;
  summary?: string;
  elapsedSeconds?: number;
}

export type AgentActivityCallback = (activity: AgentActivity) => Promise<void> | void;

export interface AgentRuntimeOptions {
  runtime?: AgentRuntime;
  abortController?: AbortController;
  maxBudgetUsd?: number;
  temperature?: number;
  maxOutputTokens?: number;
  history?: AgentHistoryEntry[];
  activityCallback?: AgentActivityCallback;
  /** Optional message bus for emitting LLM observability events. */
  bus?: MessageBus;
  /** Optional run ID for correlating observability events. */
  runId?: string;
  /** Controls thinking depth: low = fast/cheap, high = deep reasoning. */
  effort?: AgentEffort;
  /** Disable extended thinking entirely. */
  thinkingDisabled?: boolean;
  /** Reuse an existing session instead of spawning a new subprocess per call. */
  session?: AgentSession;
  /**
   * Caller-supplied task identifier. Threaded into the runtime so emitted
   * `task:activity` lines under the spinner are tagged with the right
   * task. Defaults to `"agent-runtime"` inside the runtime when omitted.
   */
  taskId?: string;
  /**
   * Per-target identifier (finding fingerprint, hunt target id) used as the
   * key for the "N agents active" counter. Combined with `phase` it makes
   * the runtime emit `${phase}:agent-activity` envelopes.
   */
  fingerprint?: string;
  /** Phase / pipeline stage that owns this query. Picks the bus topic prefix. */
  phase?: AgentActivityPhase;
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
  allowedTools: string[];
  runtimeOptions?: AgentRuntimeOptions;
  systemPromptPrefix?: string;
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
  // Include schema and allowedTools in the cache key to prevent
  // different-shaped queries with identical prompts from colliding.
  const extraKeyParts = [
    JSON.stringify(args.schema ?? ""),
    JSON.stringify(args.allowedTools ?? []),
  ].join("\x00");
  const cacheKey = inflightCache.generateKey(
    args.model,
    args.systemPromptPrefix ?? "",
    `${args.prompt}\x00${extraKeyParts}`,
    args.cwd,
  );

  try {
    return await inflightCache.getOrExecute(cacheKey, () => executeStructuredAgentQuery(args));
  } catch (error) {
    // executeStructuredAgentQuery throws a sentinel error for soft errors (e.g., LLM
    // returned an error result) to prevent caching. Extract the result from it.
    if (error instanceof Error && error.message === "__kuzushi_soft_error__") {
      return (error as unknown as Record<string, unknown>).__result as AgentQueryExecutionResult;
    }
    throw error;
  }
}

async function executeStructuredAgentQuery(
  args: StructuredAgentQueryArgs,
): Promise<AgentQueryExecutionResult> {
  const runtime = args.runtimeOptions?.runtime;
  if (!runtime) {
    throw new Error(
      "Agent runtime is required. Pass runtimeOptions.runtime explicitly when executing agent queries.",
    );
  }
  const bus = args.runtimeOptions?.bus;
  const runId = args.runtimeOptions?.runId ?? "";
  let resultText = "";
  let structuredOutput: unknown;
  let executionError: string | null = null;
  let costUsd = 0;
  const startedAtMs = Date.now();

  // Emit llm:call-start
  if (bus) {
    try {
      await bus.publish<LlmCallStartEvent>({
        type: "llm:call-start",
        meta: {
          id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          runId,
        },
        payload: {
          model: args.model,
          promptLength: args.prompt.length,
          runId,
        },
      });
    } catch {
      // Non-fatal: observability emission should never break execution
    }
  }

  try {
    // Use existing session if available (avoids spawning a new subprocess)
    const session = args.runtimeOptions?.session;
    const messageStream = session
      ? session.query(args.prompt)
      : runtime.query({
          prompt: args.prompt,
          options: {
            cwd: args.cwd,
            model: args.model,
            temperature: args.runtimeOptions?.temperature,
            maxOutputTokens: args.runtimeOptions?.maxOutputTokens,
            allowedTools: [...args.allowedTools],
            permissionMode: "dontAsk",
            maxBudgetUsd: args.runtimeOptions?.maxBudgetUsd,
            abortController: args.runtimeOptions?.abortController,
            history: args.runtimeOptions?.history,
            systemPromptPrefix: args.systemPromptPrefix,
            effort: args.runtimeOptions?.effort,
            thinkingDisabled: args.runtimeOptions?.thinkingDisabled,
            taskId: args.runtimeOptions?.taskId,
            fingerprint: args.runtimeOptions?.fingerprint,
            phase: args.runtimeOptions?.phase,
            outputFormat: {
              type: "json_schema",
              schema: args.schema,
              strict: args.strict,
              retryInvalidStructuredOutput: args.retryInvalidStructuredOutput,
            },
          },
        });

    for await (const message of messageStream) {
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

      executionError =
        (Array.isArray(message.errors) ? message.errors.join("; ") : "") ||
        message.subtype ||
        "unknown error";
    }

    // Emit llm:call-complete on success or non-throwing error
    if (bus) {
      const durationMs = Date.now() - startedAtMs;
      try {
        if (executionError) {
          await bus.publish<LlmCallErrorEvent>({
            type: "llm:call-error",
            meta: {
              id: crypto.randomUUID(),
              timestamp: new Date().toISOString(),
              runId,
            },
            payload: {
              model: args.model,
              error: executionError,
              retryable: false,
              runId,
            },
          });
        } else {
          await bus.publish<LlmCallCompleteEvent>({
            type: "llm:call-complete",
            meta: {
              id: crypto.randomUUID(),
              timestamp: new Date().toISOString(),
              runId,
            },
            payload: {
              model: args.model,
              durationMs,
              tokensUsed: 0, // Token count not available at this abstraction level
              costUsd,
              runId,
            },
          });
        }
      } catch {
        // Non-fatal: observability emission should never break execution
      }
    }
  } catch (error) {
    // Emit llm:call-error on thrown error
    if (bus) {
      try {
        const errorMessage = error instanceof Error ? error.message : String(error);
        await bus.publish<LlmCallErrorEvent>({
          type: "llm:call-error",
          meta: {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            runId,
          },
          payload: {
            model: args.model,
            error: errorMessage,
            retryable: false,
            runId,
          },
        });
      } catch {
        // Non-fatal
      }
    }
    throw error;
  }

  const result: AgentQueryExecutionResult = {
    resultText,
    structuredOutput,
    executionError,
    costUsd,
  };

  // Do not cache error results — throw so getOrExecute's error path prevents caching.
  // The caller (runStructuredAgentQuery) catches and returns the result.
  if (executionError) {
    const err = new Error("__kuzushi_soft_error__");
    (err as unknown as Record<string, unknown>).__result = result;
    throw err;
  }

  return result;
}

/**
 * Execute a structured query within an existing session (single subprocess).
 * Unlike `runStructuredAgentQuery()`, this does NOT spawn a new subprocess —
 * it sends the prompt as a turn on an already-running session.
 */
export async function runStructuredSessionQuery(
  session: AgentSession,
  prompt: string,
): Promise<AgentQueryExecutionResult> {
  let resultText = "";
  let structuredOutput: unknown;
  let executionError: string | null = null;
  let costUsd = 0;

  for await (const message of session.query(prompt)) {
    if (message.type !== "result") continue;

    if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
      costUsd = message.totalCostUsd;
    }

    if ("result" in message) {
      resultText = message.result;
      structuredOutput = message.structuredOutput;
    } else {
      executionError =
        (Array.isArray(message.errors) ? message.errors.join("; ") : "") ||
        message.subtype ||
        "unknown error";
    }
  }

  return { resultText, structuredOutput, executionError, costUsd };
}

/**
 * Map an async worker over `items` with a bounded concurrency limit. Preserves
 * input order in the result array. Errors propagate (no implicit swallow).
 *
 * Used by the `runStructuredBatchQuery` OAuth fallback so an operator's
 * `--triage-concurrency` (or per-task default) actually translates into N
 * parallel agent queries instead of strictly sequential ones. Kept generic so
 * other batch-fallback paths (taint labeling, llm-rescore) can adopt it.
 */
export async function mapConcurrent<T, R>(
  items: readonly T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const limit = Math.max(1, Math.floor(Number.isFinite(concurrency) ? concurrency : 1));
  const results = new Array<R>(items.length);
  if (items.length === 0) return results;

  let nextIndex = 0;
  const runners: Array<Promise<void>> = [];
  const runnerCount = Math.min(limit, items.length);
  for (let r = 0; r < runnerCount; r++) {
    runners.push(
      (async () => {
        while (true) {
          const i = nextIndex++;
          if (i >= items.length) return;
          results[i] = await worker(items[i], i);
        }
      })(),
    );
  }
  await Promise.all(runners);
  return results;
}

/**
 * Submit multiple tool-less prompts as a batch for 50% cost reduction.
 * Falls back to bounded-concurrency `runStructuredAgentQuery()` calls if the
 * runtime doesn't support batch processing (e.g. OAuth-mode Claude).
 */
export async function runStructuredBatchQuery(
  requests: Array<{ id: string; prompt: string; systemPrompt?: string }>,
  args: {
    cwd: string;
    model: string;
    schema: Record<string, unknown>;
    runtimeOptions?: AgentRuntimeOptions;
    effort?: AgentEffort;
    thinkingDisabled?: boolean;
    /**
     * Max parallel agent queries when the runtime falls back from the Batch
     * API to per-prompt calls (OAuth mode, proxy 404, etc.). Defaults to 1
     * (preserves prior strictly sequential behavior).
     */
    fallbackConcurrency?: number;
  },
): Promise<Map<string, AgentQueryExecutionResult>> {
  const runtime = args.runtimeOptions?.runtime;
  if (!runtime) {
    throw new Error("Agent runtime is required for batch queries.");
  }

  // Use batch API if available, fall back to sequential on endpoint errors (e.g. proxy 404).
  // Skip outright when the runtime is in OAuth mode — the throw is
  // synchronous and logging the same warning per batch is just noise
  // (field-test issue #28). The runtime exposes an `oauthMode` flag
  // set in claude.ts when no apiKey is configured.
  const batchUnavailableUnderOAuth =
    runtime.queryBatch && (runtime as { oauthMode?: boolean }).oauthMode === true;
  if (runtime.queryBatch && !batchUnavailableUnderOAuth) {
    try {
      return await runtime.queryBatch(
        requests.map((r) => ({ id: r.id, prompt: r.prompt, systemPrompt: r.systemPrompt })),
        {
          cwd: args.cwd,
          model: args.model,
          outputFormat: { type: "json_schema", schema: args.schema },
          effort: args.effort,
          thinkingDisabled: args.thinkingDisabled,
          permissionMode: "dontAsk",
        },
      );
    } catch (err) {
      log.warn(`Batch API failed, falling back to sequential: ${toErrorMessage(err)}`);
    }
  }

  // Fallback: run with bounded concurrency. The agent-runtime spawn
  // semaphore (claude.ts MAX_CONCURRENT_QUERIES) still caps subprocess
  // count, but bounded mapConcurrent here gives operators a way to tune
  // OAuth-mode throughput via --triage-concurrency without unbounded
  // promise creation.
  // Do NOT carry over temperature=0 from batch settings — the Batch API
  // handles temperature internally, but sequential queries with thinking
  // enabled require temperature=1 (or omitted to use the default).
  const concurrency = args.fallbackConcurrency ?? 1;
  const entries = await mapConcurrent(requests, concurrency, async (req) => {
    const result = await runStructuredAgentQuery({
      prompt: req.prompt,
      cwd: args.cwd,
      model: args.model,
      allowedTools: [],
      runtimeOptions: {
        ...args.runtimeOptions,
        temperature: undefined,
        effort: args.effort,
        thinkingDisabled: args.thinkingDisabled,
      },
      systemPromptPrefix: req.systemPrompt,
      schema: args.schema,
    });
    return [req.id, result] as const;
  });
  const results = new Map<string, AgentQueryExecutionResult>();
  for (const [id, result] of entries) {
    results.set(id, result);
  }
  return results;
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
    "runtime" in runtimeOptions ||
    "abortController" in runtimeOptions ||
    "maxBudgetUsd" in runtimeOptions ||
    "temperature" in runtimeOptions ||
    "maxOutputTokens" in runtimeOptions ||
    "history" in runtimeOptions ||
    "activityCallback" in runtimeOptions ||
    "bus" in runtimeOptions ||
    "runId" in runtimeOptions
  );
}

export async function emitAssistantActivity(
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

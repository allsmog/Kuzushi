import {
  type AssistantMessageEvent,
  getModel,
  type KnownProvider,
  type AssistantMessage as PiAiAssistantMessage,
  type Context as PiAiContext,
  type ToolCall as PiAiToolCall,
  stream,
  type Tool,
  validateToolCall,
} from "@mariozechner/pi-ai";
import { publishAgentActivity, publishTaskActivity } from "../bus/activity.js";
import type {
  LlmCallCompleteEvent,
  LlmCallErrorEvent,
  LlmCallStartEvent,
  LlmRetryEvent,
} from "../bus/events.js";
import type { MessageBus } from "../bus/types.js";
import { resolveAgentRuntimeConfig } from "../credentials.js";
import { KuzushiError, wrapError } from "../errors.js";
import { installGlobalDispatcher } from "../http-agent.js";
import { getLogger } from "../logger.js";
import { getRateLimitRegistry } from "../scheduler/index.js";
import type { AgentRuntimeCredentials } from "../types.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "../utils.js";
import { maybeCompactContext } from "./context-compactor.js";
import { enforceAgentQuery, resolveFallbackConsent } from "./enforcement.js";
import { parsePiAiModelSpec } from "./model-spec.js";
import { assertRuntimeModelSelection } from "./model-validation.js";
import { normalizeToolInput } from "./tool-input-normalizer.js";
import { summarizeToolCompletion } from "./tool-summary.js";
import { executeTool, PI_AI_TOOL_DEFINITIONS } from "./tools.js";
import type {
  AgentEffort,
  AgentMessage,
  AgentQueryOptions,
  AgentQueryRequest,
  AgentRuntime,
  AgentRuntimeTool,
  AgentSession,
} from "./types.js";

process.env.PI_CACHE_RETENTION ??= "long";

// Install the global undici dispatcher early so that all fetch() calls made by
// pi-ai (and transitively by the Anthropic SDK) reuse a shared connection pool.
installGlobalDispatcher();

const KNOWN_TOOL_NAMES = new Set([
  "Read",
  "Glob",
  "Grep",
  "Bash",
  "Write",
  "GetCallers",
  "GetCallees",
  "GetFunctionBody",
  "GoToDefinition",
  "FindReferences",
  "TypeAtPosition",
]);

const TRANSIENT_RETRY_MAX = 3;
const TRANSIENT_RETRY_BASE_MS = 5_000;

const TRANSIENT_STATUS_CODES = [500, 502, 503, 529, 429];
const TRANSIENT_NETWORK_TOKENS = [
  "ETIMEDOUT",
  "ECONNREFUSED",
  "ECONNRESET",
  "socket hang up",
  "fetch failed",
  "Request timed out",
];
const TRANSIENT_API_TOKENS = [
  "overloaded",
  "temporarily unavailable",
  "Service Temporarily Unavailable",
];
const log = getLogger("pi-ai");

/** Exported for testing. */
export function isTransientError(error: unknown): boolean {
  const message = toErrorMessage(error);
  for (const code of TRANSIENT_STATUS_CODES) {
    if (message.includes(String(code))) return true;
  }
  for (const token of TRANSIENT_NETWORK_TOKENS) {
    if (message.includes(token)) return true;
  }
  for (const token of TRANSIENT_API_TOKENS) {
    if (message.toLowerCase().includes(token.toLowerCase())) return true;
  }
  return false;
}

function isTransientErrorMessage(errorMessage: string): boolean {
  return isTransientError(new Error(errorMessage));
}

/** Check whether an error (thrown or soft) indicates a rate-limit (429) specifically. */
function isRateLimitError(error: unknown): boolean {
  const message = typeof error === "string" ? error : toErrorMessage(error);
  return message.includes("429");
}

/**
 * Recognize the "single request exceeded the model's input-context cap"
 * case — observed on Anthropic direct + Vertex proxied responses. Not
 * retryable: the request was too big the first time and will still be
 * too big on retry. Callers should surface a human-readable hint
 * instead of the raw 400.
 */
function isContextOverflowMessage(message: string): boolean {
  const lower = message.toLowerCase();
  return (
    lower.includes("prompt is too long") ||
    lower.includes("exceeds the context window") ||
    lower.includes("exceeds context length") ||
    lower.includes("greater than the context length") ||
    lower.includes("request_too_large")
  );
}

/**
 * Stream one LLM turn with rate-limit gating and transient-error retry.
 *
 * Generator-shaped so callers (`runTurnLoop`) can `yield*` events in
 * real time and still receive the final AssistantMessage via the
 * generator's return value. Without a generator, the outer turn loop
 * can't surface deltas during an in-flight await — JS can't yield from
 * a suspended awaitee — so a 20-second PASTA S4 Write would still look
 * like a silent spinner.
 *
 * Events yielded: `AssistantMessageEvent` (text deltas, tool-call deltas,
 * thinking deltas, terminal done/error).
 * Generator return: the final `PiAiAssistantMessage`.
 *
 * Retry semantics match the old retryTransient + rateLimitedComplete
 * combo: retry on thrown network-class errors with exponential backoff,
 * respect AbortSignal, release the concurrency slot exactly once per
 * attempt. Soft-error retry (stopReason === "error" with transient
 * message) is handled by the caller, not here, to preserve the old
 * separation of concerns.
 */
async function* streamLlmCall(
  modelSpec: string,
  model: Parameters<typeof stream>[0],
  context: PiAiContext,
  options: {
    signal?: AbortSignal;
    temperature?: number;
    maxTokens?: number;
    effort?: AgentEffort;
    thinkingDisabled?: boolean;
    maxRetries?: number;
    backoffMs?: number;
    observability?: { bus?: MessageBus; model?: string; runId?: string };
  },
): AsyncGenerator<AssistantMessageEvent, PiAiAssistantMessage> {
  const registry = getRateLimitRegistry();
  const maxRetries = options.maxRetries ?? TRANSIENT_RETRY_MAX;
  const backoffMs = options.backoffMs ?? TRANSIENT_RETRY_BASE_MS;
  const streamOptions = {
    signal: options.signal,
    temperature: options.temperature,
    maxTokens: options.maxTokens,
    ...buildReasoningOptions(options.effort, options.thinkingDisabled),
  };

  let lastError: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    await registry.acquire(modelSpec);
    let success = true;
    try {
      const events = stream(model, context, streamOptions);
      // Yield each event to the caller in real time. Once the stream
      // ends, await events.result() for the final AssistantMessage.
      for await (const event of events) {
        yield event;
      }
      const result = await events.result();
      if (
        result.stopReason === "error" &&
        result.errorMessage &&
        isRateLimitError(result.errorMessage)
      ) {
        success = false;
      }
      return result;
    } catch (error) {
      lastError = error;
      success = !isRateLimitError(error);
      const wrapped = error instanceof KuzushiError ? error : wrapError(error);
      if (!wrapped.retryable || attempt === maxRetries) {
        throw wrapped;
      }
      if (options.signal?.aborted) {
        throw wrapped;
      }
      const factor = wrapped.category === "rate_limit" ? 3 : 1;
      const delay = backoffMs * factor * 2 ** attempt;
      log.warn(
        `[pi-ai] ${wrapped.name} (attempt ${attempt + 1}/${maxRetries + 1}), retrying in ${delay / 1000}s: ${wrapped.message}`,
      );
      if (options.observability?.bus) {
        try {
          const retryRunId = options.observability.runId ?? "";
          await options.observability.bus.publish<LlmRetryEvent>({
            type: "llm:retry",
            meta: {
              id: crypto.randomUUID(),
              timestamp: new Date().toISOString(),
              runId: retryRunId,
            },
            payload: {
              model: options.observability.model ?? "unknown",
              attempt: attempt + 1,
              maxAttempts: maxRetries + 1,
              delayMs: delay,
              runId: retryRunId,
            },
          });
        } catch {
          // Non-fatal: observability emission should never break retry logic
        }
      }
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, delay);
        if (options.signal) {
          const onAbort = () => {
            clearTimeout(timer);
            resolve();
          };
          options.signal.addEventListener("abort", onAbort, { once: true });
        }
      });
      if (options.signal?.aborted) {
        throw wrapped;
      }
      // fallthrough: next attempt
    } finally {
      registry.release(modelSpec, success);
    }
  }
  throw wrapError(lastError);
}

/**
 * Translate one pi-ai AssistantMessageEvent into the AgentMessage delta
 * variant (if any) operators should see on the live-tail. Returns null
 * for bookkeeping events (`start`, `*_end`, `done`, `error`, etc.) so
 * consumers don't get flooded.
 */
function mapPiAiEventToAgentMessage(event: AssistantMessageEvent): AgentMessage | null {
  switch (event.type) {
    case "text_delta":
      return { type: "text-delta", delta: event.delta };
    case "thinking_delta":
      return { type: "thinking-delta", delta: event.delta };
    case "toolcall_start": {
      const block = event.partial.content[event.contentIndex];
      const toolName =
        block && block.type === "toolCall" && typeof block.name === "string" ? block.name : "tool";
      const toolUseId =
        block && block.type === "toolCall" && typeof block.id === "string" ? block.id : "";
      return { type: "tool-call-start", toolUseId, toolName };
    }
    case "toolcall_delta": {
      const block = event.partial.content[event.contentIndex];
      const toolUseId =
        block && block.type === "toolCall" && typeof block.id === "string" ? block.id : "";
      return { type: "tool-call-delta", toolUseId, delta: event.delta };
    }
    default:
      return null;
  }
}

// retryTransient was the pre-streaming retry wrapper for rateLimitedComplete.
// Both have been replaced by streamLlmCall (a generator that bakes retry
// + rate-limit + streaming into one). Removing retryTransient avoids a
// dead-code trap for future contributors who might wire it into a new
// non-streaming path and miss the streaming-first contract.

export class PiAiAgentRuntime implements AgentRuntime {
  readonly id = "pi-ai";
  private readonly runtimeConfig?: AgentRuntimeCredentials;
  /** Optional message bus for LLM observability events. */
  bus?: MessageBus;
  /** Optional run ID for correlating observability events. */
  runId?: string;

  constructor(runtimeConfig?: AgentRuntimeCredentials) {
    this.runtimeConfig = resolveAgentRuntimeConfig(runtimeConfig);
  }

  async *query(request: AgentQueryRequest): AsyncIterable<AgentMessage> {
    enforceAgentQuery({
      runtimeId: this.id,
      model: request.options.model,
      fallbackModel: request.options.fallbackModel,
      fallbackConsent: resolveFallbackConsent(request.options.consentToModelFallback),
      callsite: "pi-ai.query",
    });
    assertRuntimeModelSelection(request.options.model, request.options.fallbackModel);
    const restoreRuntimeEnv = applyRuntimeEnvOverrides(this.runtimeConfig);
    const startedAtMs = Date.now();
    const signal = request.options.abortController?.signal;
    const maxBudgetUsd = normalizeBudget(request.options.maxBudgetUsd);
    const outputFormat = request.options.outputFormat;

    try {
      const modelSpec = request.options.model;
      const model = resolveModel(modelSpec, this.runtimeConfig?.baseUrl);
      const enabledTools = resolveEnabledTools(
        request.options.allowedTools,
        request.options.disallowedTools,
        request.options.customTools,
      );
      const context: PiAiContext = {
        systemPrompt: buildSystemPrompt(
          outputFormat?.schema,
          request.options.systemPromptPrefix,
          enabledTools,
        ),
        messages: [
          ...mapHistoryToMessages(request.options.history),
          {
            role: "user",
            content: request.prompt,
            timestamp: Date.now(),
          },
        ],
        ...(enabledTools.length > 0 ? { tools: enabledTools } : {}),
      };
      const toolsByName = new Map(enabledTools.map((tool) => [tool.name, tool]));

      yield* runTurnLoop({
        context,
        modelSpec,
        model,
        options: request.options,
        enabledTools,
        toolsByName,
        signal,
        startedAtMs,
        outputFormat,
        maxBudgetUsd,
        bus: this.bus,
        runId: this.runId,
      });
    } finally {
      restoreRuntimeEnv();
    }
  }

  createSession(baseOptions: AgentQueryOptions): AgentSession {
    enforceAgentQuery({
      runtimeId: this.id,
      model: baseOptions.model,
      fallbackModel: baseOptions.fallbackModel,
      fallbackConsent: resolveFallbackConsent(baseOptions.consentToModelFallback),
      callsite: "pi-ai.session",
    });
    assertRuntimeModelSelection(baseOptions.model, baseOptions.fallbackModel);
    return new PiAiSession(this, this.runtimeConfig, baseOptions);
  }
}

interface RunTurnLoopArgs {
  context: PiAiContext;
  modelSpec: string;
  model: ReturnType<typeof resolveModel>;
  options: AgentQueryOptions;
  enabledTools: Tool[];
  toolsByName: Map<string, Tool>;
  signal: AbortSignal | undefined;
  startedAtMs: number;
  outputFormat: AgentQueryOptions["outputFormat"] | undefined;
  maxBudgetUsd: number | undefined;
  bus?: MessageBus;
  runId?: string;
}

/**
 * Core per-turn loop: repeatedly LLM-call + tool-exec until the assistant
 * stops emitting tool calls (or errors/aborts/exceeds budget). Extracted from
 * `PiAiAgentRuntime.query()` so both one-shot queries and long-lived sessions
 * (which reuse the same `context`) share identical retry, tool-dispatch, and
 * observability behaviour.
 *
 * The provided `context.messages` is mutated in place — caller decides whether
 * to allocate it fresh (query) or reuse it across turns (session).
 */
async function* runTurnLoop(args: RunTurnLoopArgs): AsyncIterable<AgentMessage> {
  const {
    context,
    modelSpec,
    model,
    options,
    enabledTools,
    toolsByName,
    signal,
    startedAtMs,
    outputFormat,
    maxBudgetUsd,
    bus,
    runId,
  } = args;
  const strictStructuredOutput = outputFormat?.strict === true;
  let invalidStructuredOutputRetriesRemaining = normalizeRetryCount(
    outputFormat?.retryInvalidStructuredOutput,
  );
  let totalCostUsd = 0;
  let generatedToolCallCounter = 0;
  const truncatedTextParts: string[] = [];
  // Per-tool validation-failure tracking across turns. When the LLM keeps
  // re-emitting the same bad tool call (e.g. {file_path} without content),
  // we bail the turn loop instead of burning tokens indefinitely.
  //
  // IMPORTANT: the counter for tool X is cleared ONLY when tool X itself
  // succeeds — not when any other tool succeeds. In the field, the
  // sub-agent often alternates a failing Write with many successful Reads
  // while it hunts for more context; a cross-tool reset would see count=1
  // indefinitely and the cap would never trip. Per-tool tracking isolates
  // "Write is stuck" from "Read is healthy".
  const MAX_VALIDATION_FAILURES_PER_TOOL = 3;
  const validationFailuresByTool = new Map<string, number>();

  try {
    for (let turn = 1; ; turn++) {
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

      const observability = { bus, model: options.model, runId };

      // Capture timing BEFORE the bus publish so llm:call-complete durationMs
      // is symmetric with llm:call-start.
      const turnStartMs = Date.now();

      // Emit llm:call-start for each turn's LLM call
      if (bus) {
        try {
          const turnRunId = runId ?? "";
          const promptLength = context.messages.reduce((len, m) => {
            const content = typeof m.content === "string" ? m.content : "";
            return len + content.length;
          }, 0);
          await bus.publish<LlmCallStartEvent>({
            type: "llm:call-start",
            meta: {
              id: crypto.randomUUID(),
              timestamp: new Date().toISOString(),
              runId: turnRunId,
            },
            payload: {
              model: options.model,
              promptLength,
              runId: turnRunId,
            },
          });
        } catch {
          // Non-fatal
        }
      }
      // Stream the LLM turn, fanning out per-event AgentMessage deltas
      // (`text-delta`, `tool-call-start`, `tool-call-delta`, ...) in real
      // time. The generator returns the final AssistantMessage via its
      // return value, which we capture with the two-step do-while/yield*
      // pattern below — `yield*` forwards the yielded events and binds
      // the return value on completion.
      const streamGen = streamLlmCall(modelSpec, model, context, {
        signal,
        temperature: options.temperature,
        maxTokens: options.maxOutputTokens,
        effort: options.effort,
        thinkingDisabled: options.thinkingDisabled,
        observability,
      });
      let assistant: PiAiAssistantMessage;
      {
        let next: IteratorResult<AssistantMessageEvent, PiAiAssistantMessage>;
        for (;;) {
          next = await streamGen.next();
          if (next.done) {
            assistant = next.value;
            break;
          }
          const mapped = mapPiAiEventToAgentMessage(next.value);
          if (mapped) {
            // Mirror the Claude runtime: when a tool call kicks off, surface
            // it as a `task:activity` line under the spinner and increment
            // the agents-active counter for the caller's fingerprint.
            if (mapped.type === "tool-call-start" && bus) {
              const toolName = mapped.toolName || "tool";
              publishTaskActivity(bus, options.taskId ?? "agent-runtime", `Calling ${toolName}…`, {
                runId: runId ?? undefined,
              });
              if (options.phase && options.fingerprint) {
                publishAgentActivity(bus, options.phase, options.fingerprint, "tool-start", {
                  toolName,
                });
              }
            }
            yield mapped;
          }
        }
      }

      // Handle transient soft errors (stopReason === "error" with transient message).
      // pi-ai's complete() never throws on API errors — it returns them as soft errors
      // (stopReason === "error"). We must retry by checking the return value.
      if (
        assistant.stopReason === "error" &&
        assistant.errorMessage &&
        isTransientErrorMessage(assistant.errorMessage)
      ) {
        let retried = false;
        for (let softRetry = 0; softRetry < TRANSIENT_RETRY_MAX; softRetry++) {
          if (signal?.aborted) break;
          const isRateLimit = /\b429\b|rate.?limit/i.test(assistant.errorMessage ?? "");
          const rateFactor = isRateLimit ? 3 : 1;
          const delay = TRANSIENT_RETRY_BASE_MS * rateFactor * 2 ** softRetry;
          log.warn(
            `[pi-ai] Transient soft error (attempt ${softRetry + 1}/${TRANSIENT_RETRY_MAX}), retrying in ${delay / 1000}s: ${assistant.errorMessage}`,
          );

          // Emit llm:retry for soft error retry
          if (bus) {
            try {
              const retryRunId = runId ?? "";
              await bus.publish<LlmRetryEvent>({
                type: "llm:retry",
                meta: {
                  id: crypto.randomUUID(),
                  timestamp: new Date().toISOString(),
                  runId: retryRunId,
                },
                payload: {
                  model: options.model,
                  attempt: softRetry + 1,
                  maxAttempts: TRANSIENT_RETRY_MAX,
                  delayMs: delay,
                  runId: retryRunId,
                },
              });
            } catch {
              // Non-fatal
            }
          }

          await new Promise<void>((resolve) => {
            const timer = setTimeout(resolve, delay);
            if (signal) {
              const onAbort = () => {
                clearTimeout(timer);
                resolve();
              };
              signal.addEventListener("abort", onAbort, { once: true });
            }
          });
          if (signal?.aborted) break;
          // Soft-error retry also streams — same generator/yield* plumbing
          // as the first attempt so operators see deltas during retries.
          const retryGen = streamLlmCall(modelSpec, model, context, {
            signal,
            temperature: options.temperature,
            maxTokens: options.maxOutputTokens,
            effort: options.effort,
            thinkingDisabled: options.thinkingDisabled,
            // Soft-retry loop manages its own attempt count; disable
            // streamLlmCall's internal network-retry so we don't double-retry.
            maxRetries: 0,
            observability,
          });
          for (;;) {
            const next = await retryGen.next();
            if (next.done) {
              assistant = next.value;
              break;
            }
            const mapped = mapPiAiEventToAgentMessage(next.value);
            if (mapped) yield mapped;
          }
          if (
            assistant.stopReason !== "error" ||
            !assistant.errorMessage ||
            !isTransientErrorMessage(assistant.errorMessage)
          ) {
            retried = true;
            break;
          }
        }
        if (!retried && assistant.stopReason === "error") {
          yield errorResult(
            "error_runtime",
            assistant.errorMessage ?? "pi-ai transient error retries exhausted",
            startedAtMs,
            turn,
            totalCostUsd,
          );
          return;
        }
      }

      context.messages.push(assistant);
      const turnCostUsd = extractCostUsd(assistant);
      totalCostUsd += turnCostUsd;

      // Context compaction: when `assistant.usage.input` crosses 75% of
      // the model's context window, compact old tool-result content in
      // place. Keeps many-turn agent runs (carlini-threat-hunt's 50-turn
      // free-exploration hunts especially) from hitting provider
      // `prompt is too long` 400s. See context-compactor.ts for the
      // rationale and knobs.
      const lastInputTokens = assistant.usage?.input ?? 0;
      const contextWindow = (model as { contextWindow?: number } | undefined)?.contextWindow ?? 0;
      if (contextWindow > 0 && lastInputTokens > 0) {
        const compactResult = maybeCompactContext(context, {
          contextWindow,
          lastInputTokens,
          turn,
        });
        if (compactResult.compacted) {
          log.info(
            `[pi-ai] compacted ${compactResult.compactedCount} tool-result(s), freed ~${compactResult.estimatedFreedTokens} input tokens (turn ${turn}, usage ${lastInputTokens}/${contextWindow})`,
          );
        }
      }

      // Emit llm:call-complete or llm:call-error for this turn
      if (bus) {
        const turnDurationMs = Date.now() - turnStartMs;
        const turnRunId = runId ?? "";
        try {
          if (assistant.stopReason === "error") {
            await bus.publish<LlmCallErrorEvent>({
              type: "llm:call-error",
              meta: {
                id: crypto.randomUUID(),
                timestamp: new Date().toISOString(),
                runId: turnRunId,
              },
              payload: {
                model: options.model,
                error: assistant.errorMessage ?? "pi-ai request failed",
                retryable: assistant.errorMessage
                  ? isTransientErrorMessage(assistant.errorMessage)
                  : false,
                runId: turnRunId,
              },
            });
          } else {
            const tokensUsed = (assistant.usage?.input ?? 0) + (assistant.usage?.output ?? 0);
            await bus.publish<LlmCallCompleteEvent>({
              type: "llm:call-complete",
              meta: {
                id: crypto.randomUUID(),
                timestamp: new Date().toISOString(),
                runId: turnRunId,
              },
              payload: {
                model: options.model,
                durationMs: turnDurationMs,
                tokensUsed,
                costUsd: turnCostUsd,
                runId: turnRunId,
              },
            });
          }
        } catch {
          // Non-fatal
        }
      }

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
        // Translate context-overflow 400s into a specific, actionable
        // error. The raw message looks like:
        //   `400 ... "prompt is too long: 1355012 tokens > 1000000 maximum"`
        // which tells the operator nothing about WHAT to tune. This
        // helper catches the known patterns and emits a hint pointing
        // to the two knobs that actually fix it (turn count, file
        // exploration scope).
        const rawErr = assistant.errorMessage ?? "pi-ai request failed";
        if (isContextOverflowMessage(rawErr)) {
          yield errorResult(
            "error_context_overflow",
            `Input-context cap exceeded (${rawErr.slice(0, 160)}). The agent's accumulated tool results exceeded the model's 1M-token input limit. Lower maxTurnsPerHunt, cap Read/Grep scope, or switch to a smaller context-heavy task (e.g. single-file targeted hunts). Raw provider error preserved above.`,
            startedAtMs,
            turn,
            totalCostUsd,
          );
          return;
        }
        yield errorResult("error_runtime", rawErr, startedAtMs, turn, totalCostUsd);
        return;
      }

      // Handle output truncation (hit max output tokens).
      // When expecting structured JSON output, accumulate the partial text
      // and signal the LLM to continue where it left off.
      if (assistant.stopReason === "length") {
        const hasToolCalls = assistant.content.some((block) => block.type === "toolCall");

        // Tool-call truncation path. The provider cut off the tool's
        // JSON argument mid-field, so `toolCall.arguments` is incomplete
        // (e.g. missing `content`). Feeding an incomplete call to AJV
        // produces a puzzling "missing required property" error and the
        // model retries the same oversized Write next turn. Short-circuit:
        // skip validation, feed back a clear corrective message, and emit
        // a `tool-result isError` per truncated call so the per-tool cap
        // still trips if the model can't shrink.
        if (hasToolCalls) {
          const truncatedToolCalls = assistant.content.filter(
            (block): block is PiAiToolCall => block.type === "toolCall",
          );
          for (const tc of truncatedToolCalls) {
            const tcId = tc.id || `${tc.name}_${Date.now()}_${++generatedToolCallCounter}`;
            const truncMsg = `Your "${tc.name}" tool call was truncated at the output-token limit before the arguments were complete. Retry with a smaller payload: for a large JSON artifact, Write a header first and Edit-append remaining sections, or reduce the content (fewer items, shorter descriptions).`;
            const activityMsg = `${tc.name} truncated at output limit`;
            log.warn(`[pi-ai] ${activityMsg} — asking model to split`);
            yield {
              type: "tool-summary",
              summary: activityMsg,
              precedingToolUseIds: [tcId],
            };
            yield {
              type: "tool-result",
              toolUseId: tcId,
              isError: true,
              content: truncMsg,
            };
            // Track under the per-tool cap so repeated truncations of
            // the same tool eventually bail the turn loop.
            const currentCount = (validationFailuresByTool.get(tc.name) ?? 0) + 1;
            validationFailuresByTool.set(tc.name, currentCount);
            if (currentCount >= MAX_VALIDATION_FAILURES_PER_TOOL) {
              log.warn(
                `[pi-ai] Tool "${tc.name}" truncated ${currentCount} times this turn; aborting.`,
              );
              yield errorResult(
                "error_tool_loop",
                `Tool "${tc.name}" truncated ${currentCount} times this turn; aborting. The tool's arguments exceed the model's output-token budget.`,
                startedAtMs,
                turn,
                totalCostUsd,
              );
              return;
            }
            context.messages.push({
              role: "toolResult",
              toolCallId: tcId,
              toolName: tc.name,
              content: [{ type: "text", text: truncMsg }],
              isError: true,
              timestamp: Date.now(),
            });
          }
          // Don't push the incomplete assistant message into context — the
          // toolResults above are enough to cue the LLM. Move to the next
          // turn so the model can retry with a smaller payload.
          continue;
        }

        if (!hasToolCalls && outputFormat) {
          truncatedTextParts.push(extractText(assistant));
          // Re-send with a continuation prompt so the LLM finishes its JSON.
          context.messages.push(assistant as unknown as PiAiContext["messages"][number]);
          context.messages.push({
            role: "user",
            content:
              "Your response was truncated due to length. Please continue your JSON output exactly where you left off. Do not restart — just continue from the cut-off point.",
            timestamp: Date.now(),
          });
          continue;
        }
      }

      const toolCalls = assistant.content.filter(
        (block): block is PiAiToolCall => block.type === "toolCall",
      );

      if (toolCalls.length === 0) {
        const currentText = extractText(assistant);
        const resultText =
          truncatedTextParts.length > 0 ? truncatedTextParts.join("") + currentText : currentText;
        const structuredResult = outputFormat
          ? parseStructuredOutput(resultText)
          : { structuredOutput: undefined, parseError: null };

        if (
          outputFormat &&
          strictStructuredOutput &&
          structuredResult.structuredOutput === undefined
        ) {
          if (invalidStructuredOutputRetriesRemaining > 0) {
            invalidStructuredOutputRetriesRemaining -= 1;
            context.messages.push({
              role: "user",
              content: buildStructuredOutputRetryMessage(outputFormat.schema),
              timestamp: Date.now(),
            });
            continue;
          }

          yield errorResult(
            "error_output_format",
            `pi-ai structured output parsing failed: ${structuredResult.parseError ?? "response did not contain valid JSON output"}`,
            startedAtMs,
            turn,
            totalCostUsd,
          );
          return;
        }

        yield {
          type: "result",
          subtype: "success",
          result: resultText,
          structuredOutput: structuredResult.structuredOutput,
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

      for (const toolCall of toolCalls) {
        const toolUseId =
          toolCall.id || `${toolCall.name}_${Date.now()}_${++generatedToolCallCounter}`;
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
            summary: summarizeToolResult(
              toolCall.name,
              toolCall.arguments as Record<string, unknown> | undefined,
              unknownToolMessage,
              true,
              elapsedSeconds,
            ),
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

        // Pre-validation alias normalization. Weaker models often emit
        // camelCase aliases (`filePath`, `oldString`, `newString`, `text`)
        // for tools whose schemas demand snake_case (`file_path`,
        // `old_string`, ...). Without this, AJV rejects every call and the
        // next turn sees the error, retries with the same wrong key, and
        // we loop for 20+ minutes on PASTA S4. normalizeToolInput returns
        // the same reference when no change is needed — cheap on hot path.
        const {
          input: normalizedArgs,
          changed,
          renames,
        } = normalizeToolInput(toolCall.name, toolCall.arguments);
        if (changed) {
          log.debug(`[pi-ai] normalized ${toolCall.name} input: ${renames.join(", ")}`);
          (toolCall as { arguments: unknown }).arguments = normalizedArgs;
        }

        let validatedArgs: Record<string, unknown>;
        try {
          validatedArgs = validateToolCall(enabledTools, toolCall) as Record<string, unknown>;
          // Clear THIS tool's failure counter only — leave other tools'
          // counters untouched so a stuck Write isn't forgiven by a
          // healthy interleaved Read.
          validationFailuresByTool.delete(toolCall.name);
        } catch (error) {
          const validationError = toErrorMessage(error);
          const elapsedSeconds = Math.max(0, (Date.now() - startedToolMs) / 1000);

          const currentCount = (validationFailuresByTool.get(toolCall.name) ?? 0) + 1;
          validationFailuresByTool.set(toolCall.name, currentCount);

          yield {
            type: "tool-progress",
            toolUseId,
            toolName: toolCall.name,
            elapsedSeconds,
          };
          yield {
            type: "tool-summary",
            summary: summarizeToolResult(
              toolCall.name,
              toolCall.arguments as Record<string, unknown> | undefined,
              validationError,
              true,
              elapsedSeconds,
            ),
            precedingToolUseIds: [toolUseId],
          };
          // Also surface on the structured tool-result stream so downstream
          // consumers (e.g. randori-runner's retry cap) can observe failures
          // directly rather than relying on the cosmetic tool-summary.
          yield {
            type: "tool-result",
            toolUseId,
            isError: true,
            content: validationError,
          };

          if (currentCount >= MAX_VALIDATION_FAILURES_PER_TOOL) {
            const truncated =
              validationError.length > 200 ? `${validationError.slice(0, 200)}…` : validationError;
            log.warn(
              `[pi-ai] Tool "${toolCall.name}" failed validation ${currentCount} times this turn; aborting.`,
            );
            yield errorResult(
              "error_tool_loop",
              `Tool "${toolCall.name}" failed validation ${currentCount} times this turn; aborting. Last error: ${truncated}`,
              startedAtMs,
              turn,
              totalCostUsd,
            );
            return;
          }

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
          options,
          toolCall.name,
          validatedArgs,
          signal,
          toolUseId,
        );

        if (permission.behavior === "deny") {
          const denyMessage = permission.message ?? `Permission denied for tool "${toolCall.name}"`;
          const elapsedSecondsDeny = Math.max(0, (Date.now() - startedToolMs) / 1000);
          yield {
            type: "tool-progress" as const,
            toolUseId,
            toolName: toolCall.name,
            elapsedSeconds: elapsedSecondsDeny,
          };
          yield {
            type: "tool-summary" as const,
            summary: summarizeToolResult(
              toolCall.name,
              validatedArgs,
              denyMessage,
              true,
              elapsedSecondsDeny,
            ),
            precedingToolUseIds: [toolUseId],
          };
          yield {
            type: "tool-result" as const,
            toolUseId,
            isError: true,
            content: denyMessage,
          };
          context.messages.push({
            role: "toolResult",
            toolCallId: toolUseId,
            toolName: toolCall.name,
            content: [{ type: "text", text: denyMessage }],
            isError: true,
            timestamp: Date.now(),
          });
          continue;
        }

        let isToolError = false;
        let toolResultText = "";
        try {
          const customTool = options.customTools?.find(
            (candidate) => candidate.name === toolCall.name,
          );
          toolResultText = customTool
            ? await customTool.execute(validatedArgs, {
                cwd: options.cwd,
                signal,
                toolUseId,
              })
            : await executeTool(toolCall.name, validatedArgs, options.cwd);
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
          summary: summarizeToolResult(
            toolCall.name,
            validatedArgs,
            toolResultText,
            isToolError,
            elapsedSeconds,
          ),
          precedingToolUseIds: [toolUseId],
        };
        yield {
          type: "tool-result",
          toolUseId,
          isError: isToolError,
          content: toolResultText,
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
  } catch (error) {
    const aborted = signal?.aborted === true;
    const wrapped = error instanceof KuzushiError ? error : wrapError(error);
    yield errorResult(
      aborted ? "error_aborted" : "error_runtime",
      wrapped.message,
      startedAtMs,
      0,
      totalCostUsd,
    );
  } finally {
    // Always clear the agents-active row when the loop unwinds — covers the
    // happy path (return inside the loop), error path, and consumer-side
    // generator close. Skip cleanly when no fingerprint/phase was set.
    if (bus && options.phase && options.fingerprint) {
      publishAgentActivity(bus, options.phase, options.fingerprint, "tool-complete", {
        done: true,
      });
    }
  }
}

/**
 * Long-lived pi-ai session: keeps the `PiAiContext` (systemPrompt, messages,
 * tools) alive across multiple `query()` calls so the shell can have a real
 * multi-turn conversation. The conversation runs in-process — pi-ai has no
 * subprocess — so there is nothing to dispose on close() besides aborting any
 * in-flight completion and restoring env-var overrides.
 */
class PiAiSession implements AgentSession {
  private readonly context: PiAiContext;
  private readonly modelSpec: string;
  private readonly model: ReturnType<typeof resolveModel>;
  private readonly enabledTools: Tool[];
  private readonly toolsByName: Map<string, Tool>;
  private readonly options: AgentQueryOptions;
  private readonly outputFormat: AgentQueryOptions["outputFormat"] | undefined;
  private readonly maxBudgetUsd: number | undefined;
  private readonly internalAbort = new AbortController();
  private readonly restoreRuntimeEnv: () => void;
  private closed = false;
  private inFlight = false;

  constructor(
    private readonly runtime: PiAiAgentRuntime,
    runtimeConfig: AgentRuntimeCredentials | undefined,
    baseOptions: AgentQueryOptions,
  ) {
    this.restoreRuntimeEnv = applyRuntimeEnvOverrides(runtimeConfig);
    this.options = baseOptions;
    this.modelSpec = baseOptions.model;
    this.model = resolveModel(baseOptions.model, runtimeConfig?.baseUrl);
    this.enabledTools = resolveEnabledTools(
      baseOptions.allowedTools,
      baseOptions.disallowedTools,
      baseOptions.customTools,
    );
    this.toolsByName = new Map(this.enabledTools.map((tool) => [tool.name, tool]));
    this.outputFormat = baseOptions.outputFormat;
    this.maxBudgetUsd = normalizeBudget(baseOptions.maxBudgetUsd);
    this.context = {
      systemPrompt: buildSystemPrompt(
        this.outputFormat?.schema,
        baseOptions.systemPromptPrefix,
        this.enabledTools,
      ),
      messages: [...mapHistoryToMessages(baseOptions.history)],
      ...(this.enabledTools.length > 0 ? { tools: this.enabledTools } : {}),
    };

    // Link caller-supplied abort to our internal controller so shell Ctrl+C
    // (which typically calls session.close()) and any externally-provided
    // signal both terminate in-flight completions.
    if (baseOptions.abortController) {
      const outerSignal = baseOptions.abortController.signal;
      if (outerSignal.aborted) {
        this.internalAbort.abort();
      } else {
        outerSignal.addEventListener("abort", () => this.internalAbort.abort(), { once: true });
      }
    }
  }

  async *query(prompt: string): AsyncIterable<AgentMessage> {
    if (this.closed) {
      throw new Error("pi-ai session is closed");
    }
    if (this.inFlight) {
      throw new Error("pi-ai session query already in flight");
    }
    this.inFlight = true;
    const startedAtMs = Date.now();
    this.context.messages.push({
      role: "user",
      content: prompt,
      timestamp: startedAtMs,
    });
    try {
      yield* runTurnLoop({
        context: this.context,
        modelSpec: this.modelSpec,
        model: this.model,
        options: this.options,
        enabledTools: this.enabledTools,
        toolsByName: this.toolsByName,
        signal: this.internalAbort.signal,
        startedAtMs,
        outputFormat: this.outputFormat,
        maxBudgetUsd: this.maxBudgetUsd,
        bus: this.runtime.bus,
        runId: this.runtime.runId,
      });
    } finally {
      this.inFlight = false;
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    if (!this.internalAbort.signal.aborted) {
      this.internalAbort.abort();
    }
    this.restoreRuntimeEnv();
  }
}

function applyRuntimeEnvOverrides(runtimeConfig: AgentRuntimeCredentials | undefined): () => void {
  const shouldOverrideApiKey = Boolean(runtimeConfig?.apiKey);
  const shouldOverrideAuthToken = Boolean(runtimeConfig?.authToken);
  const shouldOverrideBaseUrl = Boolean(runtimeConfig?.baseUrl);

  const originalApiKey = process.env["ANTHROPIC_API_KEY"];
  const originalAuthToken = process.env["ANTHROPIC_AUTH_TOKEN"];
  const originalOauthToken = process.env["ANTHROPIC_OAUTH_TOKEN"];
  const originalBaseUrl = process.env["ANTHROPIC_BASE_URL"];

  if (shouldOverrideApiKey && runtimeConfig?.apiKey) {
    process.env["ANTHROPIC_API_KEY"] = runtimeConfig.apiKey;
  }

  if (shouldOverrideAuthToken && runtimeConfig?.authToken) {
    process.env["ANTHROPIC_AUTH_TOKEN"] = runtimeConfig.authToken;
    process.env["ANTHROPIC_OAUTH_TOKEN"] = runtimeConfig.authToken;
  }

  if (shouldOverrideBaseUrl && runtimeConfig?.baseUrl) {
    process.env["ANTHROPIC_BASE_URL"] = runtimeConfig.baseUrl;
  }

  return () => {
    if (shouldOverrideApiKey) {
      if (originalApiKey === undefined) {
        delete process.env["ANTHROPIC_API_KEY"];
      } else {
        process.env["ANTHROPIC_API_KEY"] = originalApiKey;
      }
    }

    if (shouldOverrideAuthToken) {
      if (originalAuthToken === undefined) {
        delete process.env["ANTHROPIC_AUTH_TOKEN"];
      } else {
        process.env["ANTHROPIC_AUTH_TOKEN"] = originalAuthToken;
      }
      if (originalOauthToken === undefined) {
        delete process.env["ANTHROPIC_OAUTH_TOKEN"];
      } else {
        process.env["ANTHROPIC_OAUTH_TOKEN"] = originalOauthToken;
      }
    }

    if (shouldOverrideBaseUrl) {
      if (originalBaseUrl === undefined) {
        delete process.env["ANTHROPIC_BASE_URL"];
      } else {
        process.env["ANTHROPIC_BASE_URL"] = originalBaseUrl;
      }
    }
  };
}

function resolveModel(modelSpec: string, baseUrlOverride?: string) {
  const { provider, modelId } = parsePiAiModelSpec(modelSpec);
  const effectiveBaseUrl = baseUrlOverride ?? providerBaseUrlFromEnv(provider);

  try {
    const model = getModel(provider as KnownProvider, modelId as never);
    if (model) {
      if (effectiveBaseUrl) {
        (model as { baseUrl: string }).baseUrl = effectiveBaseUrl;
      }
      return model;
    }
  } catch {
    // Fall through to custom model construction below.
  }

  // Model not in pi-ai registry — construct a custom model object.
  // This supports Ollama and other OpenAI-compatible endpoints.
  if (!effectiveBaseUrl) {
    throw new Error(
      `Unable to resolve pi-ai model "${modelSpec}": model not found in registry. ` +
        "Provide agentRuntimeConfig.baseUrl (or --base-url) for custom model endpoints.",
    );
  }

  return {
    id: modelId,
    name: modelId,
    api: "openai-completions" as const,
    provider,
    baseUrl: effectiveBaseUrl,
    reasoning: false,
    input: ["text"] as ("text" | "image")[],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: 32768,
    maxTokens: 16384,
  };
}

function providerBaseUrlFromEnv(provider: string): string | undefined {
  const key =
    provider === "anthropic"
      ? "ANTHROPIC_BASE_URL"
      : provider === "openai"
        ? "OPENAI_BASE_URL"
        : undefined;
  const value = key ? process.env[key]?.trim() : undefined;
  return value || undefined;
}

function piAiThinkingLevel(
  effort: AgentEffort | undefined,
): "low" | "medium" | "high" | "xhigh" | undefined {
  if (effort === "max" || effort === "xhigh") return "xhigh";
  if (effort === "low" || effort === "medium" || effort === "high") return effort;
  return undefined;
}

function buildReasoningOptions(
  effort: AgentEffort | undefined,
  thinkingDisabled: boolean | undefined,
): Record<string, unknown> {
  if (thinkingDisabled || effort === "low") {
    return {
      thinkingEnabled: false,
      reasoningEffort: "minimal",
    };
  }

  const level = piAiThinkingLevel(effort);
  if (!level) return {};

  return {
    thinkingEnabled: true,
    thinkingDisplay: "summarized",
    effort: level,
    reasoning: level,
    reasoningEffort: level,
  };
}

function resolveEnabledTools(
  allowedTools: string[] | undefined,
  disallowedTools: string[] | undefined,
  customTools: AgentRuntimeTool[] | undefined,
): Tool[] {
  const allowSet = new Set<string>();
  const customToolNames = new Set((customTools ?? []).map((tool) => tool.name));
  if (Array.isArray(allowedTools)) {
    for (const toolName of allowedTools) {
      if (KNOWN_TOOL_NAMES.has(toolName) || customToolNames.has(toolName)) {
        allowSet.add(toolName);
      }
    }
  } else {
    for (const toolName of KNOWN_TOOL_NAMES) {
      allowSet.add(toolName);
    }
    for (const toolName of customToolNames) {
      allowSet.add(toolName);
    }
  }

  if (Array.isArray(disallowedTools)) {
    for (const toolName of disallowedTools) {
      allowSet.delete(toolName);
    }
  }

  return [
    ...PI_AI_TOOL_DEFINITIONS,
    ...(customTools ?? []).map(
      (tool) =>
        ({
          name: tool.name,
          description: tool.description,
          parameters: tool.parameters,
        }) as Tool,
    ),
  ].filter((tool): tool is Tool => allowSet.has(tool.name));
}

function buildStructuredOutputRetryMessage(schema: Record<string, unknown>): string {
  return [
    "Return JSON only matching schema; no prose/code fences.",
    "Schema:",
    JSON.stringify(schema),
  ].join("\n");
}

function buildSystemPrompt(
  schema: Record<string, unknown> | undefined,
  prefix?: string,
  enabledTools: Tool[] = PI_AI_TOOL_DEFINITIONS,
): string {
  const lines: string[] = [];
  const toolNames =
    enabledTools.length > 0 ? enabledTools.map((tool) => tool.name).join(", ") : "no tools";

  if (prefix) {
    lines.push(prefix, "");
  }

  lines.push(
    "You are a code security agent operating on a local repository.",
    `Use available tools (${toolNames}) when code inspection, retrieval, or file manipulation is required.`,
    "When you call tools, pass valid JSON arguments.",
  );

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

function mapAssistantContent(assistant: PiAiAssistantMessage): Array<Record<string, unknown>> {
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
    .filter(
      (block): block is Extract<PiAiAssistantMessage["content"][number], { type: "text" }> =>
        block.type === "text",
    )
    .map((block) => block.text.trim())
    .filter(Boolean);

  return textBlocks.join("\n\n");
}

function parseStructuredOutput(resultText: string): {
  structuredOutput: unknown | undefined;
  parseError: string | null;
} {
  const extracted = extractJsonObject(resultText);
  if (!extracted) {
    return {
      structuredOutput: undefined,
      parseError: "response was empty",
    };
  }

  try {
    return {
      structuredOutput: JSON.parse(extracted),
      parseError: null,
    };
  } catch (error) {
    return {
      structuredOutput: undefined,
      parseError: toErrorMessage(error),
    };
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

function normalizeBudget(value: number | undefined): number | undefined {
  if (!Number.isFinite(value) || value == null || value < 0) {
    return undefined;
  }

  return value;
}

function normalizeRetryCount(value: number | undefined): number {
  if (!Number.isFinite(value) || value == null || value < 0) {
    return 0;
  }

  return Math.floor(value);
}

function mapHistoryToMessages(
  history: AgentQueryRequest["options"]["history"],
): PiAiContext["messages"] {
  if (!Array.isArray(history) || history.length === 0) {
    return [];
  }

  return history.map((entry) => ({
    role: "user" as const,
    content: `${entry.role === "assistant" ? "Assistant" : "User"}:\n${entry.content}`,
    timestamp: Date.now(),
  }));
}

async function canUseTool(
  options: AgentQueryOptions,
  toolName: string,
  args: Record<string, unknown>,
  signal: AbortSignal | undefined,
  toolUseId: string,
) {
  if (!options.canUseTool) {
    return { behavior: "allow" } as const;
  }

  return options.canUseTool(toolName, args, {
    signal: signal ?? new AbortController().signal,
    toolUseId,
  });
}

function summarizeToolResult(
  toolName: string,
  toolInput: Record<string, unknown> | undefined,
  toolResult: string,
  isError: boolean,
  elapsedSeconds?: number,
): string {
  return summarizeToolCompletion(toolName, toolInput, toolResult, isError, { elapsedSeconds });
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

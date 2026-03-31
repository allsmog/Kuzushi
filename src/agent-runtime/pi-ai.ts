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
import {
  KuzushiError,
  wrapError,
} from "../errors.js";
import type { MessageBus } from "../bus/types.js";
import type {
  LlmCallStartEvent,
  LlmCallCompleteEvent,
  LlmCallErrorEvent,
  LlmRetryEvent,
} from "../bus/events.js";
import type { AgentRuntimeConfig } from "../types.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "../utils.js";
import { getRateLimitRegistry } from "../scheduler/index.js";
import { getLogger } from "../logger.js";
import { parsePiAiModelSpec } from "./model-spec.js";
import { executeTool, PI_AI_TOOL_DEFINITIONS } from "./tools.js";
import type { AgentMessage, AgentQueryRequest, AgentRuntime } from "./types.js";
import { installGlobalDispatcher } from "../http-agent.js";

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
 * Call `complete()` with rate-limit gating.
 *
 * Acquires a concurrency slot from the global `RateLimitRegistry` before
 * invoking the LLM, and releases it afterward with the appropriate
 * success/failure signal so adaptive concurrency can adjust.
 */
async function rateLimitedComplete(
  modelSpec: string,
  model: Parameters<typeof complete>[0],
  context: PiAiContext,
  options: { signal?: AbortSignal; temperature?: number; maxTokens?: number },
): Promise<PiAiAssistantMessage> {
  const registry = getRateLimitRegistry();
  // acquire() returns a safety-net release function, but we call
  // registry.release() explicitly so we can pass the success flag.
  // We intentionally ignore the returned function to avoid double-release.
  await registry.acquire(modelSpec);
  let success = true;

  try {
    const result = await complete(model, context, options);

    // Detect rate-limit soft errors returned by pi-ai.
    if (
      result.stopReason === "error"
      && result.errorMessage
      && isRateLimitError(result.errorMessage)
    ) {
      success = false;
    }

    return result;
  } catch (error) {
    success = !isRateLimitError(error);
    throw error;
  } finally {
    registry.release(modelSpec, success);
  }
}

async function retryTransient<T>(
  fn: () => Promise<T>,
  signal: AbortSignal | undefined,
  maxRetries = TRANSIENT_RETRY_MAX,
  backoffMs = TRANSIENT_RETRY_BASE_MS,
  observability?: { bus?: MessageBus; model?: string; runId?: string },
): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      // Wrap non-KuzushiError instances so callers always get typed errors.
      const wrapped = error instanceof KuzushiError
        ? error
        : wrapError(error);

      if (!wrapped.retryable || attempt === maxRetries) {
        throw wrapped;
      }
      if (signal?.aborted) {
        throw wrapped;
      }
      // Rate-limit errors get longer backoff.
      const factor = wrapped.category === "rate_limit" ? 3 : 1;
      const delay = backoffMs * factor * 2 ** attempt;
      log.warn(
        `[pi-ai] ${wrapped.name} (attempt ${attempt + 1}/${maxRetries + 1}), retrying in ${delay / 1000}s: ${wrapped.message}`,
      );

      // Emit llm:retry event
      if (observability?.bus) {
        try {
          const retryRunId = observability.runId ?? "";
          await observability.bus.publish<LlmRetryEvent>({
            type: "llm:retry",
            meta: {
              id: crypto.randomUUID(),
              timestamp: new Date().toISOString(),
              runId: retryRunId,
            },
            payload: {
              model: observability.model ?? "unknown",
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
        if (signal) {
          const onAbort = () => {
            clearTimeout(timer);
            resolve();
          };
          signal.addEventListener("abort", onAbort, { once: true });
        }
      });
      if (signal?.aborted) {
        throw wrapped;
      }
    }
  }
  throw wrapError(lastError);
}

export class PiAiAgentRuntime implements AgentRuntime {
  readonly id = "pi-ai";
  private readonly runtimeConfig?: AgentRuntimeConfig;
  /** Optional message bus for LLM observability events. */
  bus?: MessageBus;
  /** Optional run ID for correlating observability events. */
  runId?: string;

  constructor(runtimeConfig?: AgentRuntimeConfig) {
    this.runtimeConfig = runtimeConfig;
  }

  async *query(request: AgentQueryRequest): AsyncIterable<AgentMessage> {
    const restoreRuntimeEnv = applyRuntimeEnvOverrides(this.runtimeConfig);
    const startedAtMs = Date.now();
    const signal = request.options.abortController?.signal;
    const maxBudgetUsd = normalizeBudget(request.options.maxBudgetUsd);
    const outputFormat = request.options.outputFormat;
    const strictStructuredOutput = outputFormat?.strict === true;
    let invalidStructuredOutputRetriesRemaining = normalizeRetryCount(
      outputFormat?.retryInvalidStructuredOutput,
    );
    let totalCostUsd = 0;
    let generatedToolCallCounter = 0;
    const truncatedTextParts: string[] = [];

    try {
      const modelSpec = request.options.model;
      const model = resolveModel(modelSpec, this.runtimeConfig?.baseUrl);
      const enabledTools = resolveEnabledTools(
        request.options.allowedTools,
        request.options.disallowedTools,
      );
      const context: PiAiContext = {
        systemPrompt: buildSystemPrompt(outputFormat?.schema, request.options.systemPromptPrefix),
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

        const observability = { bus: this.bus, model: request.options.model, runId: this.runId };

        // Capture timing BEFORE the bus publish so llm:call-complete durationMs
        // is symmetric with llm:call-start.
        const turnStartMs = Date.now();

        // Emit llm:call-start for each turn's LLM call
        if (this.bus) {
          try {
            const turnRunId = this.runId ?? "";
            const promptLength = context.messages.reduce((len, m) => {
              const content = typeof m.content === "string" ? m.content : "";
              return len + content.length;
            }, 0);
            await this.bus.publish<LlmCallStartEvent>({
              type: "llm:call-start",
              meta: {
                id: crypto.randomUUID(),
                timestamp: new Date().toISOString(),
                runId: turnRunId,
              },
              payload: {
                model: request.options.model,
                promptLength,
                runId: turnRunId,
              },
            });
          } catch {
            // Non-fatal
          }
        }
        let assistant = await retryTransient(
          () => rateLimitedComplete(modelSpec, model, context, {
            signal,
            temperature: request.options.temperature,
            maxTokens: request.options.maxOutputTokens,
          }),
          signal,
          TRANSIENT_RETRY_MAX,
          TRANSIENT_RETRY_BASE_MS,
          observability,
        );

        // Handle transient soft errors (stopReason === "error" with transient message).
        // pi-ai's complete() never throws on API errors — it returns them as soft errors
        // (stopReason === "error"). We must retry by checking the return value.
        if (
          assistant.stopReason === "error"
          && assistant.errorMessage
          && isTransientErrorMessage(assistant.errorMessage)
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
            if (this.bus) {
              try {
                const retryRunId = this.runId ?? "";
                await this.bus.publish<LlmRetryEvent>({
                  type: "llm:retry",
                  meta: {
                    id: crypto.randomUUID(),
                    timestamp: new Date().toISOString(),
                    runId: retryRunId,
                  },
                  payload: {
                    model: request.options.model,
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
                const onAbort = () => { clearTimeout(timer); resolve(); };
                signal.addEventListener("abort", onAbort, { once: true });
              }
            });
            if (signal?.aborted) break;
            assistant = await rateLimitedComplete(modelSpec, model, context, {
              signal,
              temperature: request.options.temperature,
              maxTokens: request.options.maxOutputTokens,
            });
            if (assistant.stopReason !== "error" || !assistant.errorMessage || !isTransientErrorMessage(assistant.errorMessage)) {
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

        // Emit llm:call-complete or llm:call-error for this turn
        if (this.bus) {
          const turnDurationMs = Date.now() - turnStartMs;
          const turnRunId = this.runId ?? "";
          try {
            if (assistant.stopReason === "error") {
              await this.bus.publish<LlmCallErrorEvent>({
                type: "llm:call-error",
                meta: {
                  id: crypto.randomUUID(),
                  timestamp: new Date().toISOString(),
                  runId: turnRunId,
                },
                payload: {
                  model: request.options.model,
                  error: assistant.errorMessage ?? "pi-ai request failed",
                  retryable: assistant.errorMessage ? isTransientErrorMessage(assistant.errorMessage) : false,
                  runId: turnRunId,
                },
              });
            } else {
              const tokensUsed = (assistant.usage?.input ?? 0) + (assistant.usage?.output ?? 0);
              await this.bus.publish<LlmCallCompleteEvent>({
                type: "llm:call-complete",
                meta: {
                  id: crypto.randomUUID(),
                  timestamp: new Date().toISOString(),
                  runId: turnRunId,
                },
                payload: {
                  model: request.options.model,
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
          yield errorResult(
            "error_runtime",
            assistant.errorMessage ?? "pi-ai request failed",
            startedAtMs,
            turn,
            totalCostUsd,
          );
          return;
        }

        // Handle output truncation (hit max output tokens).
        // When expecting structured JSON output, accumulate the partial text
        // and signal the LLM to continue where it left off.
        if (assistant.stopReason === "length") {
          const hasToolCalls = assistant.content.some(
            (block) => block.type === "toolCall",
          );
          if (!hasToolCalls && outputFormat) {
            truncatedTextParts.push(extractText(assistant));
            // Re-send with a continuation prompt so the LLM finishes its JSON.
            context.messages.push(
              assistant as unknown as PiAiContext["messages"][number],
            );
            context.messages.push({
              role: "user",
              content: "Your response was truncated due to length. Please continue your JSON output exactly where you left off. Do not restart — just continue from the cut-off point.",
              timestamp: Date.now(),
            });
            continue;
          }
        }

        const toolCalls = assistant.content.filter((block): block is PiAiToolCall => (
          block.type === "toolCall"
        ));

        if (toolCalls.length === 0) {
          const currentText = extractText(assistant);
          const resultText = truncatedTextParts.length > 0
            ? truncatedTextParts.join("") + currentText
            : currentText;
          const structuredResult = outputFormat
            ? parseStructuredOutput(resultText)
            : { structuredOutput: undefined, parseError: null };

          if (outputFormat && strictStructuredOutput && structuredResult.structuredOutput === undefined) {
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
              summary: summarizeToolResult(toolCall.name, denyMessage, true),
              precedingToolUseIds: [toolUseId],
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
      restoreRuntimeEnv();
    }
  }
}

function applyRuntimeEnvOverrides(runtimeConfig: AgentRuntimeConfig | undefined): () => void {
  const shouldOverrideApiKey = Boolean(runtimeConfig?.apiKey);
  const shouldOverrideBaseUrl = Boolean(runtimeConfig?.baseUrl);

  const originalApiKey = process.env["ANTHROPIC_API_KEY"];
  const originalBaseUrl = process.env["ANTHROPIC_BASE_URL"];

  if (shouldOverrideApiKey && runtimeConfig?.apiKey) {
    process.env["ANTHROPIC_API_KEY"] = runtimeConfig.apiKey;
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

  try {
    const model = getModel(provider as KnownProvider, modelId as never);
    if (model) {
      if (baseUrlOverride) {
        (model as { baseUrl: string }).baseUrl = baseUrlOverride;
      }
      return model;
    }
  } catch {
    // Fall through to custom model construction below.
  }

  // Model not in pi-ai registry — construct a custom model object.
  // This supports Ollama and other OpenAI-compatible endpoints.
  if (!baseUrlOverride) {
    throw new Error(
      `Unable to resolve pi-ai model "${modelSpec}": model not found in registry. `
      + "Provide agentRuntimeConfig.baseUrl (or --base-url) for custom model endpoints.",
    );
  }

  return {
    id: modelId,
    name: modelId,
    api: "openai-completions" as const,
    provider,
    baseUrl: baseUrlOverride,
    reasoning: false,
    input: ["text"] as ("text" | "image")[],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: 32768,
    maxTokens: 16384,
  };
}

function resolveEnabledTools(
  allowedTools: string[] | undefined,
  disallowedTools: string[] | undefined,
): Tool[] {
  const allowSet = new Set<string>();
  if (Array.isArray(allowedTools)) {
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

function buildStructuredOutputRetryMessage(schema: Record<string, unknown>): string {
  return [
    "Return JSON only matching schema; no prose/code fences.",
    "Schema:",
    JSON.stringify(schema),
  ].join("\n");
}

function buildSystemPrompt(schema: Record<string, unknown> | undefined, prefix?: string): string {
  const lines: string[] = [];

  if (prefix) {
    lines.push(prefix, "");
  }

  lines.push(
    "You are a code security agent operating on a local repository.",
    "Use available tools (Read, Glob, Grep, Bash, Write, GetCallers, GetCallees, GetFunctionBody, GoToDefinition, FindReferences, TypeAtPosition) when code inspection or file manipulation is required.",
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

import Anthropic from "@anthropic-ai/sdk";
import {
  query as claudeQuery,
  type Options as ClaudeOptions,
  type SDKMessage,
  type SDKUserMessage,
} from "@anthropic-ai/claude-agent-sdk";
import type { AgentRuntimeConfig } from "../types.js";
import type { MessageBus } from "../bus/types.js";
import type {
  LlmCallStartEvent,
  LlmCallCompleteEvent,
  LlmCallErrorEvent,
} from "../bus/events.js";
import { normalizeCostUsd, toErrorMessage } from "../utils.js";
import { getLogger } from "../logger.js";
import type {
  AgentBatchRequest,
  AgentMessage,
  AgentQueryOptions,
  AgentQueryRequest,
  AgentRuntime,
  AgentSession,
} from "./types.js";
import type { AgentQueryExecutionResult } from "./execution.js";

const log = getLogger("claude-runtime");

// Prevent EPIPE from crashing the process when Claude SDK subprocesses die.
// Multiple concurrent query() calls each spawn a Claude Code subprocess;
// if one exits early the parent may write to a closed pipe.
for (const stream of [process.stdout, process.stderr]) {
  stream.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EPIPE" || err.code === "ERR_STREAM_DESTROYED") return;
    throw err;
  });
}

/**
 * Agent runtime backed by the Claude Agent SDK (@anthropic-ai/claude-agent-sdk).
 *
 * Benefits over pi-ai:
 * - Uses Claude Code's native tool implementations (Read, Grep, Glob, Bash, etc.)
 * - Prompt caching via Claude's API
 * - .claude configuration support
 * - Session persistence and resume
 */
// Semaphore to limit concurrent Claude Code subprocess spawns.
// Each query() spawns a subprocess; too many concurrent processes causes
// rapid "process exited with code 1" failures.
const MAX_CONCURRENT_QUERIES = 5;
let activeQueries = 0;
const waitQueue: Array<() => void> = [];

async function acquireSlot(): Promise<void> {
  if (activeQueries < MAX_CONCURRENT_QUERIES) {
    activeQueries++;
    return;
  }
  await new Promise<void>((resolve) => waitQueue.push(resolve));
  activeQueries++;
}

function releaseSlot(): void {
  activeQueries--;
  const next = waitQueue.shift();
  if (next) next();
}

export class ClaudeAgentRuntime implements AgentRuntime {
  readonly id = "claude";
  private readonly config: AgentRuntimeConfig | undefined;
  bus: MessageBus | null = null;
  runId: string | null = null;

  constructor(config?: AgentRuntimeConfig) {
    this.config = config;
  }

  createSession(baseOptions: AgentQueryOptions): AgentSession {
    return new ClaudeSession(baseOptions, this.config, this.bus, this.runId);
  }

  /**
   * Submit multiple tool-less prompts as a single Anthropic Batch API call.
   * 50% cost reduction, async processing. Polls until completion.
   */
  async queryBatch(
    requests: AgentBatchRequest[],
    baseOptions: AgentQueryOptions,
  ): Promise<Map<string, AgentQueryExecutionResult>> {
    if (requests.length === 0) return new Map();

    const apiKey = this.config?.apiKey ?? process.env["ANTHROPIC_API_KEY"];
    const baseURL = this.config?.baseUrl;
    const client = new Anthropic({ apiKey, baseURL });

    let model = baseOptions.model ?? "claude-sonnet-4-6";
    if (model.includes(":")) model = model.split(":").slice(1).join(":");
    const isHaiku = model.includes("haiku");

    const batchRequests = requests.map((req) => {
      const systemBlocks: Anthropic.TextBlockParam[] = [];
      const sysPrompt = req.systemPrompt ?? baseOptions.systemPromptPrefix;
      if (sysPrompt) {
        systemBlocks.push({
          type: "text" as const,
          text: sysPrompt,
          cache_control: { type: "ephemeral" as const, ttl: "1h" as const },
        });
      }

      // Build output_config — effort errors on Haiku, so skip it
      const outputConfig: Record<string, unknown> = {};
      if (baseOptions.outputFormat) {
        outputConfig.format = {
          type: "json_schema" as const,
          schema: baseOptions.outputFormat.schema,
        };
      }
      if (baseOptions.effort && !isHaiku) {
        outputConfig.effort = baseOptions.effort;
      }

      const params: Anthropic.MessageCreateParamsNonStreaming = {
        model,
        max_tokens: baseOptions.maxOutputTokens ?? 16000,
        temperature: baseOptions.temperature,
        system: systemBlocks.length > 0 ? systemBlocks : undefined,
        messages: [{ role: "user" as const, content: req.prompt }],
        stream: false,
        ...(Object.keys(outputConfig).length > 0 ? { output_config: outputConfig } : {}),
        ...(baseOptions.thinkingDisabled || (baseOptions.effort === "low" && !isHaiku)
          ? { thinking: { type: "disabled" as const } }
          : {}),
      };

      return { custom_id: req.id, params };
    });

    log.info(`Submitting batch of ${batchRequests.length} requests`);
    let batch = await client.messages.batches.create({ requests: batchRequests });
    log.info(`Batch ${batch.id} submitted, polling for completion`);

    const startMs = Date.now();
    const POLL_INTERVAL_MS = 2_000;
    const MAX_POLL_MS = 600_000; // 10 minutes

    while (batch.processing_status !== "ended") {
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
      batch = await client.messages.batches.retrieve(batch.id);
      if (Date.now() - startMs > MAX_POLL_MS) {
        await client.messages.batches.cancel(batch.id);
        throw new Error(`Batch ${batch.id} timed out after ${MAX_POLL_MS}ms`);
      }
    }

    const durationMs = Date.now() - startMs;
    log.info(`Batch ${batch.id} completed in ${durationMs}ms — succeeded: ${batch.request_counts.succeeded}, errored: ${batch.request_counts.errored}`);

    // Stream results
    const results = new Map<string, AgentQueryExecutionResult>();
    const decoder = await client.messages.batches.results(batch.id);

    // Model-aware pricing at batch rate (50% of standard)
    const inputRate = (isHaiku ? 1 : model.includes("opus") ? 5 : 3) * 0.5;
    const outputRate = (isHaiku ? 5 : model.includes("opus") ? 25 : 15) * 0.5;

    for await (const item of decoder) {
      if (item.result.type === "succeeded") {
        const msg = item.result.message;
        const textBlock = msg.content.find(
          (b): b is Anthropic.TextBlock => b.type === "text",
        );
        const usage = msg.usage;
        const inputCost = (usage.input_tokens / 1_000_000) * inputRate;
        const outputCost = (usage.output_tokens / 1_000_000) * outputRate;
        const cacheReadTokens = (usage as unknown as Record<string, unknown>)["cache_read_input_tokens"] as number ?? 0;
        const cacheSavings = (cacheReadTokens / 1_000_000) * (inputRate * 0.9);

        results.set(item.custom_id, {
          resultText: textBlock?.text ?? "",
          structuredOutput: (msg as unknown as Record<string, unknown>)["parsed_output"] ?? undefined,
          executionError: null,
          costUsd: normalizeCostUsd(inputCost + outputCost - cacheSavings),
        });
      } else {
        const errorMsg = item.result.type === "errored"
          ? JSON.stringify(item.result.error)
          : item.result.type;
        results.set(item.custom_id, {
          resultText: "",
          structuredOutput: undefined,
          executionError: errorMsg,
          costUsd: 0,
        });
      }
    }

    return results;
  }

  /**
   * Direct Anthropic API call for tool-less queries. Skips the Claude Code
   * subprocess entirely — no spawn overhead, no tool initialization.
   *
   * Best practices applied:
   * - Streaming with finalMessage() for large outputs (avoids HTTP timeouts)
   * - cache_control with 1h TTL for system prompt reuse across pipeline
   * - Typed error handling (RateLimitError, APIError)
   * - Effort not set on Haiku (would error)
   * - Right-sized max_tokens based on output needs
   */
  private async *queryDirect(request: AgentQueryRequest): AsyncIterable<AgentMessage> {
    const startedAtMs = Date.now();
    const turnRunId = this.runId ?? "";

    // Strip provider prefix
    let model = request.options.model ?? "claude-sonnet-4-6";
    if (model.includes(":")) model = model.split(":").slice(1).join(":");
    const isHaiku = model.includes("haiku");

    const apiKey = this.config?.apiKey ?? process.env["ANTHROPIC_API_KEY"];
    const baseURL = this.config?.baseUrl;
    const client = new Anthropic({ apiKey, baseURL });

    // Build system prompt with 1h cache TTL for pipeline-duration reuse
    const systemBlocks: Anthropic.TextBlockParam[] = [];
    if (request.options.systemPromptPrefix) {
      systemBlocks.push({
        type: "text",
        text: request.options.systemPromptPrefix,
        cache_control: { type: "ephemeral", ttl: "1h" },
      });
    }

    // Emit llm:call-start
    if (this.bus) {
      try {
        await this.bus.publish<LlmCallStartEvent>({
          type: "llm:call-start",
          meta: { id: crypto.randomUUID(), timestamp: new Date().toISOString(), runId: turnRunId },
          payload: { model, promptLength: request.prompt.length, runId: turnRunId },
        });
      } catch { /* non-fatal */ }
    }

    try {
      // Build output_config — effort errors on Haiku, so skip it
      const outputConfig: Record<string, unknown> = {};
      if (request.options.outputFormat) {
        outputConfig.format = {
          type: "json_schema" as const,
          schema: request.options.outputFormat.schema,
        };
      }
      if (request.options.effort && !isHaiku) {
        outputConfig.effort = request.options.effort;
      }

      // Right-size max_tokens: classification tasks need minimal output
      const maxTokens = request.options.maxOutputTokens ?? 16000;

      // Use streaming + finalMessage() to avoid HTTP timeouts on large outputs
      const stream = client.messages.stream({
        model,
        max_tokens: maxTokens,
        temperature: request.options.temperature,
        system: systemBlocks.length > 0 ? systemBlocks : undefined,
        messages: [{ role: "user", content: request.prompt }],
        ...(Object.keys(outputConfig).length > 0 ? { output_config: outputConfig } : {}),
        ...(request.options.thinkingDisabled || (request.options.effort === "low" && !isHaiku)
          ? { thinking: { type: "disabled" as const } }
          : {}),
      });

      const response = await stream.finalMessage();
      const durationMs = Date.now() - startedAtMs;

      // Extract cost from usage (model-aware pricing)
      const inputRate = isHaiku ? 1 : model.includes("opus") ? 5 : 3;
      const outputRate = isHaiku ? 5 : model.includes("opus") ? 25 : 15;
      const inputCost = (response.usage.input_tokens / 1_000_000) * inputRate;
      const outputCost = (response.usage.output_tokens / 1_000_000) * outputRate;
      const cacheReadTokens = (response.usage as unknown as Record<string, unknown>)["cache_read_input_tokens"] as number ?? 0;
      const cacheSavings = (cacheReadTokens / 1_000_000) * (inputRate * 0.9); // 90% savings on cached tokens
      const totalCostUsd = normalizeCostUsd(inputCost + outputCost - cacheSavings);

      // Extract text result
      const textBlock = response.content.find((b): b is Anthropic.TextBlock => b.type === "text");
      const resultText = textBlock?.text ?? "";

      // Emit llm:call-complete
      if (this.bus) {
        try {
          await this.bus.publish<LlmCallCompleteEvent>({
            type: "llm:call-complete",
            meta: { id: crypto.randomUUID(), timestamp: new Date().toISOString(), runId: turnRunId },
            payload: { model, durationMs, tokensUsed: response.usage.input_tokens + response.usage.output_tokens, costUsd: totalCostUsd, runId: turnRunId },
          });
        } catch { /* non-fatal */ }
      }

      yield {
        type: "result",
        subtype: "success",
        result: resultText,
        structuredOutput: (response as unknown as Record<string, unknown>)["parsed_output"] ?? undefined,
        durationMs,
        numTurns: 1,
        totalCostUsd,
      };
    } catch (error) {
      const durationMs = Date.now() - startedAtMs;
      const retryable = error instanceof Anthropic.RateLimitError
        || error instanceof Anthropic.InternalServerError;

      log.error(`Direct API query failed (${durationMs}ms, retryable=${retryable}): ${toErrorMessage(error)}`);

      if (this.bus) {
        try {
          await this.bus.publish<LlmCallErrorEvent>({
            type: "llm:call-error",
            meta: { id: crypto.randomUUID(), timestamp: new Date().toISOString(), runId: turnRunId },
            payload: { model, error: toErrorMessage(error), retryable, runId: turnRunId },
          });
        } catch { /* non-fatal */ }
      }

      yield {
        type: "result",
        subtype: "error_runtime",
        errors: [toErrorMessage(error)],
        durationMs,
        numTurns: 0,
        totalCostUsd: 0,
      };
    }
  }

  async *query(request: AgentQueryRequest): AsyncIterable<AgentMessage> {
    // Fast path: tool-less calls go directly to Anthropic API — no subprocess
    if (!request.options.allowedTools?.length && !request.options.disallowedTools?.length) {
      yield* this.queryDirect(request);
      return;
    }

    await acquireSlot();
    const startedAtMs = Date.now();
    let totalCostUsd = 0;
    let numTurns = 0;

    const options: ClaudeOptions = {
      cwd: request.options.cwd,
      permissionMode: mapPermissionMode(request.options.permissionMode),
      allowDangerouslySkipPermissions: true,
      persistSession: false,
    };

    // Model
    if (request.options.model) {
      // Strip provider prefix (e.g. "anthropic:claude-sonnet-4-6" -> "claude-sonnet-4-6")
      const model = request.options.model.includes(":")
        ? request.options.model.split(":").slice(1).join(":")
        : request.options.model;
      options.model = model;
    }

    // Tools — use `tools` to restrict available tools (not just auto-approve).
    // With bypassPermissions, `allowedTools` only auto-approves but doesn't
    // restrict availability. `tools` actually removes tools from the model's context.
    if (request.options.allowedTools) {
      options.tools = request.options.allowedTools;
    }
    if (request.options.disallowedTools) {
      options.disallowedTools = request.options.disallowedTools;
    }

    // Structured output — enforce JSON schema and add system prompt reinforcement.
    // The Claude SDK subprocess doesn't always enforce structured output when tools
    // are also active, so we add explicit instructions to the system prompt.
    if (request.options.outputFormat) {
      options.outputFormat = {
        type: "json_schema",
        schema: request.options.outputFormat.schema,
      };
      // Reinforce JSON-only output in the system prompt to prevent prose responses
      const jsonEnforcement = [
        "CRITICAL: You MUST return your final response as a valid JSON object matching the provided schema.",
        "Do NOT wrap the JSON in markdown code fences. Do NOT include any text before or after the JSON.",
        "After using tools to investigate, respond with ONLY the JSON result.",
      ].join(" ");
      const existingPrefix = request.options.systemPromptPrefix ?? "";
      request = {
        ...request,
        options: {
          ...request.options,
          systemPromptPrefix: existingPrefix
            ? `${jsonEnforcement}\n\n${existingPrefix}`
            : jsonEnforcement,
        },
      };
    }

    // Budget
    if (request.options.maxBudgetUsd) {
      options.maxBudgetUsd = request.options.maxBudgetUsd;
    }

    // System prompt — use Claude Code's default with appended instructions
    if (request.options.systemPromptPrefix) {
      options.systemPrompt = {
        type: "preset",
        preset: "claude_code",
        append: request.options.systemPromptPrefix,
      };
    }

    // API key / base URL from config — always pass env so subprocess
    // inherits credentials even when agentRuntimeConfig is not set.
    const env: Record<string, string | undefined> = { ...process.env };
    if (this.config?.apiKey) {
      env.ANTHROPIC_API_KEY = this.config.apiKey;
    }
    if (this.config?.baseUrl) {
      env.ANTHROPIC_BASE_URL = this.config.baseUrl;
    }
    // Claude Code refuses to launch inside another Claude Code session.
    // Strip the nesting detection variable so subprocesses can run.
    delete env.CLAUDECODE;
    delete env.CLAUDE_CODE_SESSION_ID;
    options.env = env;

    // Abort controller
    if (request.options.abortController) {
      options.abortController = request.options.abortController;
    }

    // Fallback model
    if (request.options.fallbackModel) {
      const fallback = request.options.fallbackModel.includes(":")
        ? request.options.fallbackModel.split(":").slice(1).join(":")
        : request.options.fallbackModel;
      options.fallbackModel = fallback;
    }

    // Effort level
    if (request.options.effort) {
      options.effort = request.options.effort;
    }

    // Thinking — disable only when explicitly requested or for low-effort classification
    if (request.options.thinkingDisabled || request.options.effort === "low") {
      options.thinking = { type: "disabled" };
    }

    // Emit llm:call-start
    const turnRunId = this.runId ?? "";
    if (this.bus) {
      try {
        await this.bus.publish<LlmCallStartEvent>({
          type: "llm:call-start",
          meta: {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            runId: turnRunId,
          },
          payload: {
            model: request.options.model,
            promptLength: request.prompt.length,
            runId: turnRunId,
          },
        });
      } catch {
        // Non-fatal
      }
    }

    try {
      const queryResult = claudeQuery({
        prompt: request.prompt,
        options,
      });

      for await (const message of queryResult) {
        const mapped = mapMessage(message);
        if (!mapped) continue;

        if (mapped.type === "result") {
          // Extract cost and metadata from SDK result
          const sdkMsg = message as Record<string, unknown>;
          totalCostUsd = normalizeCostUsd(sdkMsg["total_cost_usd"] as number | undefined);
          numTurns = (sdkMsg["num_turns"] as number) ?? 0;

          const durationMs = Date.now() - startedAtMs;

          if (mapped.subtype === "success") {
            yield {
              type: "result",
              subtype: "success",
              result: mapped.result,
              structuredOutput: (sdkMsg as Record<string, unknown>)["structured_output"],
              durationMs,
              numTurns,
              totalCostUsd,
            };
          } else {
            yield {
              type: "result",
              subtype: mapped.subtype,
              errors: mapped.errors,
              durationMs,
              numTurns,
              totalCostUsd,
            };
          }
        } else {
          yield mapped;
        }
      }

      // Emit llm:call-complete
      if (this.bus) {
        try {
          await this.bus.publish<LlmCallCompleteEvent>({
            type: "llm:call-complete",
            meta: {
              id: crypto.randomUUID(),
              timestamp: new Date().toISOString(),
              runId: turnRunId,
            },
            payload: {
              model: request.options.model,
              durationMs: Date.now() - startedAtMs,
              tokensUsed: 0,
              costUsd: totalCostUsd,
              runId: turnRunId,
            },
          });
        } catch {
          // Non-fatal
        }
      }
    } catch (error) {
      const durationMs = Date.now() - startedAtMs;
      log.error(`Claude SDK query failed (${durationMs}ms): ${toErrorMessage(error)}`);

      // Emit llm:call-error
      if (this.bus) {
        try {
          await this.bus.publish<LlmCallErrorEvent>({
            type: "llm:call-error",
            meta: {
              id: crypto.randomUUID(),
              timestamp: new Date().toISOString(),
              runId: turnRunId,
            },
            payload: {
              model: request.options.model,
              error: toErrorMessage(error),
              retryable: false,
              runId: turnRunId,
            },
          });
        } catch {
          // Non-fatal
        }
      }

      yield {
        type: "result",
        subtype: "error_runtime",
        errors: [toErrorMessage(error)],
        durationMs,
        numTurns,
        totalCostUsd,
      };
    } finally {
      releaseSlot();
    }
  }
}

/**
 * Async queue that implements AsyncIterable — used to feed SDKUserMessages
 * into a single `claudeQuery()` call. Push messages with `enqueue()`, end
 * with `done()`. The SDK subprocess stays alive as long as the iterable
 * hasn't completed.
 */
class MessageQueue implements AsyncIterable<SDKUserMessage>, AsyncIterator<SDKUserMessage> {
  private queue: SDKUserMessage[] = [];
  private resolve: ((result: IteratorResult<SDKUserMessage>) => void) | null = null;
  private isDone = false;

  enqueue(msg: SDKUserMessage): void {
    if (this.resolve) {
      const r = this.resolve;
      this.resolve = null;
      r({ done: false, value: msg });
    } else {
      this.queue.push(msg);
    }
  }

  done(): void {
    this.isDone = true;
    if (this.resolve) {
      const r = this.resolve;
      this.resolve = null;
      r({ done: true, value: undefined });
    }
  }

  next(): Promise<IteratorResult<SDKUserMessage>> {
    if (this.queue.length > 0) {
      return Promise.resolve({ done: false, value: this.queue.shift()! });
    }
    if (this.isDone) {
      return Promise.resolve({ done: true, value: undefined });
    }
    return new Promise((resolve) => { this.resolve = resolve; });
  }

  [Symbol.asyncIterator](): AsyncIterator<SDKUserMessage> { return this; }
}

/**
 * A session backed by a single Claude Code subprocess. Uses the SDK's
 * `query({ prompt: AsyncIterable<SDKUserMessage> })` to keep one process
 * alive across multiple turns. Each `query()` call pushes a user message
 * and yields response messages until a `result` arrives.
 */
class ClaudeSession implements AgentSession {
  private readonly messageQueue = new MessageQueue();
  private queryIterator: AsyncIterator<SDKMessage> | null = null;
  private closed = false;
  private slotAcquired = false;

  constructor(
    private readonly baseOptions: AgentQueryOptions,
    private readonly config: AgentRuntimeConfig | undefined,
    private readonly bus: MessageBus | null,
    private readonly runId: string | null,
  ) {}

  private ensureStarted(): void {
    if (this.queryIterator) return;

    const options: ClaudeOptions = {
      cwd: this.baseOptions.cwd,
      permissionMode: mapPermissionMode(this.baseOptions.permissionMode),
      allowDangerouslySkipPermissions: true,
      persistSession: false,
    };

    if (this.baseOptions.model) {
      const model = this.baseOptions.model.includes(":")
        ? this.baseOptions.model.split(":").slice(1).join(":")
        : this.baseOptions.model;
      options.model = model;
    }

    if (this.baseOptions.allowedTools) {
      options.allowedTools = this.baseOptions.allowedTools;
    }
    if (this.baseOptions.disallowedTools) {
      options.disallowedTools = this.baseOptions.disallowedTools;
    }

    if (this.baseOptions.outputFormat) {
      options.outputFormat = {
        type: "json_schema",
        schema: this.baseOptions.outputFormat.schema,
      };
    }

    if (this.baseOptions.maxBudgetUsd) {
      options.maxBudgetUsd = this.baseOptions.maxBudgetUsd;
    }

    if (this.baseOptions.systemPromptPrefix) {
      options.systemPrompt = {
        type: "preset",
        preset: "claude_code",
        append: this.baseOptions.systemPromptPrefix,
      };
    }

    // Fallback model
    if (this.baseOptions.fallbackModel) {
      const fallback = this.baseOptions.fallbackModel.includes(":")
        ? this.baseOptions.fallbackModel.split(":").slice(1).join(":")
        : this.baseOptions.fallbackModel;
      options.fallbackModel = fallback;
    }

    // Effort level
    if (this.baseOptions.effort) {
      options.effort = this.baseOptions.effort;
    }

    // Thinking — disable only when explicitly requested or for low-effort classification
    if (this.baseOptions.thinkingDisabled || this.baseOptions.effort === "low") {
      options.thinking = { type: "disabled" };
    }

    const env: Record<string, string | undefined> = { ...process.env };
    if (this.config?.apiKey) env.ANTHROPIC_API_KEY = this.config.apiKey;
    if (this.config?.baseUrl) env.ANTHROPIC_BASE_URL = this.config.baseUrl;
    delete env.CLAUDECODE;
    delete env.CLAUDE_CODE_SESSION_ID;
    options.env = env;

    if (this.baseOptions.abortController) {
      options.abortController = this.baseOptions.abortController;
    }

    // Pass the async message queue as prompt — SDK keeps one subprocess alive
    const queryResult = claudeQuery({
      prompt: this.messageQueue,
      options,
    });

    this.queryIterator = queryResult[Symbol.asyncIterator]();
  }

  async *query(prompt: string): AsyncIterable<AgentMessage> {
    if (this.closed) throw new Error("Session is closed");

    // Acquire semaphore on first query only
    if (!this.slotAcquired) {
      await acquireSlot();
      this.slotAcquired = true;
    }

    this.ensureStarted();

    // Push user message into the queue
    const userMessage: SDKUserMessage = {
      type: "user",
      session_id: "",
      message: { role: "user", content: [{ type: "text", text: prompt }] },
      parent_tool_use_id: null,
    };
    this.messageQueue.enqueue(userMessage);

    // Read messages from the subprocess until we get a result for this turn
    const iter = this.queryIterator!;
    while (true) {
      const { value, done } = await iter.next();
      if (done) return;

      const mapped = mapMessage(value);
      if (!mapped) continue;

      if (mapped.type === "result") {
        const sdkMsg = value as Record<string, unknown>;
        const totalCostUsd = normalizeCostUsd(sdkMsg["total_cost_usd"] as number | undefined);
        const numTurns = (sdkMsg["num_turns"] as number) ?? 0;

        if (mapped.subtype === "success") {
          yield {
            type: "result",
            subtype: "success",
            result: mapped.result,
            structuredOutput: sdkMsg["structured_output"],
            numTurns,
            totalCostUsd,
          };
        } else {
          yield {
            type: "result",
            subtype: mapped.subtype,
            errors: mapped.errors,
            numTurns,
            totalCostUsd,
          };
        }
        return; // Turn complete — caller can call query() again for next turn
      }

      yield mapped;
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.messageQueue.done();
    if (this.slotAcquired) {
      releaseSlot();
    }
  }
}

function mapPermissionMode(
  mode: string | undefined,
): "default" | "acceptEdits" | "bypassPermissions" | "plan" | "dontAsk" {
  switch (mode) {
    case "default":
    case "acceptEdits":
    case "plan":
      return mode;
    case "bypassPermissions":
    case "dontAsk":
      // For non-interactive automated use, "dontAsk" in Kuzushi maps to
      // "bypassPermissions" in the Claude SDK. The SDK's "dontAsk" denies
      // anything not pre-approved, which breaks automated tool execution.
      return "bypassPermissions";
    default:
      return "bypassPermissions";
  }
}

function mapMessage(msg: SDKMessage): AgentMessage | null {
  const type = (msg as Record<string, unknown>)["type"] as string;

  switch (type) {
    case "result": {
      const sdkMsg = msg as Record<string, unknown>;
      const subtype = sdkMsg["subtype"] as string;
      if (subtype === "success") {
        return {
          type: "result",
          subtype: "success",
          result: (sdkMsg["result"] as string) ?? "",
          structuredOutput: sdkMsg["structured_output"],
          totalCostUsd: normalizeCostUsd(sdkMsg["total_cost_usd"] as number | undefined),
        };
      }
      return {
        type: "result",
        subtype: subtype ?? "error_runtime",
        errors: Array.isArray(sdkMsg["errors"])
          ? (sdkMsg["errors"] as string[])
          : [String(sdkMsg["errors"] ?? "Unknown error")],
        totalCostUsd: normalizeCostUsd(sdkMsg["total_cost_usd"] as number | undefined),
      };
    }

    case "assistant": {
      const sdkMsg = msg as Record<string, unknown>;
      return {
        type: "assistant",
        content: Array.isArray(sdkMsg["content"]) ? sdkMsg["content"] : [],
      };
    }

    case "tool_use_progress": {
      const sdkMsg = msg as Record<string, unknown>;
      return {
        type: "tool-progress",
        toolUseId: String(sdkMsg["tool_use_id"] ?? ""),
        toolName: String(sdkMsg["tool_name"] ?? ""),
        elapsedSeconds: (sdkMsg["elapsed_seconds"] as number) ?? 0,
      };
    }

    case "tool_use_summary": {
      const sdkMsg = msg as Record<string, unknown>;
      return {
        type: "tool-summary",
        summary: String(sdkMsg["summary"] ?? ""),
        precedingToolUseIds: Array.isArray(sdkMsg["preceding_tool_use_ids"])
          ? sdkMsg["preceding_tool_use_ids"] as string[]
          : [],
      };
    }

    default:
      // Skip system messages, auth status, stream events, etc.
      return null;
  }
}

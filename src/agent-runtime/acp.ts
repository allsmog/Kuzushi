/**
 * ACP (Agent Client Protocol) runtime adapter.
 *
 * Communicates with an ACP-compatible agent process via JSON-RPC 2.0
 * over stdio (ndJSON stream).
 */

import { spawn, type ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";
import { randomUUID } from "node:crypto";
import { classifyError, isTransientError, calculateBackoff } from "./error-classification.js";
import { checkContextBudget, truncateToolResult, getModelContextWindow } from "./context-guards.js";
import type {
  AgentMessage,
  AgentQueryRequest,
  AgentRuntime,
} from "./types.js";
import type { AgentRuntimeConfig } from "../types.js";
import { getLogger } from "../logger.js";
import { normalizeCostUsd, toErrorMessage } from "../utils.js";

const SHUTDOWN_TIMEOUT_MS = 5_000;
const TRANSIENT_RETRY_MAX = 3;
const TRANSIENT_RETRY_BASE_MS = 5_000;
const log = getLogger("acp");

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: string;
  method: string;
  params: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

interface AcpPromptResult {
  content: Array<{ type: string; text?: string }>;
  stopReason?: string;
  usage?: { inputTokens?: number; outputTokens?: number };
  cost?: { total?: number };
}

export class AcpAgentRuntime implements AgentRuntime {
  readonly id = "acp";
  private process: ChildProcess | null = null;
  private readonly adapterCommand: string;
  private readonly runtimeConfig?: AgentRuntimeConfig;
  private pendingRequests = new Map<string, {
    resolve: (value: JsonRpcResponse) => void;
    reject: (error: Error) => void;
  }>();

  constructor(adapterCommand: string, runtimeConfig?: AgentRuntimeConfig) {
    this.adapterCommand = adapterCommand;
    this.runtimeConfig = runtimeConfig;
  }

  async *query(request: AgentQueryRequest): AsyncIterable<AgentMessage> {
    const startedAtMs = Date.now();
    const signal = request.options.abortController?.signal;
    let totalCostUsd = 0;
    const promptWithHistory = formatPromptWithHistory(
      request.options.history,
      request.prompt,
    );

    try {
      await this.ensureProcess();

      // Check context budget before sending
      const contextChars = (request.options.systemPromptPrefix?.length ?? 0) + request.prompt.length;
      const maxContextTokens = getModelContextWindow(request.options.model);
      const budget = checkContextBudget(contextChars, { maxContextTokens });
      if (!budget.ok) {
        yield {
          type: "result",
          subtype: "error_context_overflow",
          errors: [budget.warning ?? "Context budget exhausted"],
          durationMs: Date.now() - startedAtMs,
          numTurns: 0,
          totalCostUsd: 0,
        };
        return;
      }

      const maxTurns = request.options.maxTurns ?? 50;

      for (let turn = 1; turn <= maxTurns; turn++) {
        if (signal?.aborted) {
          yield {
            type: "result",
            subtype: "error_aborted",
            errors: ["ACP agent run aborted"],
            durationMs: Date.now() - startedAtMs,
            numTurns: turn - 1,
            totalCostUsd: normalizeCostUsd(totalCostUsd),
          };
          return;
        }

        let response: JsonRpcResponse;
        try {
          response = await this.sendWithRetry("prompt", {
            prompt: promptWithHistory,
            model: request.options.model,
            systemPrompt: request.options.systemPromptPrefix ?? "",
            maxTurns: 1,
            temperature: request.options.temperature,
            maxTokens: request.options.maxOutputTokens,
            allowedTools: request.options.allowedTools ?? [],
            outputFormat: request.options.outputFormat,
          }, signal);
        } catch (error) {
          yield {
            type: "result",
            subtype: "error_runtime",
            errors: [toErrorMessage(error)],
            durationMs: Date.now() - startedAtMs,
            numTurns: turn,
            totalCostUsd: normalizeCostUsd(totalCostUsd),
          };
          return;
        }

        if (response.error) {
          yield {
            type: "result",
            subtype: "error_runtime",
            errors: [response.error.message],
            durationMs: Date.now() - startedAtMs,
            numTurns: turn,
            totalCostUsd: normalizeCostUsd(totalCostUsd),
          };
          return;
        }

        const result = response.result as AcpPromptResult | undefined;
        if (!result) {
          yield {
            type: "result",
            subtype: "error_runtime",
            errors: ["ACP adapter returned empty result"],
            durationMs: Date.now() - startedAtMs,
            numTurns: turn,
            totalCostUsd: normalizeCostUsd(totalCostUsd),
          };
          return;
        }

        const turnCost = normalizeCostUsd(result.cost?.total);
        totalCostUsd += turnCost;

        // Map ACP content to assistant message
        const content = (result.content ?? []).map((block) => {
          if (block.type === "text") {
            return { type: "text", text: block.text ?? "" };
          }
          if (block.type === "tool_use") {
            return block;
          }
          return { type: "text", text: JSON.stringify(block) };
        });

        if (content.length > 0) {
          yield { type: "assistant", content } as AgentMessage;
        }

        // Check if this is a final response (no tool calls pending)
        const hasToolCalls = (result.content ?? []).some((b) => b.type === "tool_use");
        if (!hasToolCalls || result.stopReason === "end_turn") {
          const textParts = (result.content ?? [])
            .filter((b) => b.type === "text")
            .map((b) => b.text ?? "")
            .filter(Boolean);

          yield {
            type: "result",
            subtype: "success",
            result: textParts.join("\n\n"),
            durationMs: Date.now() - startedAtMs,
            numTurns: turn,
            totalCostUsd: normalizeCostUsd(totalCostUsd),
          };
          return;
        }
      }

      yield {
        type: "result",
        subtype: "error_max_turns",
        errors: [`ACP agent exceeded max turns (${maxTurns})`],
        durationMs: Date.now() - startedAtMs,
        numTurns: maxTurns,
        totalCostUsd: normalizeCostUsd(totalCostUsd),
      };
    } catch (error) {
      yield {
        type: "result",
        subtype: "error_runtime",
        errors: [toErrorMessage(error)],
        durationMs: Date.now() - startedAtMs,
        numTurns: 0,
        totalCostUsd: normalizeCostUsd(totalCostUsd),
      };
    }
  }

  private async ensureProcess(): Promise<void> {
    if (this.process && this.process.exitCode === null) {
      return;
    }

    const [cmd, ...args] = this.adapterCommand.split(/\s+/);
    const env: Record<string, string> = { ...process.env as Record<string, string> };
    if (this.runtimeConfig?.apiKey) {
      env["ANTHROPIC_API_KEY"] = this.runtimeConfig.apiKey;
    }
    if (this.runtimeConfig?.baseUrl) {
      env["ANTHROPIC_BASE_URL"] = this.runtimeConfig.baseUrl;
    }

    this.process = spawn(cmd, args, {
      stdio: ["pipe", "pipe", "pipe"],
      env,
    });

    this.process.on("error", (err) => {
      for (const [, pending] of this.pendingRequests) {
        pending.reject(err);
      }
      this.pendingRequests.clear();
    });

    this.process.on("exit", () => {
      for (const [, pending] of this.pendingRequests) {
        pending.reject(new Error("ACP adapter process exited unexpectedly"));
      }
      this.pendingRequests.clear();
    });

    // Read ndJSON responses from stdout
    if (this.process.stdout) {
      const rl = createInterface({ input: this.process.stdout });
      rl.on("line", (line) => {
        try {
          const response = JSON.parse(line) as JsonRpcResponse;
          const pending = this.pendingRequests.get(response.id);
          if (pending) {
            this.pendingRequests.delete(response.id);
            pending.resolve(response);
          }
        } catch {
          // Ignore malformed lines
        }
      });
    }
  }

  private async sendRequest(method: string, params: Record<string, unknown>): Promise<JsonRpcResponse> {
    if (!this.process?.stdin?.writable) {
      throw new Error("ACP adapter process is not available");
    }

    const id = randomUUID();
    const request: JsonRpcRequest = {
      jsonrpc: "2.0",
      id,
      method,
      params,
    };

    return new Promise<JsonRpcResponse>((resolve, reject) => {
      this.pendingRequests.set(id, { resolve, reject });
      this.process!.stdin!.write(JSON.stringify(request) + "\n", (err) => {
        if (err) {
          this.pendingRequests.delete(id);
          reject(err);
        }
      });
    });
  }

  private async sendWithRetry(
    method: string,
    params: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<JsonRpcResponse> {
    let lastError: unknown;

    for (let attempt = 0; attempt <= TRANSIENT_RETRY_MAX; attempt++) {
      try {
        return await this.sendRequest(method, params);
      } catch (error) {
        lastError = error;
        if (!isTransientError(error) || attempt === TRANSIENT_RETRY_MAX) {
          throw error;
        }
        if (signal?.aborted) throw error;

        const classified = classifyError(error);
        const delay = calculateBackoff(attempt, TRANSIENT_RETRY_BASE_MS, classified);
        log.warn(
          `[acp] ${classified.category} error (attempt ${attempt + 1}/${TRANSIENT_RETRY_MAX + 1}), retrying in ${delay / 1000}s`,
        );

        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, delay);
          if (signal) {
            const onAbort = () => { clearTimeout(timer); resolve(); };
            signal.addEventListener("abort", onAbort, { once: true });
          }
        });
        if (signal?.aborted) throw error;
      }
    }

    throw lastError;
  }

  async shutdown(): Promise<void> {
    if (!this.process || this.process.exitCode !== null) {
      return;
    }

    this.process.kill("SIGTERM");

    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        if (this.process && this.process.exitCode === null) {
          this.process.kill("SIGKILL");
        }
        resolve();
      }, SHUTDOWN_TIMEOUT_MS);

      this.process!.on("exit", () => {
        clearTimeout(timer);
        resolve();
      });
    });

    this.process = null;
    this.pendingRequests.clear();
  }
}

function formatPromptWithHistory(
  history: AgentQueryRequest["options"]["history"],
  prompt: string,
): string {
  if (!Array.isArray(history) || history.length === 0) {
    return prompt;
  }

  const transcript = history
    .map((entry) => `${entry.role === "assistant" ? "Assistant" : "User"}:\n${entry.content}`)
    .join("\n\n");

  return [
    "Prior conversation context:",
    transcript,
    "",
    "Current request:",
    prompt,
  ].join("\n");
}

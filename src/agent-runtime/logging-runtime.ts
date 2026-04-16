import { getLogger } from "../logger.js";
import type {
  AgentBatchRequest,
  AgentMessage,
  AgentQueryOptions,
  AgentQueryRequest,
  AgentRuntime,
  AgentSession,
} from "./types.js";

const log = getLogger("agent");

/**
 * Transparent decorator that logs every prompt sent and every message received
 * from an underlying {@link AgentRuntime}. Covers all 40+ call sites without
 * touching individual task files.
 */
export class LoggingAgentRuntime implements AgentRuntime {
  readonly id: string;
  private inner: AgentRuntime;

  constructor(inner: AgentRuntime) {
    this.inner = inner;
    this.id = inner.id;
  }

  async *query(request: AgentQueryRequest): AsyncIterable<AgentMessage> {
    const { prompt, options } = request;
    const lines = prompt.split("\n");
    const preview = lines.slice(0, 5).join("\n");
    const suffix = lines.length > 5 ? `\n  ... (${lines.length} lines total)` : "";

    log.info(`Prompt -> ${options.model} (${lines.length} lines):\n${preview}${suffix}`);
    log.debug(`Full prompt:\n${prompt}`);

    for await (const message of this.inner.query(request)) {
      logMessage(message);
      yield message;
    }
  }

  createSession?(baseOptions: AgentQueryOptions): AgentSession {
    const innerSession = this.inner.createSession?.(baseOptions);
    if (!innerSession) return undefined as unknown as AgentSession;

    const origQuery = innerSession.query.bind(innerSession);
    return {
      async *query(prompt: string): AsyncIterable<AgentMessage> {
        const lines = prompt.split("\n");
        const preview = lines.slice(0, 5).join("\n");
        const suffix = lines.length > 5 ? `\n  ... (${lines.length} lines total)` : "";

        log.info(`Session prompt (${lines.length} lines):\n${preview}${suffix}`);
        log.debug(`Full session prompt:\n${prompt}`);

        for await (const msg of origQuery(prompt)) {
          logMessage(msg);
          yield msg;
        }
      },
      close: () => innerSession.close(),
    };
  }

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
  > {
    if (!this.inner.queryBatch) return undefined as never;
    log.info(`Batch request: ${requests.length} prompts -> ${baseOptions.model}`);
    return this.inner.queryBatch(requests, baseOptions);
  }
}

function logMessage(message: AgentMessage): void {
  switch (message.type) {
    case "tool-progress":
      log.info(`  [${Math.round(message.elapsedSeconds)}s] Tool: ${message.toolName}`);
      break;

    case "tool-summary":
      log.info(`  ${message.summary}`);
      break;

    case "assistant": {
      const toolUses = message.content
        .filter((b) => b["type"] === "tool_use")
        .map((b) => b["name"]);
      if (toolUses.length > 0) {
        log.info(`  Using tools: ${toolUses.join(", ")}`);
      }
      const textBlocks = message.content
        .filter((b) => b["type"] === "text")
        .map((b) => String(b["text"] ?? ""));
      for (const text of textBlocks) {
        if (text.length > 0) {
          const truncated = text.length > 200 ? `${text.slice(0, 200)}...` : text;
          log.info(`  ${truncated}`);
        }
      }
      break;
    }

    case "result":
      if ("result" in message && message.subtype === "success") {
        const dur = message.durationMs ? `${(message.durationMs / 1000).toFixed(1)}s` : "?";
        log.info(
          `  Result: ${dur}, ${message.numTurns ?? "?"} turns, $${message.totalCostUsd?.toFixed(4) ?? "?"}`,
        );
      } else if ("errors" in message) {
        log.info(
          `  Error: ${message.subtype} — ${(message as { errors: string[] }).errors.join("; ")}`,
        );
      }
      break;
  }
}

import { assertRuntimeModelCompatible } from "../../agent-runtime/model-validation.js";
import type {
  AgentMessage,
  AgentQueryOptions,
  AgentRuntime,
  AgentRuntimeTool,
} from "../../agent-runtime/types.js";
import type { TaintIrisNextAgentStatus } from "./types.js";

export interface IrisAgentQueryAdapterResult {
  resultText: string;
  structuredOutput: unknown;
  costUsd: number;
  runtimeErrors: string[];
  messageCount: number;
  aborted: boolean;
}

export async function queryIrisAgentOnce(options: {
  runtime: AgentRuntime;
  prompt: string;
  cwd: string;
  model: string;
  allowedTools: string[];
  customTools: AgentRuntimeTool[];
  abortController: AbortController;
  taskId: string;
  fingerprint: string;
  maxBudgetUsd?: number;
  outputFormat: AgentQueryOptions["outputFormat"];
  signal?: AbortSignal;
  forwardActivity?: (message: AgentMessage) => void;
}): Promise<IrisAgentQueryAdapterResult> {
  assertRuntimeModelCompatible(options.model);
  let structuredOutput: unknown;
  let resultText = "";
  let streamedText = "";
  let costUsd = 0;
  let messageCount = 0;
  const runtimeErrors: string[] = [];

  const queryOptions: AgentQueryOptions = {
    cwd: options.cwd,
    model: options.model,
    allowedTools: options.allowedTools,
    customTools: options.customTools,
    permissionMode: "dontAsk",
    abortController: options.abortController,
    taskId: options.taskId,
    fingerprint: options.fingerprint,
    phase: "scan",
    outputFormat: options.outputFormat,
    ...(options.maxBudgetUsd !== undefined ? { maxBudgetUsd: options.maxBudgetUsd } : {}),
  };

  for await (const message of options.runtime.query({
    prompt: options.prompt,
    options: queryOptions,
  })) {
    messageCount += 1;
    if (options.signal?.aborted) break;
    options.forwardActivity?.(message);

    if (message.type === "text-delta" || message.type === "thinking-delta") {
      streamedText += message.delta;
      continue;
    }
    if (message.type === "assistant") {
      streamedText += assistantText(message);
      continue;
    }
    if (message.type !== "result") continue;

    if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
      costUsd = message.totalCostUsd;
    }
    if (message.subtype === "success" && "result" in message) {
      resultText = message.result || streamedText;
      structuredOutput = message.structuredOutput;
    } else if ("errors" in message) {
      runtimeErrors.push(...message.errors);
      if (!resultText) resultText = streamedText || message.errors.join("\n");
    }
  }

  return {
    resultText: resultText || streamedText,
    structuredOutput,
    costUsd,
    runtimeErrors,
    messageCount,
    aborted: options.signal?.aborted === true || options.abortController.signal.aborted,
  };
}

export function resolveIrisAgentStatus(options: {
  structuredOutputValid: boolean;
  retryCount: number;
  selectedCweCount: number;
  findingCount: number;
  reviewCandidateCount: number;
}): TaintIrisNextAgentStatus {
  if (!options.structuredOutputValid) return "invalid-json";
  if (
    options.reviewCandidateCount > 0 &&
    options.selectedCweCount > 0 &&
    options.findingCount > 0
  ) {
    return "no-selection-fallback";
  }
  if (options.selectedCweCount === 0 && options.findingCount === 0) return "no-selection";
  return options.retryCount > 0 ? "repaired-json" : "valid-json";
}

function assistantText(message: Extract<AgentMessage, { type: "assistant" }>): string {
  let text = "";
  for (const block of message.content) {
    if (typeof block["text"] === "string") text += block["text"];
  }
  return text;
}

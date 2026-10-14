#!/usr/bin/env node
import process from "node:process";
import { HumanMessage, ToolMessage } from "@langchain/core/messages";
import { END, MessagesAnnotation, START, StateGraph } from "@langchain/langgraph";
import { debugDumpBridgeCall } from "./langgraph-bridge/diagnostics.mjs";
import { bridgeErrorResponse } from "./langgraph-bridge/errors.mjs";
import { fileToolsForRequest } from "./langgraph-bridge/file-tools.mjs";
import {
  isMcpToolTimeoutError,
  mcpToolsForRequest,
  normalizeMcpToolError,
  withMcpClientCleanup,
} from "./langgraph-bridge/mcp.mjs";
import {
  appendStructuredOutputContract,
  bridgeQueryResult,
  humanMessageForRequest,
  interruptedQueryResult,
  isAiMessage,
  loopOpeningMessageForRequest,
  maybeParseJson,
  messageText,
  modelContinuationDecision,
  modelForRequest,
  parseModelSpec,
  systemMessageForRequest,
  toolMessageForOutput,
  turnBudgetNotice,
  usageFromMessage,
} from "./langgraph-bridge/model.mjs";
import { messagesForNextStep } from "./langgraph-bridge/next-step-messages.mjs";
import { parseOauthLoginArgs, runOauthLogin } from "./langgraph-bridge/oauth-login.mjs";
import { writeBridgePayload, writeBridgeResponseAndExit } from "./langgraph-bridge/process-exit.mjs";
import { openProviderAdmission, readBridgeRequest, withProviderAdmission } from "./langgraph-bridge/provider-admission.mjs";
import { invokeWithResponseText, responseStreamFor } from "./langgraph-bridge/response-stream.mjs";
import { bridgeToolsForNextStep, validateBridgeRequest } from "./langgraph-bridge/schema.mjs";
import {
  acknowledgeToolPolicy,
  authorizeExecutingQuery,
} from "./langgraph-bridge/tool-policy-handshake.mjs";

// Agentic tool loops need room beyond langgraph's default recursion limit
// of 25: one model step plus one tool step per hop halves the effective
// tool budget, and evidence-gathering verbs (verify:finding) routinely
// need >12 tool hops on large targets.
const QUERY_GRAPH_RECURSION_LIMIT = 64;

async function runQueryGraph(request) {
  const mcp = await mcpToolsForRequest(request);
  return withMcpClientCleanup(async () => {
    const system = querySystemPromptForRequest(request);
    const tools = [...fileToolsForRequest(request), ...mcp.tools];
    const mcpToolNames = new Set(mcp.tools.map((tool) => tool.name));
    const progress = { messages: [] };
    const graph = queryGraphForRequest(request, tools, mcpToolNames, system, progress);
    try {
      const completion = await runQueryGraphToConclusion(graph, request, system, progress);
      const { messages } = completion;
      const message = messages.at(-1);
      debugDumpBridgeCall("query", request, tools, system, message, messages);
      return queryResultFromMessages(messages, request, completion.stopReason);
    } catch (error) {
      if (!isMcpToolTimeoutError(error)) throw error;
      const message = progress.messages.at(-1);
      debugDumpBridgeCall("query", request, tools, system, message, progress.messages);
      return interruptedQueryResult(progress.messages, "mcp_tool_timeout");
    }
  }, mcp.close);
}

// When an evidence-gathering loop exhausts its tool budget, a verdict from
// the evidence already collected beats an opaque failure: force one final
// tool-free model turn so the caller always receives the structured output,
// with the model's confidence reflecting the incomplete investigation.
const FORCED_CONCLUSION_PROMPT =
  "Your tool budget is exhausted — no further tool calls are possible. " +
  "Produce your final structured answer now from the evidence you have " +
  "already gathered, lowering your stated confidence to reflect anything " +
  "you could not confirm.";

async function runQueryGraphToConclusion(graph, request, system, progress) {
  const state = { messages: [loopOpeningMessageForRequest(request)] };
  try {
    const result = await graph.invoke(state, {
      recursionLimit: QUERY_GRAPH_RECURSION_LIMIT,
    });
    return { messages: result.messages };
  } catch (error) {
    if (error?.name !== "GraphRecursionError") throw error;
    const conclusion = await forcedConclusion(request, system, progress);
    return {
      messages: [...progress.messages, conclusion],
      stopReason: "forced_conclusion",
    };
  }
}

async function forcedConclusion(request, system, progress) {
  const model = modelForRequest(request);
  return invokeThroughQuotaWindows(model, [
    systemMessageForRequest(request, system),
    humanMessageForRequest(request),
    ...concludedEvidenceMessages(progress),
    new HumanMessage(FORCED_CONCLUSION_PROMPT),
  ], request);
}

// The evidence transcript minus the leading prompt, trimmed of a trailing
// assistant turn whose tool calls never received results — the provider
// rejects tool_use blocks without matching tool_result blocks.
function concludedEvidenceMessages(progress) {
  const evidence = progress.messages.slice(1);
  const last = evidence.at(-1);
  if (isAiMessage(last) && last.tool_calls?.length) evidence.pop();
  return evidence;
}

function queryGraphForRequest(request, tools, mcpToolNames, system, progress) {
  const model = modelForRequest(request);
  const boundModel = tools.length ? model.bindTools(tools) : model;
  return new StateGraph(MessagesAnnotation)
    .addNode("model", callModelNode(boundModel, request, system, progress))
    .addNode("tools", runToolsNode(tools, mcpToolNames, progress))
    .addEdge(START, "model")
    .addConditionalEdges("model", shouldContinueForRequest(request))
    .addEdge("tools", "model")
    .compile();
}

function querySystemPromptForRequest(request) {
  return appendStructuredOutputContract(
    request.systemPrompt ?? request.system_prompt,
    request.structuredOutput ?? request.structured_output,
  );
}

// The SDK's built-in retries back off for seconds, but Vertex burst quotas
// are per-minute windows: an agent loop whose context has grown past the
// per-minute token quota sees every fast retry fail. Waiting out the window
// (honoring retry-after when the provider states one) lets the run finish
// instead of dying mid-loop.
const QUOTA_WINDOW_RETRIES = 3;
const QUOTA_WINDOW_WAIT_MS = 65_000;

function callModelNode(model, request, system, progress) {
  return async (state) => {
    const notice = turnBudgetNotice(state.messages, requestMaxModelTurns(request));
    const response = await invokeThroughQuotaWindows(model, [
      systemMessageForRequest(request, system),
      ...state.messages,
      ...(notice ? [notice] : []),
    ], request);
    progress.messages = [...state.messages, response];
    return { messages: [response] };
  };
}

async function invokeThroughQuotaWindows(model, messages, request) {
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await withProviderAdmission(request, () => invokeWithResponseText(model, messages, request), usageFromMessage);
    } catch (error) {
      if (attempt >= QUOTA_WINDOW_RETRIES || !isRateLimitError(error)) throw error;
      await sleep(quotaWaitMs(error));
    }
  }
}

function isRateLimitError(error) {
  const status = error?.status ?? error?.statusCode ?? error?.response?.status;
  return Number(status) === 429;
}

function quotaWaitMs(error) {
  const headers = error?.headers ?? error?.response?.headers;
  const raw = typeof headers?.get === "function" ? headers.get("retry-after") : headers?.["retry-after"];
  const seconds = Number(typeof raw === "string" ? raw.trim() : raw);
  if (Number.isInteger(seconds) && seconds > 0) return Math.min(seconds, 300) * 1000;
  return QUOTA_WINDOW_WAIT_MS;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function runToolsNode(tools, mcpToolNames, progress) {
  const byName = Object.fromEntries(tools.map((tool) => [tool.name, tool]));
  return async (state) => {
    const results = await runRequestedTools(state.messages.at(-1), byName, mcpToolNames);
    progress.messages = [...state.messages, ...results];
    return { messages: results };
  };
}

async function runRequestedTools(message, toolsByName, mcpToolNames) {
  if (!isAiMessage(message) || !message.tool_calls?.length) return [];
  const results = [];
  for (const call of message.tool_calls) {
    results.push(await runOneTool(call, toolsByName[call.name], mcpToolNames.has(call.name)));
  }
  return results;
}

async function runOneTool(call, tool, isMcpTool) {
  if (!tool) {
    return new ToolMessage({ tool_call_id: call.id ?? call.name, content: `Unknown tool ${call.name}` });
  }
  try {
    const output = await tool.invoke(call.args ?? {});
    return toolMessageForOutput(call, output);
  } catch (error) {
    if (isMcpTool && isMcpToolTimeoutError(error)) {
      throw normalizeMcpToolError(error);
    }
    // A failed tool call is agent feedback, not a bridge crash: return the
    // failure as an error tool result so the model can adjust its approach.
    return new ToolMessage({
      tool_call_id: call.id ?? call.name,
      content: `Tool ${call.name} failed: ${String(error?.message ?? error).slice(0, 2000)}`,
      status: "error",
    });
  }
}

function shouldContinueForRequest(request) {
  return (state) => {
    const last = state.messages.at(-1);
    if (!isAiMessage(last) || !last.tool_calls?.length) return END;
    return queryStopReason(state.messages, request) ? END : "tools";
  };
}

function queryResultFromMessages(messages, request, completionStopReason) {
  const message = messages.at(-1);
  const stopReason =
    completionStopReason ?? queryStopReason(messages, request) ?? message?.response_metadata?.finish_reason;
  return bridgeQueryResult(messages, stopReason);
}

function requestMaxModelTurns(request) {
  const options = request.runtimeOptions ?? request.runtime_options ?? {};
  return options.maxModelTurns ?? options.max_model_turns ?? undefined;
}

function queryStopReason(messages, request) {
  const last = messages.at(-1);
  if (!isAiMessage(last) || !last.tool_calls?.length) return undefined;
  const options = request.runtimeOptions ?? request.runtime_options ?? {};
  const stop = options.observedSpendStopUsd ?? options.observed_spend_stop_usd;
  const rates = request.spendEstimateRates ?? request.spend_estimate_rates;
  const decision = modelContinuationDecision(messages, stop, requestMaxModelTurns(request), rates);
  return decision === "continue" ? undefined : decision;
}

async function handleNextStep(request) {
  const tools = bridgeToolsForNextStep(request);
  const baseModel = modelForRequest(request);
  const model = tools.length ? baseModel.bindTools(tools) : baseModel;
  const system = request.systemPrompt ?? request.system_prompt ?? "";
  const response = await withProviderAdmission(request, () => invokeWithResponseText(model, [
    systemMessageForRequest(request, system),
    ...messagesForNextStep(request.messages),
  ], request), usageFromMessage);
  debugDumpBridgeCall("next-step", request, tools, system, response);
  return nextStepResultFromResponse(response);
}

function nextStepResultFromResponse(response) {
  const usage = usageFromMessage(response);
  const call = response.tool_calls?.[0];
  if (call) {
    return {
      ok: true,
      step: "tool_call",
      call: { name: call.name, input: call.args ?? {}, callId: call.id },
      cost_usd: usage.costUsd,
      input_tokens: usage.inputTokens,
      output_tokens: usage.outputTokens,
    };
  }
  const text = messageText(response);
  return {
    ok: true,
    step: "final",
    text,
    structured: maybeParseJson(text),
    cost_usd: usage.costUsd,
    input_tokens: usage.inputTokens,
    output_tokens: usage.outputTokens,
  };
}

async function handlePing(request) {
  const start = Date.now();
  const model = modelForRequest(request);
  const response = await withProviderAdmission(request, () => model.invoke([
    systemMessageForRequest(request, "You are an auth ping probe. Reply with ok."),
    new HumanMessage("ok"),
  ]), usageFromMessage);
  const usage = usageFromMessage(response);
  return {
    ok: true,
    auth_mode: model.authMode ?? "langchain-provider",
    model: parseModelSpec(request.model)[1],
    latency_ms: Date.now() - start,
    input_tokens: usage.inputTokens,
    output_tokens: usage.outputTokens,
    cost_usd: usage.costUsd,
  };
}

async function dispatch(request) {
  if (request.type === "tool-policy-handshake") return acknowledgeToolPolicy(request);
  if (request.authorization) return dispatchAuthorizedModelRequest(request);
  return dispatchModelRequest(request);
}

async function dispatchAuthorizedModelRequest(request) {
  const acknowledgement = authorizeExecutingQuery(request);
  const response = await dispatchModelRequest(request);
  return { ...response, toolPolicyAcknowledgement: acknowledgement };
}

async function dispatchModelRequest(request) {
  requireMembershipAuthorization(request);
  if (request.type === "next-step") return handleNextStep(request);
  if (request.type === "next-step-preflight") {
    return { ok: true, step: "final", text: "ok", cost_usd: 0 };
  }
  if (request.type === "ping") return handlePing(request);
  return runQueryGraph(request);
}

function requireMembershipAuthorization(request) {
  if (declaresReadMembership(request.toolPolicy) && !request.authorization) {
    throw new Error("accepted read membership requires explicit tool-policy authorization");
  }
}

function declaresReadMembership(policy) {
  return Object.hasOwn(policy ?? {}, "readScope") || Object.hasOwn(policy ?? {}, "read_scope");
}

let responseStream;

async function finishResponse(response, exitCode) {
  if (!responseStream) return writeBridgeResponseAndExit(response, exitCode);
  await responseStream.finish(response);
  process.exit(exitCode);
}

async function main() {
  // `--oauth-login <provider> [method]` runs an interactive auth flow over the
  // inherited terminal and never reads the JSON request envelope from stdin.
  const oauthArgs = parseOauthLoginArgs(process.argv.slice(2));
  if (oauthArgs) {
    process.exitCode = await runOauthLogin(oauthArgs);
    return;
  }
  const request = validateBridgeRequest(await readBridgeRequest(process.stdin));
  responseStream = responseStreamFor(request, writeBridgePayload);
  await openProviderAdmission(request, writeBridgePayload);
  await finishResponse(await dispatch(request), 0);
}

main().catch(async (error) => {
  const response = bridgeErrorResponse(error);
  // Mirror bounded redacted detail on stderr so native diagnostics can capture
  // it even when stdout parsing fails.
  if (response.detail) {
    process.stderr.write(`[bridge-error] ${response.errorClass}: ${response.detail}\n`);
  }
  try {
    await finishResponse(response, 1);
  } catch {
    process.exit(1);
  }
});

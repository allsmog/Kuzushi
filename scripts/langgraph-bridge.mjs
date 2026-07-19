#!/usr/bin/env node
import process from "node:process";
import { AIMessage, HumanMessage, ToolMessage } from "@langchain/core/messages";
import { END, MessagesAnnotation, START, StateGraph } from "@langchain/langgraph";
import { debugDumpBridgeCall } from "./langgraph-bridge/diagnostics.mjs";
import { bridgeErrorResponse } from "./langgraph-bridge/errors.mjs";
import {
  isMcpToolTimeoutError,
  mcpToolsForRequest,
  normalizeMcpToolError,
  withMcpClientCleanup,
} from "./langgraph-bridge/mcp.mjs";
import {
  appendStructuredOutputContract,
  bridgeUsageFields,
  DEFAULT_MAX_MODEL_TURNS,
  interruptedQueryResult,
  isAiMessage,
  maybeParseJson,
  messageText,
  modelContinuationDecision,
  modelForRequest,
  parseModelSpec,
  systemMessageForRequest,
  toolMessageForOutput,
  usageFromMessage,
  usageFromMessages,
} from "./langgraph-bridge/model.mjs";
import { parseOauthLoginArgs, runOauthLogin } from "./langgraph-bridge/oauth-login.mjs";
import { bridgeToolsForNextStep, validateBridgeRequest } from "./langgraph-bridge/schema.mjs";

async function readStdin() {
  let data = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

async function runQueryGraph(request) {
  const mcp = await mcpToolsForRequest(request);
  const modelMessages = [];
  return withMcpClientCleanup(async () => {
    const system = querySystemPromptForRequest(request);
    const graph = queryGraphForRequest(request, mcp.tools, system, modelMessages);
    try {
      const result = await graph.invoke({
        messages: [new HumanMessage(request.prompt ?? "")],
      }, { recursionLimit: DEFAULT_MAX_MODEL_TURNS * 2 + 2 });
      const message = result.messages.at(-1);
      debugDumpBridgeCall("query", request, mcp.tools, system, message);
      return queryResultFromMessages(result.messages, request);
    } catch (error) {
      if (!isMcpToolTimeoutError(error)) throw error;
      const message = modelMessages.at(-1);
      debugDumpBridgeCall("query", request, mcp.tools, system, message);
      return interruptedQueryResult(modelMessages, "mcp_tool_timeout");
    }
  }, mcp.close);
}

function queryGraphForRequest(request, tools, system, modelMessages) {
  const model = modelForRequest(request);
  const boundModel = tools.length ? model.bindTools(tools) : model;
  return new StateGraph(MessagesAnnotation)
    .addNode("model", callModelNode(boundModel, request, system, modelMessages))
    .addNode("tools", runToolsNode(tools))
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

function callModelNode(model, request, system, modelMessages) {
  return async (state) => {
    const message = await model.invoke([
      systemMessageForRequest(request, system),
      ...state.messages,
    ]);
    modelMessages.push(message);
    return { messages: [message] };
  };
}

function runToolsNode(tools) {
  const byName = Object.fromEntries(tools.map((tool) => [tool.name, tool]));
  return async (state) => ({ messages: await runRequestedTools(state.messages.at(-1), byName) });
}

async function runRequestedTools(message, toolsByName) {
  if (!isAiMessage(message) || !message.tool_calls?.length) return [];
  const results = [];
  for (const call of message.tool_calls) {
    results.push(await runOneTool(call, toolsByName[call.name]));
  }
  return results;
}

async function runOneTool(call, tool) {
  if (!tool) {
    return new ToolMessage({ tool_call_id: call.id ?? call.name, content: `Unknown tool ${call.name}` });
  }
  try {
    const output = await tool.invoke(call.args ?? {});
    return toolMessageForOutput(call, output);
  } catch (error) {
    throw normalizeMcpToolError(error);
  }
}

function shouldContinueForRequest(request) {
  return (state) => {
    const last = state.messages.at(-1);
    if (!isAiMessage(last) || !last.tool_calls?.length) return END;
    return queryStopReason(state.messages, request) ? END : "tools";
  };
}

function queryResultFromMessages(messages, request) {
  const message = messages.at(-1);
  const text = messageText(message);
  const usage = usageFromMessages(messages);
  const stopReason = queryStopReason(messages, request) ?? message?.response_metadata?.finish_reason;
  return {
    ok: true,
    text,
    structured: maybeParseJson(text),
    ...bridgeUsageFields(usage),
    truncated: isTruncatedStopReason(stopReason),
    stopReason,
  };
}

function queryStopReason(messages, request) {
  const last = messages.at(-1);
  if (!isAiMessage(last) || !last.tool_calls?.length) return undefined;
  const options = request.runtimeOptions ?? request.runtime_options ?? {};
  const stop = options.observedSpendStopUsd ?? options.observed_spend_stop_usd;
  const decision = modelContinuationDecision(messages, stop);
  return decision === "continue" ? undefined : decision;
}

function isTruncatedStopReason(reason) {
  return [
    "length",
    "max_tokens",
    "max_tokens_reached",
    "model_turn_limit",
    "mcp_tool_timeout",
    "observed_spend_incomplete",
    "observed_spend_exhausted",
  ].includes(String(reason ?? ""));
}

function messagesForNextStep(request) {
  return (request.messages ?? []).flatMap(nextStepMessage);
}

function nextStepMessage(raw) {
  const role = raw.role ?? raw.type;
  if (role === "user") return [new HumanMessage(raw.content ?? "")];
  if (role === "assistant") return [new AIMessage(raw.content ?? "")];
  if (role !== "tool") return [];
  return [
    new ToolMessage({
      tool_call_id: raw.tool_call_id ?? raw.toolUseId ?? raw.id ?? "tool",
      content: raw.content ?? "",
    }),
  ];
}

async function handleNextStep(request) {
  const tools = bridgeToolsForNextStep(request);
  const baseModel = modelForRequest(request);
  const model = tools.length ? baseModel.bindTools(tools) : baseModel;
  const system = request.systemPrompt ?? request.system_prompt ?? "";
  const response = await model.invoke([
    systemMessageForRequest(request, system),
    ...messagesForNextStep(request),
  ]);
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
  const response = await model.invoke([
    systemMessageForRequest(request, "You are an auth ping probe. Reply with ok."),
    new HumanMessage("ok"),
  ]);
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
  if (request.type === "next-step") return handleNextStep(request);
  if (request.type === "next-step-preflight") {
    return { ok: true, step: "final", text: "ok", cost_usd: 0 };
  }
  if (request.type === "ping") return handlePing(request);
  return runQueryGraph(request);
}

async function main() {
  // `--oauth-login <provider> [method]` runs an interactive auth flow over the
  // inherited terminal and never reads the JSON request envelope from stdin.
  const oauthArgs = parseOauthLoginArgs(process.argv.slice(2));
  if (oauthArgs) {
    process.exitCode = await runOauthLogin(oauthArgs);
    return;
  }
  const request = validateBridgeRequest(JSON.parse(await readStdin()));
  process.stdout.write(JSON.stringify(await dispatch(request)));
}

main().catch((error) => {
  process.stdout.write(JSON.stringify(bridgeErrorResponse(error)));
  process.exitCode = 1;
});

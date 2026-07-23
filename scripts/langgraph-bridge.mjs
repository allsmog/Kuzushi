#!/usr/bin/env node
import process from "node:process";
import { AIMessage, HumanMessage, ToolMessage } from "@langchain/core/messages";
import { END, MessagesAnnotation, START, StateGraph } from "@langchain/langgraph";
import { debugDumpBridgeCall } from "./langgraph-bridge/diagnostics.mjs";
import { bridgeErrorResponse } from "./langgraph-bridge/errors.mjs";
import { fileToolsForRequest } from "./langgraph-bridge/file-tools.mjs";
import { mcpToolsForRequest } from "./langgraph-bridge/mcp.mjs";
import {
  appendStructuredOutputContract,
  isAiMessage,
  maybeParseJson,
  messageText,
  modelForRequest,
  parseModelSpec,
  systemMessageForRequest,
  toolMessageForOutput,
  usageFromMessage,
} from "./langgraph-bridge/model.mjs";
import { parseOauthLoginArgs, runOauthLogin } from "./langgraph-bridge/oauth-login.mjs";
import { bridgeToolsForNextStep, validateBridgeRequest } from "./langgraph-bridge/schema.mjs";

async function readStdin() {
  let data = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

// Agentic tool loops need room beyond langgraph's default recursion limit
// of 25: one model step plus one tool step per hop halves the effective
// tool budget, and evidence-gathering verbs (verify:finding) routinely
// need >12 tool hops on large targets.
const QUERY_GRAPH_RECURSION_LIMIT = 64;

async function runQueryGraph(request) {
  const mcp = await mcpToolsForRequest(request);
  try {
    const system = querySystemPromptForRequest(request);
    const tools = [...fileToolsForRequest(request), ...mcp.tools];
    const graph = queryGraphForRequest(request, tools, system);
    const result = await graph.invoke(
      { messages: [new HumanMessage(request.prompt ?? "")] },
      { recursionLimit: QUERY_GRAPH_RECURSION_LIMIT },
    );
    const message = result.messages.at(-1);
    debugDumpBridgeCall("query", request, tools, system, message);
    return queryResultFromMessage(message);
  } finally {
    await mcp.close();
  }
}

function queryGraphForRequest(request, tools, system) {
  const model = modelForRequest(request);
  const boundModel = tools.length ? model.bindTools(tools) : model;
  return new StateGraph(MessagesAnnotation)
    .addNode("model", callModelNode(boundModel, request, system))
    .addNode("tools", runToolsNode(tools))
    .addEdge(START, "model")
    .addConditionalEdges("model", shouldContinue)
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

function callModelNode(model, request, system) {
  return async (state) => ({
    messages: [
      await invokeThroughQuotaWindows(model, [
        systemMessageForRequest(request, system),
        ...state.messages,
      ]),
    ],
  });
}

async function invokeThroughQuotaWindows(model, messages) {
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await model.invoke(messages);
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
    // A failed tool call is agent feedback, not a bridge crash: return the
    // failure as an error tool result so the model can adjust its approach.
    return new ToolMessage({
      tool_call_id: call.id ?? call.name,
      content: `Tool ${call.name} failed: ${String(error?.message ?? error).slice(0, 2000)}`,
      status: "error",
    });
  }
}

function shouldContinue(state) {
  const last = state.messages.at(-1);
  return isAiMessage(last) && last.tool_calls?.length ? "tools" : END;
}

function queryResultFromMessage(message) {
  const text = messageText(message);
  const usage = usageFromMessage(message);
  const stopReason = message?.response_metadata?.finish_reason;
  return {
    ok: true,
    text,
    structured: maybeParseJson(text),
    cost_usd: usage.costUsd,
    input_tokens: usage.inputTokens,
    output_tokens: usage.outputTokens,
    truncated: isTruncatedStopReason(stopReason),
    stopReason,
  };
}

function isTruncatedStopReason(reason) {
  return ["length", "max_tokens", "max_tokens_reached"].includes(String(reason ?? ""));
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

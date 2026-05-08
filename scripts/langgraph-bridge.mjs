#!/usr/bin/env node
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { AIMessage, HumanMessage, ToolMessage } from "@langchain/core/messages";
import { END, MessagesAnnotation, START, StateGraph } from "@langchain/langgraph";
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

async function runQueryGraph(request) {
  const mcp = await mcpToolsForRequest(request);
  try {
    const system = querySystemPromptForRequest(request);
    const graph = queryGraphForRequest(request, mcp.tools, system);
    const result = await graph.invoke({
      messages: [new HumanMessage(request.prompt ?? "")],
    });
    const message = result.messages.at(-1);
    debugDumpBridgeCall("query", request, mcp.tools, system, message);
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

function callModelNode(model, request, system) {
  return async (state) => ({
    messages: [await model.invoke([systemMessageForRequest(request, system), ...state.messages])],
  });
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
  const output = await tool.invoke(call.args ?? {});
  return toolMessageForOutput(call, output);
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

function debugDumpBridgeCall(kind, request, tools, systemPrompt, response) {
  debugDumpFullPrompt(kind, request, systemPrompt);
  const path = process.env.KUZUSHI_BRIDGE_DEBUG_DUMP;
  if (!path) return;
  try {
    const text = messageText(response);
    const dump = {
      ts: Date.now(),
      kind,
      model: request.model,
      thinkingLevel: request.thinkingLevel ?? request.thinking_level,
      toolCount: tools.length,
      toolNames: tools.map((tool) => tool.name).filter(Boolean),
      promptLen: (request.prompt ?? "").length,
      promptHead: (request.prompt ?? "").slice(0, 1500),
      messageCount: (request.messages ?? []).length,
      systemPromptLen: String(systemPrompt ?? "").length,
      systemPromptHead: String(systemPrompt ?? "").slice(0, 800),
      responseLen: text.length,
      responseHead: text.slice(0, 4000),
      responseTail: text.slice(-500),
      stopReason: response?.response_metadata?.finish_reason,
      responseToolNames: (response?.tool_calls ?? []).map((call) => call.name).filter(Boolean),
    };
    appendFileSync(path, `${JSON.stringify(dump)}\n`);
  } catch {}
}

function debugDumpFullPrompt(kind, request, systemPrompt) {
  const root = process.env.KUZUSHI_BRIDGE_DEBUG_FULL_PROMPT;
  if (!root) return;
  try {
    mkdirSync(root, { recursive: true });
    const filename = `prompt-${Date.now()}-${process.pid}-${kind}.txt`;
    writeFileSync(path.join(root, filename), fullPromptDebugBody(request, systemPrompt));
  } catch {}
}

function fullPromptDebugBody(request, systemPrompt) {
  const messages = request.messages ?? [];
  if (messages.length) {
    return [
      "[system]",
      String(systemPrompt ?? ""),
      "",
      "[messages]",
      JSON.stringify(messages, null, 2),
      "",
    ].join("\n");
  }
  return [
    "[system]",
    String(systemPrompt ?? ""),
    "",
    "[prompt]",
    String(request.prompt ?? ""),
    "",
  ].join("\n");
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
    };
  }
  const text = messageText(response);
  return {
    ok: true,
    step: "final",
    text,
    structured: maybeParseJson(text),
    cost_usd: usage.costUsd,
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
    text_preview: messageText(response).slice(0, 120),
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
  process.stdout.write(JSON.stringify({ ok: false, error: error?.message ?? String(error) }));
  process.exitCode = 1;
});

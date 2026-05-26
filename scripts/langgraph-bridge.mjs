#!/usr/bin/env node
import process from "node:process";
import { AIMessage, HumanMessage, SystemMessage, ToolMessage } from "@langchain/core/messages";
import { END, MessagesAnnotation, START, StateGraph } from "@langchain/langgraph";
import { mcpToolsForRequest } from "./langgraph-bridge/mcp.mjs";
import {
  appendStructuredOutputContract,
  isAiMessage,
  maybeParseJson,
  messageText,
  modelForRequest,
  parseModelSpec,
  toolMessageForOutput,
  usageFromMessage,
} from "./langgraph-bridge/model.mjs";
import { bridgeToolsForNextStep } from "./langgraph-bridge/schema.mjs";

async function readStdin() {
  let data = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

async function runQueryGraph(request) {
  const mcp = await mcpToolsForRequest(request);
  try {
    const graph = queryGraphForRequest(request, mcp.tools);
    const result = await graph.invoke({
      messages: [new HumanMessage(request.prompt ?? "")],
    });
    return queryResultFromMessage(result.messages.at(-1));
  } finally {
    await mcp.close();
  }
}

function queryGraphForRequest(request, tools) {
  const model = modelForRequest(request);
  const system = appendStructuredOutputContract(
    request.systemPrompt ?? request.system_prompt,
    request.structuredOutput ?? request.structured_output,
  );
  const boundModel = tools.length ? model.bindTools(tools) : model;
  return new StateGraph(MessagesAnnotation)
    .addNode("model", callModelNode(boundModel, system))
    .addNode("tools", runToolsNode(tools))
    .addEdge(START, "model")
    .addConditionalEdges("model", shouldContinue)
    .addEdge("tools", "model")
    .compile();
}

function callModelNode(model, system) {
  return async (state) => ({
    messages: [await model.invoke([new SystemMessage(system), ...state.messages])],
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
  return {
    ok: true,
    text,
    structured: maybeParseJson(text),
    cost_usd: usage.costUsd,
    input_tokens: usage.inputTokens,
    output_tokens: usage.outputTokens,
    truncated: false,
    stopReason: message?.response_metadata?.finish_reason,
  };
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
  const response = await model.invoke([new SystemMessage(system), ...messagesForNextStep(request)]);
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
    new SystemMessage("You are an auth ping probe. Reply with ok."),
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
  const request = JSON.parse(await readStdin());
  process.stdout.write(JSON.stringify(await dispatch(request)));
}

main().catch((error) => {
  process.stdout.write(JSON.stringify({ ok: false, error: error?.message ?? String(error) }));
  process.exitCode = 1;
});

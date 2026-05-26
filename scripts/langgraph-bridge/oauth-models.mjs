import { AIMessage } from "@langchain/core/messages";
import { appendStructuredOutputContract, maybeParseJson, messageText } from "./model.mjs";

const CLAUDE_CODE_IDENTITY_LINE = "You are Claude Code, Anthropic's official CLI for Claude.";

export function oauthModelForRequest(provider, modelName, token, request) {
  if (provider === "anthropic") return new AnthropicOAuthChatModel(modelName, token, request);
  if (provider === "openai-codex") return new OpenAiCodexOAuthChatModel(modelName, token, request);
  return undefined;
}

class AnthropicOAuthChatModel {
  constructor(modelName, token, request, tools = []) {
    this.modelName = modelName;
    this.token = token;
    this.request = request;
    this.tools = tools;
    this.authMode = "oauth-file";
  }

  bindTools(tools) {
    return new AnthropicOAuthChatModel(this.modelName, this.token, this.request, tools);
  }

  async invoke(messages) {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.token}`,
        "anthropic-beta": "oauth-2025-04-20",
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
      },
      body: JSON.stringify(this.body(messages)),
    });
    const text = await response.text();
    if (!response.ok) throw new Error(`Anthropic OAuth API ${response.status}: ${text.slice(0, 500)}`);
    return anthropicMessageFromResponse(JSON.parse(text));
  }

  body(messages) {
    const system = appendStructuredOutputContract(systemText(messages), structuredOutput(this.request));
    const body = {
      model: this.modelName,
      max_tokens: maxTokens(this.request),
      system: claudeCodeIdentitySystemBlocks(system),
      messages: anthropicMessages(messages),
    };
    if (this.tools.length) body.tools = this.tools.map(anthropicToolDefinition);
    const temperature = numericTemperature(this.request);
    if (temperature !== undefined) body.temperature = temperature;
    return body;
  }
}

class OpenAiCodexOAuthChatModel {
  constructor(modelName, token, request, tools = []) {
    this.modelName = modelName;
    this.token = token;
    this.request = request;
    this.tools = tools;
    this.authMode = "oauth-file";
  }

  bindTools(tools) {
    return new OpenAiCodexOAuthChatModel(this.modelName, this.token, this.request, tools);
  }

  async invoke(messages) {
    const response = await fetch("https://chatgpt.com/backend-api/codex/responses", {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(this.body(messages)),
    });
    const text = await response.text();
    if (!response.ok) throw new Error(`OpenAI Codex OAuth API ${response.status}: ${text.slice(0, 500)}`);
    return openAiMessageFromSse(text);
  }

  body(messages) {
    const instructions = appendStructuredOutputContract(systemText(messages), structuredOutput(this.request));
    const body = {
      model: this.modelName,
      instructions: instructions || "You are a concise assistant.",
      input: openAiInput(messages),
      store: false,
      stream: true,
    };
    if (this.tools.length) body.tools = this.tools.map(openAiToolDefinition);
    const temperature = numericTemperature(this.request);
    if (temperature !== undefined) body.temperature = temperature;
    return body;
  }
}

function anthropicMessageFromResponse(parsed) {
  const blocks = Array.isArray(parsed.content) ? parsed.content : [];
  const toolCalls = blocks.filter(isAnthropicToolUse).map(anthropicToolCall);
  const text = blocks.filter(isAnthropicText).map((block) => block.text).join("");
  return aiMessage(text, toolCalls, anthropicUsage(parsed.usage), parsed.stop_reason);
}

function openAiMessageFromSse(text) {
  const events = sseJsonEvents(text);
  const toolCalls = events.flatMap(openAiToolCallsFromEvent);
  const finalText = outputTextFromEvents(events);
  const usage = events.findLast?.((event) => event?.response?.usage)?.response?.usage;
  return aiMessage(finalText, toolCalls, openAiUsage(usage), undefined);
}

function aiMessage(content, toolCalls, usage, finishReason) {
  return new AIMessage({
    content,
    tool_calls: toolCalls,
    usage_metadata: usage,
    response_metadata: { finish_reason: finishReason },
  });
}

function sseJsonEvents(text) {
  return text
    .split(/\n\n+/)
    .map((chunk) => chunk.split("\n").find((line) => line.startsWith("data: "))?.slice(6))
    .filter(Boolean)
    .map(parseJsonEvent)
    .filter(Boolean);
}

function parseJsonEvent(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

function outputTextFromEvents(events) {
  const done = events.findLast?.((event) => event.type === "response.output_text.done");
  if (typeof done?.text === "string") return done.text;
  return events
    .filter((event) => event.type === "response.output_text.delta")
    .map((event) => event.delta ?? "")
    .join("");
}

function openAiToolCallsFromEvent(event) {
  const item = event?.item;
  if (event?.type !== "response.output_item.done" || item?.type !== "function_call") return [];
  return [
    {
      id: item.call_id ?? item.id ?? `call_${Date.now()}`,
      name: item.name,
      args: parseArguments(item.arguments),
      type: "tool_call",
    },
  ];
}

function parseArguments(value) {
  try {
    return value ? JSON.parse(value) : {};
  } catch {
    return {};
  }
}

function anthropicMessages(messages) {
  const converted = messages.filter((message) => message?._getType?.() !== "system").map(anthropicMessage);
  return converted.length ? converted : [{ role: "user", content: "ok" }];
}

function anthropicMessage(message) {
  if (message?._getType?.() === "ai") return { role: "assistant", content: messageText(message) };
  if (message?._getType?.() === "tool") return anthropicToolResultMessage(message);
  return { role: "user", content: messageText(message) };
}

function anthropicToolResultMessage(message) {
  return {
    role: "user",
    content: [{ type: "tool_result", tool_use_id: message.tool_call_id, content: messageText(message) }],
  };
}

function openAiInput(messages) {
  const input = messages.filter((message) => message?._getType?.() !== "system").map(openAiInputMessage);
  return input.length ? input : [{ role: "user", content: "ok" }];
}

function openAiInputMessage(message) {
  if (message?._getType?.() === "ai") return { role: "assistant", content: messageText(message) };
  if (message?._getType?.() === "tool") {
    return { type: "function_call_output", call_id: message.tool_call_id, output: messageText(message) };
  }
  return { role: "user", content: messageText(message) };
}

function systemText(messages) {
  return messages
    .filter((message) => message?._getType?.() === "system")
    .map(messageText)
    .join("\n\n");
}

function structuredOutput(request) {
  return request.structuredOutput ?? request.structured_output;
}

function maxTokens(request) {
  return request.maxOutputTokens ?? request.max_output_tokens ?? request.maxTokens ?? request.max_tokens ?? 4096;
}

function numericTemperature(request) {
  const value = Number(request?.temperature ?? request?.samplingTemperature ?? request?.sampling_temperature);
  return Number.isFinite(value) && value >= 0 && value <= 2 ? value : undefined;
}

function claudeCodeIdentitySystemBlocks(system) {
  const blocks = [{ type: "text", text: CLAUDE_CODE_IDENTITY_LINE }];
  if (system.trim()) blocks.push({ type: "text", text: stripIdentity(system) });
  return blocks;
}

function stripIdentity(system) {
  return system.startsWith(CLAUDE_CODE_IDENTITY_LINE)
    ? system.slice(CLAUDE_CODE_IDENTITY_LINE.length).replace(/^\n+/, "")
    : system;
}

function anthropicToolDefinition(tool) {
  return {
    name: tool.name,
    description: tool.description ?? "",
    input_schema: tool.schema ?? tool.input_schema ?? tool.inputSchema ?? { type: "object" },
  };
}

function openAiToolDefinition(tool) {
  return {
    type: "function",
    name: tool.name,
    description: tool.description ?? "",
    parameters: tool.schema ?? tool.input_schema ?? tool.inputSchema ?? { type: "object" },
  };
}

function isAnthropicToolUse(block) {
  return block?.type === "tool_use";
}

function isAnthropicText(block) {
  return block?.type === "text" && typeof block.text === "string";
}

function anthropicToolCall(block) {
  return { id: block.id, name: block.name, args: block.input ?? {}, type: "tool_call" };
}

function anthropicUsage(usage) {
  return {
    input_tokens: Number(usage?.input_tokens ?? 0) || 0,
    output_tokens: Number(usage?.output_tokens ?? 0) || 0,
  };
}

function openAiUsage(usage) {
  return {
    input_tokens: Number(usage?.input_tokens ?? 0) || 0,
    output_tokens: Number(usage?.output_tokens ?? 0) || 0,
  };
}

import { AIMessage } from "@langchain/core/messages";
import { invalidProviderResponseError, providerHttpError } from "./errors.mjs";
import { appendStructuredOutputContract, cacheableTextBlock, messageText } from "./model.mjs";

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
    if (!response.ok) throw providerHttpError(response.status);
    return anthropicMessageFromResponse(await providerJson(response));
  }

  body(messages) {
    const system = appendStructuredOutputContract(systemText(messages), structuredOutput(this.request));
    const body = {
      model: this.modelName,
      max_tokens: maxTokens(this.request),
      system: claudeCodeIdentitySystemBlocks(system),
      messages: anthropicMessages(messages),
    };
    if (this.tools.length) body.tools = anthropicToolDefinitions(this.tools);
    const temperature = numericTemperature(this.request);
    if (temperature !== undefined) body.temperature = temperature;
    return body;
  }
}

class OpenAiCodexOAuthChatModel {
  constructor(modelName, token, request, tools = [], toolBindings = undefined) {
    this.modelName = modelName;
    this.token = token;
    this.request = request;
    this.tools = tools;
    this.toolBindings = toolBindings ?? openAiToolBindings(tools);
    this.authMode = "oauth-file";
  }

  bindTools(tools) {
    return new OpenAiCodexOAuthChatModel(
      this.modelName,
      this.token,
      this.request,
      tools,
      openAiToolBindings(tools),
    );
  }

  async invoke(messages) {
    const response = await fetch("https://chatgpt.com/backend-api/codex/responses", {
      method: "POST",
      headers: openAiOauthHeaders(this.token, this.request.oauthAccountId),
      body: JSON.stringify(this.body(messages)),
    });
    if (!response.ok) throw providerHttpError(response.status);
    const text = await response.text();
    return openAiMessageFromSse(text, this.openAiToolNameMap());
  }

  body(messages) {
    const instructions = appendStructuredOutputContract(systemText(messages), structuredOutput(this.request));
    const body = {
      model: this.modelName,
      instructions: instructions || "You are a concise assistant.",
      input: openAiInput(messages, this.originalToSafeToolNameMap()),
      store: false,
      stream: true,
    };
    if (this.tools.length) body.tools = this.openAiToolDefinitions();
    return body;
  }

  openAiToolBindings() {
    return this.toolBindings;
  }

  openAiToolDefinitions() {
    return this.openAiToolBindings().definitions;
  }

  openAiToolNameMap() {
    return this.openAiToolBindings().safeToOriginal;
  }

  originalToSafeToolNameMap() {
    return this.openAiToolBindings().originalToSafe;
  }
}

export function openAiOauthHeaders(token, accountId) {
  return {
    authorization: `Bearer ${token}`,
    "content-type": "application/json",
    ...(accountId ? { "ChatGPT-Account-Id": accountId } : {}),
  };
}

async function providerJson(response) {
  try {
    return JSON.parse(await response.text());
  } catch {
    throw invalidProviderResponseError();
  }
}

function anthropicMessageFromResponse(parsed) {
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed) || !Array.isArray(parsed.content)) {
    throw invalidProviderResponseError();
  }
  const blocks = parsed.content;
  const toolCalls = blocks.filter(isAnthropicToolUse).map(anthropicToolCall);
  const text = blocks.filter(isAnthropicText).map((block) => block.text).join("");
  return aiMessage(text, toolCalls, anthropicUsage(parsed.usage), parsed.stop_reason);
}

function openAiMessageFromSse(text, safeToOriginal = new Map()) {
  const events = sseJsonEvents(text);
  const toolCalls = events.flatMap((event) => openAiToolCallsFromEvent(event, safeToOriginal));
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
    .split(/\r?\n\r?\n+/)
    .map(sseDataPayload)
    .filter((payload) => payload !== undefined)
    .map(parseJsonEvent)
    .filter(Boolean);
}

function sseDataPayload(chunk) {
  const dataLines = chunk
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data:"))
    .map((line) => {
      const value = line.slice(5);
      return value.startsWith(" ") ? value.slice(1) : value;
    });
  return dataLines.length ? dataLines.join("\n") : undefined;
}

function parseJsonEvent(raw) {
  const trimmed = raw.trim();
  if (trimmed === "[DONE]") return undefined;
  let parsed;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw invalidProviderResponseError();
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw invalidProviderResponseError();
  }
  return parsed;
}

function outputTextFromEvents(events) {
  const done = events.findLast?.((event) => event.type === "response.output_text.done");
  if (typeof done?.text === "string") return done.text;
  return events
    .filter((event) => event.type === "response.output_text.delta")
    .map((event) => event.delta ?? "")
    .join("");
}

function openAiToolCallsFromEvent(event, safeToOriginal = new Map()) {
  const item = event?.item;
  if (event?.type !== "response.output_item.done" || item?.type !== "function_call") return [];
  const callId = requiredProviderIdentifier(item.call_id);
  const providerName = requiredProviderIdentifier(item.name);
  return [
    {
      id: callId,
      name: safeToOriginal.get(providerName) ?? providerName,
      args: parseArguments(item.arguments),
      type: "tool_call",
    },
  ];
}

function requiredProviderIdentifier(value) {
  if (typeof value !== "string" || !value.trim()) throw invalidProviderResponseError();
  return value;
}

function requiredProviderObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw invalidProviderResponseError();
  }
  return value;
}

function parseArguments(value) {
  if (typeof value !== "string" || !value.trim()) throw invalidProviderResponseError();
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw invalidProviderResponseError();
  }
  return requiredProviderObject(parsed);
}

function anthropicMessages(messages) {
  const converted = messages.filter((message) => message?._getType?.() !== "system").map(anthropicMessage);
  if (!converted.length) return [{ role: "user", content: "ok" }];
  return markHistoryCacheBreakpoint(converted);
}

// Agent loops resend the full conversation on every call; a cache breakpoint on
// the last turn lets the next call read that shared prefix at cache-read rates.
// Single-shot calls (one message) stay unmarked so a volatile one-off prompt
// never pays the cache-write premium for a prefix that is never reused.
function markHistoryCacheBreakpoint(converted) {
  if (converted.length < 2) return converted;
  const last = converted.at(-1);
  const content = contentWithCacheBreakpoint(last.content);
  return content ? [...converted.slice(0, -1), { ...last, content }] : converted;
}

function contentWithCacheBreakpoint(content) {
  if (typeof content === "string") {
    return content.trim() ? [cacheableTextBlock(content)] : undefined;
  }
  if (!Array.isArray(content) || !content.length) return undefined;
  const last = content.at(-1);
  return [...content.slice(0, -1), { ...last, cache_control: { type: "ephemeral" } }];
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

function openAiInput(messages, originalToSafe = new Map()) {
  const input = messages
    .filter((message) => message?._getType?.() !== "system")
    .flatMap((message) => openAiInputMessage(message, originalToSafe));
  return input.length ? input : [{ role: "user", content: "ok" }];
}

function openAiInputMessage(message, originalToSafe = new Map()) {
  if (message?._getType?.() === "ai") {
    const calls = Array.isArray(message.tool_calls)
      ? message.tool_calls.map((call) => openAiFunctionCallInput(call, originalToSafe))
      : [];
    const text = messageText(message);
    const assistant = text ? [{ role: "assistant", content: text }] : [];
    return [...assistant, ...calls];
  }
  if (message?._getType?.() === "tool") {
    return [{ type: "function_call_output", call_id: message.tool_call_id, output: messageText(message) }];
  }
  return [{ role: "user", content: messageText(message) }];
}

function openAiFunctionCallInput(call, originalToSafe = new Map()) {
  return {
    type: "function_call",
    call_id: call.id ?? call.callId ?? call.name,
    name: originalToSafe.get(call.name) ?? safeOpenAiBaseName(call.name),
    arguments: JSON.stringify(call.args ?? {}),
  };
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
  if (system.trim()) blocks.push(cacheableTextBlock(stripIdentity(system)));
  return blocks;
}

function stripIdentity(system) {
  return system.startsWith(CLAUDE_CODE_IDENTITY_LINE)
    ? system.slice(CLAUDE_CODE_IDENTITY_LINE.length).replace(/^\n+/, "")
    : system;
}

// Tool definitions render first in the prompt and are stable across every call
// in a run; a breakpoint on the last definition caches the whole tools segment
// even when the role-specific system prompt differs between calls.
function anthropicToolDefinitions(tools) {
  const definitions = tools.map(anthropicToolDefinition);
  const lastIndex = definitions.length - 1;
  definitions[lastIndex] = { ...definitions[lastIndex], cache_control: { type: "ephemeral" } };
  return definitions;
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

function openAiToolBindings(tools) {
  const used = new Set();
  const safeToOriginal = new Map();
  const originalToSafe = new Map();
  const definitions = tools.map((tool) => {
    const safeName = safeOpenAiToolName(tool.name, used);
    safeToOriginal.set(safeName, tool.name);
    originalToSafe.set(tool.name, safeName);
    return openAiToolDefinition({ ...tool, name: safeName });
  });
  return { definitions, safeToOriginal, originalToSafe };
}

function safeOpenAiToolName(name, used) {
  const base = safeOpenAiBaseName(name);
  let candidate = base;
  let counter = 2;
  while (used.has(candidate)) {
    const suffix = `_${counter++}`;
    candidate = `${base.slice(0, Math.max(1, 64 - suffix.length))}${suffix}`;
  }
  used.add(candidate);
  return candidate;
}

function safeOpenAiBaseName(name) {
  const raw = String(name ?? "tool").replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64);
  return raw || "tool";
}

function isAnthropicToolUse(block) {
  return block?.type === "tool_use";
}

function isAnthropicText(block) {
  return block?.type === "text" && typeof block.text === "string";
}

function anthropicToolCall(block) {
  return {
    id: requiredProviderIdentifier(block.id),
    name: requiredProviderIdentifier(block.name),
    args: requiredProviderObject(block.input),
    type: "tool_call",
  };
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
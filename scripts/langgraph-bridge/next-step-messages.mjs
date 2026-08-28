import { AIMessage, HumanMessage, ToolMessage } from "@langchain/core/messages";
import { invalidProviderResponseError } from "./errors.mjs";

export function messagesForNextStep(rawMessages) {
  return (rawMessages ?? []).flatMap(nextStepMessage);
}

export function nextStepMessage(raw) {
  const role = raw?.role ?? raw?.type;
  if (role === "assistant") return assistantMessages(raw);
  if (role === "user") return userMessages(raw);
  if (role === "tool") return [toolMessageFromRaw(raw)];
  return [];
}

function assistantMessages(raw) {
  const content = raw?.content;
  const contentBlocks = Array.isArray(content) ? content : [];
  const toolUseBlocks = contentBlocks.filter((block) => block?.type === "tool_use");
  const providerContent = contentBlocks.filter((block) => block?.type !== "tool_use");
  const rawCalls = Array.isArray(raw?.tool_calls) ? raw.tool_calls : [];
  const calls = toolUseBlocks.length
    ? toolUseBlocks.map(toolCallFromUseBlock)
    : rawCalls.map(toolCallFromRaw);

  if (!calls.length && !Array.isArray(content)) {
    return [new AIMessage(content ?? "")];
  }

  return [
    new AIMessage({
      content: providerContent.length ? providerContent : typeof content === "string" ? content : "",
      tool_calls: calls,
    }),
  ];
}

function userMessages(raw) {
  const content = raw?.content;
  if (!Array.isArray(content)) return [new HumanMessage(content ?? "")];

  const messages = [];
  let humanBlocks = [];
  const flushHumanBlocks = () => {
    if (!humanBlocks.length) return;
    messages.push(new HumanMessage(humanBlocks));
    humanBlocks = [];
  };

  for (const block of content) {
    if (block?.type !== "tool_result") {
      humanBlocks.push(block);
      continue;
    }
    flushHumanBlocks();
    messages.push(toolMessageFromResultBlock(block));
  }
  flushHumanBlocks();
  return messages;
}

function toolCallFromUseBlock(block) {
  return {
    id: requiredIdentifier(block?.id),
    name: requiredIdentifier(block?.name),
    args: requiredObject(block?.input),
    type: "tool_call",
  };
}

function toolCallFromRaw(call) {
  return {
    id: requiredIdentifier(call?.id ?? call?.callId),
    name: requiredIdentifier(call?.name),
    args: requiredObject(call?.args ?? call?.input ?? {}),
    type: "tool_call",
  };
}

function toolMessageFromResultBlock(block) {
  return new ToolMessage({
    tool_call_id: requiredIdentifier(block?.tool_use_id ?? block?.toolUseId),
    content: block?.content ?? "",
    ...(block?.is_error ? { status: "error" } : {}),
  });
}

function toolMessageFromRaw(raw) {
  return new ToolMessage({
    tool_call_id: requiredIdentifier(raw?.tool_call_id ?? raw?.toolUseId ?? raw?.id),
    content: raw?.content ?? "",
    ...(raw?.status === "error" ? { status: "error" } : {}),
  });
}

function requiredIdentifier(value) {
  if (typeof value !== "string" || !value.trim()) throw invalidProviderResponseError();
  return value;
}

function requiredObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalidProviderResponseError();
  }
  return value;
}

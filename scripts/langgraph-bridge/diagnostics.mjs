import {
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  mkdirSync,
  openSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import path from "node:path";

let diagnosticSequence = 0;

const STOP_CLASSES = new Map([
  ["length", "length"],
  ["max_tokens", "length"],
  ["max_tokens_reached", "length"],
  ["tool_use", "tool"],
  ["tool_call", "tool"],
  ["end_turn", "complete"],
  ["stop", "complete"],
  ["stop_sequence", "complete"],
  ["completed", "complete"],
  ["content_filter", "filtered"],
]);

export function debugDumpBridgeCall(kind, request, tools, systemPrompt, response) {
  const metadata = bridgeDiagnosticMetadata(kind, request, tools, systemPrompt, response);
  appendDiagnostic(process.env.KUZUSHI_BRIDGE_DEBUG_DUMP, metadata);
  writePromptDiagnostic(process.env.KUZUSHI_BRIDGE_DEBUG_FULL_PROMPT, kind, metadata);
}

export function bridgeDiagnosticMetadata(kind, request, tools, systemPrompt, response) {
  const prompt = String(request?.prompt ?? "");
  const messages = Array.isArray(request?.messages) ? request.messages : [];
  return {
    ts: Date.now(),
    kind: diagnosticKind(kind),
    modelProvider: modelProvider(request?.model),
    thinkingLevel: thinkingLevel(request?.thinkingLevel ?? request?.thinking_level),
    toolCount: Array.isArray(tools) ? tools.length : 0,
    promptLen: prompt.length,
    messageCount: messages.length,
    systemPromptLen: String(systemPrompt ?? "").length,
    responseLen: responseTextLength(response),
    stopClass: stopClass(response?.response_metadata?.finish_reason),
    responseToolCount: Array.isArray(response?.tool_calls) ? response.tool_calls.length : 0,
  };
}

function appendDiagnostic(file, metadata) {
  if (!file) return;
  let descriptor;
  try {
    descriptor = openSync(
      file,
      constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY | noFollowFlag(),
      0o600,
    );
    fchmodSync(descriptor, 0o600);
    writeSync(descriptor, `${JSON.stringify(metadata)}\n`);
  } catch {
  } finally {
    closeDescriptor(descriptor);
  }
}

function writePromptDiagnostic(root, kind, metadata) {
  if (!root) return;
  let descriptor;
  try {
    ensureDiagnosticDirectory(root);
    const sequence = diagnosticSequence++;
    const filename = `prompt-metadata-${Date.now()}-${process.pid}-${sequence}-${diagnosticKind(kind)}.json`;
    const file = path.join(root, filename);
    descriptor = openSync(
      file,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | noFollowFlag(),
      0o600,
    );
    fchmodSync(descriptor, 0o600);
    writeFileSync(descriptor, `${JSON.stringify(metadata, null, 2)}\n`);
  } catch {
  } finally {
    closeDescriptor(descriptor);
  }
}

function closeDescriptor(descriptor) {
  if (descriptor === undefined) return;
  try {
    closeSync(descriptor);
  } catch {}
}

function ensureDiagnosticDirectory(root) {
  if (existsSync(root)) return;
  mkdirSync(root, { recursive: true, mode: 0o700 });
}

function noFollowFlag() {
  return constants.O_NOFOLLOW ?? 0;
}

function diagnosticKind(value) {
  return value === "query" || value === "next-step" ? value : "unknown";
}

function modelProvider(value) {
  const provider = String(value ?? "").split(":", 1)[0];
  return ["anthropic", "openai", "openai-codex"].includes(provider) ? provider : "other";
}

function thinkingLevel(value) {
  const level = String(value ?? "").toLowerCase();
  return ["low", "medium", "high"].includes(level) ? level : undefined;
}

function responseTextLength(response) {
  const content = response?.content;
  if (typeof content === "string") return content.length;
  if (!Array.isArray(content)) return 0;
  return content.reduce((total, part) => total + contentPartLength(part), 0);
}

function contentPartLength(part) {
  if (typeof part === "string") return part.length;
  if (typeof part?.text === "string") return part.text.length;
  if (typeof part?.content === "string") return part.content.length;
  return 0;
}

function stopClass(value) {
  const reason = String(value ?? "").toLowerCase();
  return STOP_CLASSES.get(reason) ?? (reason ? "other" : undefined);
}

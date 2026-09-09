import { invalidProviderResponseError } from "./errors.mjs";

const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;
const MAX_EVENT_CHARS = 8 * 1024 * 1024;

export async function openAiResponseEvents(response, onText) {
  const events = [];
  let completed = false;
  for await (const event of sseEvents(response.body)) {
    if (completed) throw invalidProviderResponseError();
    rejectFailedResponse(event);
    await emitEventText(event, onText);
    completed = event.type === "response.completed";
    events.push(event);
  }
  if (!completed) throw invalidProviderResponseError();
  return events;
}

async function emitEventText(event, onText) {
  if (event.type === "response.output_text.delta") await emitText(event.delta, onText);
}

async function emitText(text, onText) {
  if (typeof text !== "string") throw invalidProviderResponseError();
  if (text) await onText(text);
}

function rejectFailedResponse(event) {
  if (["error", "response.failed", "response.incomplete"].includes(event.type)) {
    throw invalidProviderResponseError();
  }
  if (event.type === "response.completed" && event.response?.status !== "completed") {
    throw invalidProviderResponseError();
  }
}

async function* sseEvents(body) {
  if (!body) throw invalidProviderResponseError();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let pending = "";
  let bytes = 0;
  for await (const chunk of body) {
    bytes += chunk.length;
    if (bytes > MAX_RESPONSE_BYTES) throw invalidProviderResponseError();
    pending += decode(decoder, chunk, true);
    const frames = pending.split(/\r?\n\r?\n/);
    pending = frames.pop();
    for (const frame of frames) {
      const event = parseFrame(frame);
      if (event) yield event;
    }
    if (pending.length > MAX_EVENT_CHARS) throw invalidProviderResponseError();
  }
  pending += decode(decoder, undefined, false);
  if (pending.trim()) throw invalidProviderResponseError();
}

function decode(decoder, chunk, stream) {
  try { return decoder.decode(chunk, { stream }); }
  catch { throw invalidProviderResponseError(); }
}

function parseFrame(frame) {
  if (frame.length > MAX_EVENT_CHARS) throw invalidProviderResponseError();
  const payload = frame.split(/\r?\n/).filter((line) => line.startsWith("data:"))
    .map((line) => line.slice(5).replace(/^ /, "")).join("\n");
  if (!payload || payload.trim() === "[DONE]") return undefined;
  const parsed = parsePayload(payload);
  if (!isEvent(parsed)) {
    throw invalidProviderResponseError();
  }
  return parsed;
}

function isEvent(value) {
  return value && typeof value.type === "string" && !Array.isArray(value);
}

function parsePayload(payload) {
  try { return JSON.parse(payload); }
  catch { throw invalidProviderResponseError(); }
}

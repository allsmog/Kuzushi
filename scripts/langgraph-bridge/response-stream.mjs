import { invalidProviderResponseError } from "./errors.mjs";

const streams = new WeakMap();

export function responseStreamFor(request, write) {
  if (request.responseEvents !== "text-v1") return undefined;
  const stream = new ResponseStream(write);
  streams.set(request, stream);
  return stream;
}

class ResponseStream {
  constructor(write) {
    this.write = write;
    this.pending = "";
    this.lastFlush = 0;
  }

  async frame(value) {
    await this.write(`\x1e${JSON.stringify(value)}\n`);
  }

  async reset() {
    this.pending = "";
    this.lastFlush = 0;
    await this.frame({ type: "reset" });
  }

  async text(text) {
    this.pending += text;
    if (Date.now() - this.lastFlush >= 50 || this.pending.length >= 4096) await this.flush();
  }

  async flush() {
    const points = Array.from(this.pending);
    this.pending = "";
    for (let offset = 0; offset < points.length; offset += 4096) {
      await this.frame({ type: "text", text: points.slice(offset, offset + 4096).join("") });
    }
    this.lastFlush = Date.now();
  }

  async finish(result) {
    await this.flush();
    await this.frame({ type: "result", result });
  }
}

export async function invokeWithResponseText(model, messages, request) {
  const stream = streams.get(request);
  if (!stream) return model.invoke(messages);
  await stream.reset();
  try {
    return await invokeStreamingModel(model, messages, (text) => stream.text(text));
  } finally {
    await stream.flush();
  }
}

async function invokeStreamingModel(model, messages, onText) {
  // OAuth adapters own their provider's transport. Older custom adapters may
  // still return only a final result; the UI receives no invented deltas.
  if (typeof model.stream !== "function") return model.invoke(messages, { onText });
  let response;
  for await (const chunk of await model.stream(messages)) {
    response = response ? response.concat(chunk) : chunk;
    const text = publicText(chunk.content);
    if (text) await onText(text);
  }
  return completedMessage(response);
}

function publicText(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.filter((part) => part?.type === "text")
    .map((part) => typeof part.text === "string" ? part.text : "").join("");
}

function completedMessage(response) {
  if (!response || response.invalid_tool_calls?.length) throw invalidProviderResponseError();
  return response;
}

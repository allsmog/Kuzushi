import { BridgePublicError } from "./errors.mjs";

const PROTOCOL = "stdio-v1";
const clients = new WeakMap();
const MAX_REQUEST_CHARS = 64 * 1024 * 1024;
const MAX_REPLY_CHARS = 4096;

export function providerAdmissionEnabled(request) {
  return request?.providerAdmission === PROTOCOL;
}

/** Legacy JSON ends at EOF. An admitted request ends at its first newline and
 * keeps stdin exclusively for host replies; none of this channel reaches models. */
export async function readBridgeRequest(input) {
  input.setEncoding("utf8");
  const iterator = input.iterator({ destroyOnReturn: false });
  let body = "";
  for (;;) {
    const next = await iterator.next();
    if (next.done) return legacyRequest(body);
    body += next.value;
    requireProtocol(body.length <= MAX_REQUEST_CHARS);
    const admitted = admittedRequest(body);
    if (admitted) {
      clients.set(admitted, new AdmissionClient(iterator));
      return admitted;
    }
  }
}

function legacyRequest(body) {
  const request = JSON.parse(body);
  requireProtocol(request?.providerAdmission === undefined);
  return request;
}

function admittedRequest(body) {
  const newline = body.indexOf("\n");
  if (newline < 0) return undefined;
  let parsed;
  try { parsed = JSON.parse(body.slice(0, newline)); }
  catch { return undefined; }
  if (parsed?.providerAdmission === undefined) return undefined;
  requireProtocol(providerAdmissionEnabled(parsed));
  requireProtocol(body.slice(newline + 1).trim() === "");
  return parsed;
}

export async function openProviderAdmission(request, write) {
  if (!providerAdmissionEnabled(request)) return;
  const client = requiredClient(request);
  client.write = write;
  const reply = await client.exchange({ type: "hello", protocol: 1 });
  requireProtocol(reply.type === "ready" && reply.protocol === 1);
}

export async function withProviderAdmission(request, invoke, usageFromMessage) {
  if (!providerAdmissionEnabled(request)) return invoke();
  const client = requiredClient(request);
  const requestId = await client.reserve(request.model);
  let response;
  try { response = await invoke(); }
  catch (error) {
    await client.settle(requestId, undefined);
    throw error;
  }
  await client.settle(requestId, usageFromMessage(response).costUsd);
  return response;
}

class AdmissionClient {
  constructor(iterator) {
    this.iterator = iterator;
    this.pending = "";
    this.write = undefined;
  }

  async exchange(action) {
    requireProtocol(typeof this.write === "function");
    await this.write(`\x1e${JSON.stringify({ type: "provider_admission", action })}\n`);
    const line = await this.readLine();
    try { return JSON.parse(line); }
    catch { throw new BridgePublicError("bridge_internal"); }
  }

  async readLine() {
    for (;;) {
      const newline = this.pending.indexOf("\n");
      if (newline >= 0) return this.takeLine(newline);
      const next = await this.iterator.next();
      requireProtocol(!next.done);
      this.pending += next.value;
      requireProtocol(this.pending.length <= MAX_REPLY_CHARS);
    }
  }

  takeLine(newline) {
    const line = this.pending.slice(0, newline);
    this.pending = this.pending.slice(newline + 1);
    return line;
  }

  async reserve(model) {
    const reply = await this.exchange({ type: "reserve", model });
    if (reply?.type === "refused") throw new BridgePublicError("allowance_refused");
    requireProtocol(reply?.type === "admitted" && /^[a-f0-9-]{36}$/.test(reply.requestId ?? ""));
    return reply.requestId;
  }

  async settle(requestId, costUsd) {
    const reply = await this.exchange({ type: "settle", requestId, costUsd: costUsd ?? null });
    requireProtocol(reply?.type === "settled" && reply.requestId === requestId);
  }
}

function requiredClient(request) {
  const client = clients.get(request);
  requireProtocol(client !== undefined);
  return client;
}

function requireProtocol(condition) {
  if (!condition) throw new BridgePublicError("bridge_internal");
}

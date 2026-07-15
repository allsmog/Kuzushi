import { spawn, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { describe, expect, it } from "vitest";

const HOST = resolve("scripts/kuzushi-dynamic-module-host.mjs");
const PACKAGE_VERSION = JSON.parse(readFileSync(resolve("package.json"), "utf8")).version as string;

describe("KWP dynamic host context", () => {
  it("rejects a native process expecting a different host package version", () => {
    const result = spawnSync(process.execPath, [HOST, "serve", HOST], {
      encoding: "utf8",
      env: {
        ...process.env,
        KUZUSHI_DYNAMIC_HOST_PROTOCOL_VERSION: "1",
        KUZUSHI_HOST_VERSION: "0.0.0-stale-native",
      },
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("dynamic host version mismatch");
  });

  it("wraps a plain module with the canonical broker surface", async () => {
    const root = await mkdtemp(join(tmpdir(), "kuzushi-kwp-host-"));
    const modulePath = join(root, "module.mjs");
    await writeFile(modulePath, SMOKE_MODULE);
    try {
      const result = await runSmokeModule(modulePath);
      expect(result.initialize.hidden).toBe(false);
      expect(result.initialize.tools[0]?.prompts).toEqual([
        {
          role: "scan instructions",
          moduleId: "kwp-smoke",
          verb: "run",
          optionKey: "KWP_PROMPT",
          defaultContent: "Review the target.",
          contextNote: "Runtime context is appended separately.",
        },
      ]);
      expect(result.initialize.tools[0]?.options?.[1]).toMatchObject({
        name: "maxBytes",
        type: "int",
        minimum: 1024,
        maximum: 67108864,
      });
      expect(result.output).toEqual({
        aliases: ["symcc"],
        body: "network-body",
        bytesWritten: 5,
        mcp: true,
        publishedIsUndefined: true,
        runtimeText: "runtime-result",
      });
      expect(result.requests).toMatchObject([
        {
          method: "kuzushi/fs/write",
          params: { scope: "moduleData", dataBase64: "aGVsbG8=", epoch: 7 },
        },
        {
          method: "kuzushi/net/fetch",
          params: {
            url: "https://example.test/api",
            method: "POST",
            bodyBase64: "cGluZw==",
            epoch: 7,
          },
        },
        {
          method: "kuzushi/runtime/query",
          params: {
            request: { prompt: "inspect", system_prompt: "system", max_output_tokens: 32 },
            epoch: 7,
          },
        },
        {
          method: "kuzushi/mcp/call",
          params: { alias: "symcc", limits: { cpuSeconds: 1 }, epoch: 7 },
        },
        {
          method: "kuzushi/bus/publish",
          params: { topic: "smoke/result", epoch: 7 },
        },
      ]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

async function runSmokeModule(modulePath: string): Promise<SmokeResult> {
  const child = spawn(process.execPath, [HOST, "serve", modulePath], {
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      ...process.env,
      KUZUSHI_DYNAMIC_HOST_PROTOCOL_VERSION: "1",
      KUZUSHI_HOST_VERSION: PACKAGE_VERSION,
    },
  });
  const state: SmokeState = { initialize: null, requests: [] };
  const completion = deferred<SmokeResult>();
  const timeout = setTimeout(() => completion.reject(new Error("KWP host smoke timed out")), 5_000);
  createInterface({ input: child.stdout, crlfDelay: Infinity }).on("line", (line) => {
    const message = JSON.parse(line) as RpcMessage;
    handleWorkerMessage(message, child, state, completion);
  });
  child.once("error", completion.reject);
  send(child, initializeRequest());
  try {
    return await completion.promise;
  } finally {
    clearTimeout(timeout);
    child.kill();
  }
}

function handleWorkerMessage(
  message: RpcMessage,
  child: ReturnType<typeof spawn>,
  state: SmokeState,
  completion: Deferred<SmokeResult>,
): void {
  if (message.method) {
    state.requests.push(message as BrokerRequest);
    send(child, brokerResponse(message));
    return;
  }
  if (message.id === 1 && message.result) {
    state.initialize = message.result as SmokeInitialize;
    send(child, toolCallRequest());
    return;
  }
  if (message.id === 2 && message.result) {
    const output = JSON.parse(String((message.result as { output: string }).output));
    if (!state.initialize) {
      completion.reject(new Error("KWP host omitted initialize result"));
      return;
    }
    completion.resolve({ initialize: state.initialize, output, requests: state.requests });
  }
}

function initializeRequest(): RpcMessage {
  return {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { _kuzushi: { grant: { mcp: [{ alias: "symcc", tools: ["compile"] }] } } },
  };
}

function toolCallRequest(): RpcMessage {
  return {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: {
      name: "kwp-smoke:run",
      arguments: {},
      _kuzushi: { invocationId: "inv-smoke", runId: "run-smoke", epoch: 7 },
      context: {
        cwd: "/tmp/host-owned-cwd",
        config: { model: "host-owned-model" },
        kwp: { invocationId: "inv-smoke", runId: "run-smoke", epoch: 7 },
      },
    },
  };
}

function brokerResponse(request: RpcMessage): RpcMessage {
  const resultByMethod: Record<string, unknown> = {
    "kuzushi/fs/write": { bytesWritten: 5 },
    "kuzushi/net/fetch": {
      status: 200,
      headers: { "content-type": "text/plain" },
      bodyBase64: "bmV0d29yay1ib2R5",
    },
    "kuzushi/runtime/query": { text: "runtime-result", truncated: false },
    "kuzushi/mcp/call": { structuredContent: { ok: true }, artifacts: [] },
    "kuzushi/bus/publish": { published: true },
  };
  return { jsonrpc: "2.0", id: request.id, result: resultByMethod[request.method ?? ""] };
}

function send(child: ReturnType<typeof spawn>, message: RpcMessage): void {
  child.stdin?.write(`${JSON.stringify(message)}\n`);
}

interface RpcMessage {
  jsonrpc: "2.0";
  id?: string | number;
  method?: string;
  params?: Record<string, unknown>;
  result?: unknown;
}

interface BrokerRequest extends RpcMessage {
  method: string;
  params: Record<string, unknown>;
}

interface SmokeResult {
  initialize: SmokeInitialize;
  output: Record<string, unknown>;
  requests: BrokerRequest[];
}

interface SmokeState {
  initialize: SmokeInitialize | null;
  requests: BrokerRequest[];
}

interface SmokeInitialize {
  hidden: boolean;
  tools: Array<{ options?: unknown[]; prompts?: unknown[] }>;
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(error: Error): void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

const SMOKE_MODULE = `
export default {
  id: "kwp-smoke",
  name: "KWP Smoke",
  kind: "internal",
  description: "Exercise the host-owned KWP context.",
  tools: [{
    name: "kwp-smoke:run",
    description: "Exercise broker handles.",
    headless: true,
    runtimeRequirement: "always",
    phase: "hunt",
    effect: "workspace-write",
    approval: "none",
    workspaceRequirement: "required",
    options: [{
      name: "KWP_PROMPT",
      type: "string",
      description: "Editable instructions.",
    }, {
      name: "maxBytes",
      type: "int",
      description: "Maximum bytes.",
      minimum: 1024,
      maximum: 67108864,
    }],
    prompts: [{
      role: "scan instructions",
      moduleId: "kwp-smoke",
      verb: "run",
      optionKey: "KWP_PROMPT",
      defaultContent: "Review the target.",
      contextNote: "Runtime context is appended separately.",
    }],
    inputSchema: { type: "object", additionalProperties: false, properties: {} },
    async run(_input, ctx) {
      if (!ctx.mcp.has("symcc") || ctx.mcp.has("missing")) throw new Error("MCP grant state drifted");
      const bytesWritten = await ctx.fs.writeText("moduleData", "plan.txt", "hello");
      const response = await ctx.net.fetch({
        url: "https://example.test/api",
        method: "POST",
        body: "ping",
      });
      const runtime = await ctx.runtime.query({
        prompt: "inspect",
        systemPrompt: "system",
        maxOutputTokens: 32,
      });
      const mcp = await ctx.mcp.call("symcc", "compile", {}, { limits: { cpuSeconds: 1 } });
      const published = await ctx.bus.publish("smoke/result", { ok: true });
      return {
        status: "completed",
        output: JSON.stringify({
          aliases: ctx.mcp.grantedAliases(),
          body: new TextDecoder().decode(await response.body()),
          bytesWritten,
          mcp: mcp.structuredContent.ok,
          publishedIsUndefined: published === undefined,
          runtimeText: runtime.text,
        }),
      };
    },
  }],
};
`;

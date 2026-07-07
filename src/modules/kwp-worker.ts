import { createInterface } from "node:readline";
import type {
  KwpMcpExecutionContext,
  McpCallOptions,
  McpCallResult,
  McpHandle,
} from "./kwp-mcp.js";
import type {
  CopilotModule,
  ExecutionContext,
  ModuleContext,
  ModuleTool,
  ToolResult,
} from "./types.js";

export const KWP_VERSION = "0.1.0";

export interface KwpWorkerOptions {
  mode?: "serve" | "probe";
  connection?: JsonRpcConnection;
}

export interface KwpFsHandle {
  read(
    scope: KwpFsScope,
    path: string,
    opts?: { offset?: number; length?: number },
  ): Promise<Uint8Array>;
  write(
    scope: KwpFsScope,
    path: string,
    data: Uint8Array | string,
    opts?: { append?: boolean },
  ): Promise<number>;
  list(
    scope: KwpFsScope,
    path: string,
  ): Promise<Array<{ name: string; kind: "file" | "dir"; size: number }>>;
  stat(
    scope: KwpFsScope,
    path: string,
  ): Promise<{ kind: "file" | "dir"; size: number; mtime: number }>;
  remove(scope: KwpFsScope, path: string): Promise<void>;
}

export type KwpFsScope = "workspace" | "moduleData" | "input";

export interface KwpNetHandle {
  fetch(
    url: string,
    init?: {
      method?: string;
      headers?: Record<string, string>;
      body?: Uint8Array | string;
      timeoutMs?: number;
    },
  ): Promise<KwpBrokeredResponse>;
}

export interface KwpRuntimeHandle {
  query(request: KwpRuntimeQuery): Promise<KwpRuntimeCompletion>;
}

export interface KwpBusHandle {
  publish(topic: string, payload: unknown): Promise<void>;
}

export interface KwpFuzzHandle {
  run(request: KwpFuzzRunRequest): Promise<KwpFuzzRunResult>;
}

export interface KwpWorkerExecutionContext extends KwpMcpExecutionContext {
  readonly invocationId: string;
  readonly runId: string;
  readonly signal: AbortSignal;
  readonly fs: KwpFsHandle;
  readonly net: KwpNetHandle;
  readonly kwpRuntime: KwpRuntimeHandle;
  readonly kwpBus: KwpBusHandle;
  readonly fuzz?: KwpFuzzHandle;
}

export interface KwpBrokeredResponse {
  status: number;
  headers: Record<string, string>;
  body(): Promise<Uint8Array>;
  artifactPath?: string;
}

export interface KwpRuntimeQuery {
  messages: Array<{ role: "user" | "assistant"; content: Array<{ type: "text"; text: string }> }>;
  systemPrompt?: string;
  maxTokens: number;
  modelPreferences?: { hints?: Array<{ name: string }> };
}

export interface KwpRuntimeCompletion {
  content: Array<{ type: "text"; text: string }>;
  stopReason?: string;
}

export interface KwpFuzzRunRequest {
  engine: string;
  target: { language: string; projectPath: string; harnessPath: string };
  inputs?: Record<string, string>;
  limits?: {
    deadlineMs?: number;
    cpuSeconds?: number;
    memoryBytes?: number;
    artifactBytes?: number;
    maxCrashes?: number;
  };
  sandbox?: { network?: boolean; readOnlySource?: boolean };
}

export interface KwpFuzzRunResult {
  status: string;
  artifacts?: Array<{ path: string; mediaType: string; sha256?: string }>;
  crashes?: unknown[];
}

export interface JsonRpcConnection {
  onInbound(handler: (message: RpcInbound) => void): void;
  request(method: string, params: unknown): Promise<unknown>;
  notify(method: string, params: unknown): void;
  reply(id: RpcId, result: unknown): void;
  replyError(id: RpcId, code: number, message: string): void;
  close(): void;
}

type RpcId = string | number;

type RpcInbound =
  | { kind: "request"; id: RpcId; method: string; params: unknown }
  | { kind: "notification"; method: string; params: unknown };

interface LiveInvocation {
  invocationId: string;
  runId: string;
  epoch: number;
  abort: AbortController;
  settled: boolean;
}

export async function runWorker(
  module: CopilotModule,
  options: KwpWorkerOptions = {},
): Promise<void> {
  const mode = options.mode ?? (process.env.KWP_WORKER_MODE === "probe" ? "probe" : "serve");
  const connection = options.connection ?? new StdioJsonRpcConnection();
  await new KwpWorkerHarness(module, connection).serve(mode);
}

export class KwpWorkerHarness {
  private grant: KwpGrantView = new KwpGrantView({});
  private limits: { maxConcurrentInvocations?: number } = {};
  private live = new Map<string, LiveInvocation>();
  private done = false;

  constructor(
    private readonly module: CopilotModule,
    private readonly connection: JsonRpcConnection,
  ) {}

  async serve(mode: "serve" | "probe"): Promise<void> {
    this.connection.onInbound((message) => this.dispatch(mode, message));
    await new Promise<void>((resolve) => {
      const tick = () => (this.done ? resolve() : setTimeout(tick, 50));
      tick();
    });
  }

  private dispatch(mode: "serve" | "probe", message: RpcInbound): void {
    if (message.kind === "notification") {
      if (message.method === "notifications/cancelled") this.cancel(message.params);
      return;
    }
    switch (message.method) {
      case "initialize":
        void this.initialize(message.id, message.params);
        break;
      case "kuzushi/module/init":
        void this.moduleInit(message.id, message.params);
        break;
      case "kuzushi/module/ready":
        this.connection.reply(message.id, {});
        break;
      case "tools/call":
        if (mode === "probe")
          this.connection.replyError(message.id, -32601, "tools/call is disabled in probe mode");
        else void this.toolCall(message.id, message.params);
        break;
      case "shutdown":
        void this.shutdown(message.id);
        break;
      default:
        this.connection.replyError(message.id, -32601, "method not found");
    }
  }

  private async initialize(id: RpcId, params: unknown): Promise<void> {
    const p = params as {
      grant?: unknown;
      limits?: { maxConcurrentInvocations?: number };
      _kuzushi?: { grant?: unknown; limits?: { maxConcurrentInvocations?: number } };
    };
    this.grant = new KwpGrantView(p._kuzushi?.grant ?? p.grant ?? {});
    this.limits = p._kuzushi?.limits ?? p.limits ?? {};
    for (const topic of this.module.events?.produces ?? []) {
      if (!this.grant.canProduce(topic)) {
        this.connection.replyError(id, -32031, `not granted to produce ${topic}`);
        return;
      }
    }
    this.connection.reply(id, {
      protocolVersion: KWP_VERSION,
      module: {
        id: this.module.id,
        displayName: this.module.displayName,
        version: this.module.version,
        category: this.module.category,
        description: this.module.description,
        tools: this.module.tools.map((tool) => describeTool(tool)),
        events: this.module.events ?? {},
      },
      concurrency: Math.min(this.limits.maxConcurrentInvocations ?? 1, 1),
    });
  }

  private async moduleInit(id: RpcId, params: unknown): Promise<void> {
    try {
      await this.module.init?.(
        (params as { config?: Record<string, unknown> })?.config ?? {},
        this.moduleContext({}),
      );
      this.connection.reply(id, {});
    } catch (error) {
      this.connection.replyError(id, -32037, messageOf(error));
    }
  }

  private async toolCall(id: RpcId, params: unknown): Promise<void> {
    const p = params as {
      name: string;
      arguments?: unknown;
      _kuzushi?: { invocationId: string; runId: string; epoch: number };
    };
    const tool = this.module.tools.find((candidate) => candidate.name === p.name);
    if (!tool) {
      this.connection.replyError(id, -32602, `unknown tool ${p.name}`);
      return;
    }
    const k = p._kuzushi;
    if (!k?.invocationId) {
      this.connection.replyError(id, -32602, "tools/call omitted _kuzushi.invocationId");
      return;
    }
    const live: LiveInvocation = {
      invocationId: k.invocationId,
      runId: k.runId,
      epoch: k.epoch,
      abort: new AbortController(),
      settled: false,
    };
    this.live.set(live.invocationId, live);
    try {
      const result = await tool.execute(p.arguments, this.executionContext(live));
      this.connection.reply(id, normalizeToolResult(result));
    } catch (error) {
      this.connection.reply(id, {
        ok: false,
        output: "",
        error: {
          kind:
            error instanceof KwpDenied ? "denied" : live.abort.signal.aborted ? "timeout" : "fatal",
          message: messageOf(error),
        },
      });
    } finally {
      live.settled = true;
      this.live.delete(live.invocationId);
    }
  }

  private cancel(params: unknown): void {
    const invocationId =
      (params as { invocationId?: string; requestId?: string }).invocationId ??
      (params as { requestId?: string }).requestId;
    if (!invocationId) return;
    const live = this.live.get(invocationId);
    if (!live) return;
    live.settled = true;
    live.abort.abort((params as { reason?: string }).reason ?? "cancelled");
  }

  private async shutdown(id: RpcId): Promise<void> {
    try {
      await this.module.dispose?.();
      this.connection.reply(id, {});
    } catch (error) {
      this.connection.replyError(id, -32603, messageOf(error));
    } finally {
      this.done = true;
      this.connection.close();
    }
  }

  private executionContext(live: LiveInvocation): ExecutionContext {
    const request = async (method: string, params: Record<string, unknown>) => {
      if (live.settled) throw new KwpDenied(-32030, method, "invocation already settled");
      return await this.connection.request(method, { invocationId: live.invocationId, ...params });
    };
    const ctx = {
      ...this.moduleContext({}),
      cwd: ".",
      invocationId: live.invocationId,
      runId: live.runId,
      signal: live.abort.signal,
      runtime: {
        query: (query: unknown) =>
          request("kuzushi/runtime/query", query as Record<string, unknown>),
      } as unknown as ExecutionContext["runtime"],
      bus: {
        publish: (topic: string, payload?: unknown) =>
          request("kuzushi/bus/publish", { topic, payload }),
      } as unknown as ExecutionContext["bus"],
      config: {} as unknown as ExecutionContext["config"],
      fs: this.fsHandle(request),
      net: this.netHandle(request),
      kwpRuntime: {
        query: (query: KwpRuntimeQuery) =>
          request(
            "kuzushi/runtime/query",
            query as unknown as Record<string, unknown>,
          ) as Promise<KwpRuntimeCompletion>,
      },
      kwpBus: {
        publish: (topic: string, payload: unknown) =>
          request("kuzushi/bus/publish", { topic, payload }).then(() => undefined),
      },
      mcp: this.mcpHandle(request),
      fuzz: {
        run: (fuzz: KwpFuzzRunRequest) =>
          request(
            "kuzushi/fuzz/run",
            fuzz as unknown as Record<string, unknown>,
          ) as Promise<KwpFuzzRunResult>,
      },
      reportActivity: (message: string, meta?: unknown) => {
        if (!live.settled)
          this.connection.notify("kuzushi/activity", {
            invocationId: live.invocationId,
            message,
            meta,
          });
      },
      reportOutput: (chunk: string) => {
        if (!live.settled)
          this.connection.notify("kuzushi/output", { invocationId: live.invocationId, chunk });
      },
    } satisfies Partial<KwpWorkerExecutionContext>;
    return ctx as unknown as ExecutionContext;
  }

  private moduleContext(config: Record<string, unknown>): ModuleContext {
    return {
      runtime: {
        query: async () => {
          throw new KwpDenied(-32030, "runtime", "runtime is unavailable outside an invocation");
        },
      },
      bus: {
        publish: async () => {},
        subscribe: () => () => {},
        unsubscribe: () => {},
        waitFor: async () => undefined,
        close: () => {},
      },
      config: config as never,
      dataDir: ".",
    } as unknown as ModuleContext;
  }

  private fsHandle(
    request: (method: string, params: Record<string, unknown>) => Promise<unknown>,
  ): KwpFsHandle {
    return {
      read: async (scope, path, opts) =>
        decodeBase64(
          (await request("kuzushi/fs/read", { scope, path, ...opts })) as { data: string },
        ),
      write: async (scope, path, data, opts) =>
        (
          (await request("kuzushi/fs/write", {
            scope,
            path,
            data: encodeBase64(data),
            ...opts,
          })) as { bytesWritten: number }
        ).bytesWritten,
      list: async (scope, path) =>
        (
          (await request("kuzushi/fs/list", { scope, path })) as {
            entries: Array<{ name: string; kind: "file" | "dir"; size: number }>;
          }
        ).entries,
      stat: async (scope, path) =>
        (await request("kuzushi/fs/stat", { scope, path })) as {
          kind: "file" | "dir";
          size: number;
          mtime: number;
        },
      remove: async (scope, path) => void (await request("kuzushi/fs/remove", { scope, path })),
    };
  }

  private netHandle(
    request: (method: string, params: Record<string, unknown>) => Promise<unknown>,
  ): KwpNetHandle {
    return {
      fetch: async (url, init) => {
        const result = (await request("kuzushi/net/fetch", {
          url,
          ...init,
          body: init?.body ? encodeBase64(init.body) : undefined,
        })) as {
          status: number;
          headers: Record<string, string>;
          body?: string;
          artifactPath?: string;
        };
        return {
          status: result.status,
          headers: result.headers,
          body: async () => decodeBase64({ data: result.body ?? "" }),
          artifactPath: result.artifactPath,
        };
      },
    };
  }

  private mcpHandle(
    request: (method: string, params: Record<string, unknown>) => Promise<unknown>,
  ): McpHandle {
    return {
      has: (alias) => this.grant.hasMcp(alias),
      grantedAliases: () => this.grant.mcpAliases(),
      call: async <TStructured>(
        alias: string,
        tool: string,
        arguments_: Record<string, unknown>,
        options?: McpCallOptions,
      ) => {
        if (!this.grant.hasMcp(alias))
          throw new KwpDenied(-32031, "mcp", `MCP alias ${alias} is not granted`);
        return (await request("kuzushi/mcp/call", {
          alias,
          tool,
          arguments: arguments_,
          limits: options?.limits,
        })) as McpCallResult<TStructured>;
      },
    };
  }
}

class KwpGrantView {
  constructor(private readonly grant: unknown) {}

  canProduce(topic: string): boolean {
    return this.patterns("bus", "produce").some((pattern) => topicMatches(pattern, topic));
  }

  hasMcp(alias: string): boolean {
    return this.mcpAliases().includes(alias);
  }

  mcpAliases(): string[] {
    const mcp = (this.grant as { mcp?: Array<{ alias?: string }> })?.mcp ?? [];
    return mcp
      .map((entry) => entry.alias)
      .filter((alias): alias is string => typeof alias === "string");
  }

  private patterns(key: "bus", subkey: "produce" | "consume"): string[] {
    const values =
      (this.grant as { bus?: { produce?: string[]; consume?: string[] } })?.[key]?.[subkey] ?? [];
    return values.filter((value): value is string => typeof value === "string");
  }
}

class KwpDenied extends Error {
  constructor(
    readonly code: number,
    readonly capability: string,
    message: string,
  ) {
    super(message);
    this.name = "KwpDenied";
  }
}

class StdioJsonRpcConnection implements JsonRpcConnection {
  private nextId = 1;
  private handler: ((message: RpcInbound) => void) | undefined;
  private pending = new Map<RpcId, { resolve(value: unknown): void; reject(error: Error): void }>();

  constructor() {
    createInterface({ input: process.stdin, crlfDelay: Infinity }).on("line", (line) =>
      this.receive(line),
    );
  }

  onInbound(handler: (message: RpcInbound) => void): void {
    this.handler = handler;
  }

  request(method: string, params: unknown): Promise<unknown> {
    const id = this.nextId++;
    this.write({ jsonrpc: "2.0", id, method, params });
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
  }

  notify(method: string, params: unknown): void {
    this.write({ jsonrpc: "2.0", method, params });
  }

  reply(id: RpcId, result: unknown): void {
    this.write({ jsonrpc: "2.0", id, result });
  }

  replyError(id: RpcId, code: number, message: string): void {
    this.write({ jsonrpc: "2.0", id, error: { code, message } });
  }

  close(): void {
    for (const { reject } of this.pending.values()) reject(new Error("connection closed"));
    this.pending.clear();
  }

  private receive(line: string): void {
    const message = JSON.parse(line) as {
      id?: RpcId;
      method?: string;
      params?: unknown;
      result?: unknown;
      error?: { code: number; message: string };
    };
    if (message.id !== undefined && ("result" in message || "error" in message)) {
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      if (message.error)
        pending.reject(
          Object.assign(new Error(message.error.message), { code: message.error.code }),
        );
      else pending.resolve(message.result);
      return;
    }
    if (!message.method) return;
    if (message.id !== undefined)
      this.handler?.({
        kind: "request",
        id: message.id,
        method: message.method,
        params: message.params,
      });
    else this.handler?.({ kind: "notification", method: message.method, params: message.params });
  }

  private write(message: unknown): void {
    process.stdout.write(`${JSON.stringify(message)}\n`);
  }
}

function describeTool(tool: ModuleTool): Record<string, unknown> {
  return {
    name: tool.name,
    description: tool.description,
    inputSchema: tool.inputSchema,
    headless: tool.headless,
    hidden: tool.hidden ?? false,
    rank: tool.rank,
    dag: "dag" in tool ? (tool as unknown as { dag?: unknown }).dag : undefined,
  };
}

function normalizeToolResult(result: ToolResult): ToolResult {
  const copy = { ...result } as ToolResult & { costUsd?: number };
  delete copy.costUsd;
  return copy;
}

function encodeBase64(data: Uint8Array | string): string {
  return Buffer.from(typeof data === "string" ? new TextEncoder().encode(data) : data).toString(
    "base64",
  );
}

function decodeBase64(response: { data?: string }): Uint8Array {
  return new Uint8Array(Buffer.from(response.data ?? "", "base64"));
}

function topicMatches(pattern: string, topic: string): boolean {
  if (pattern === topic) return true;
  const prefix = pattern.endsWith("/*") ? pattern.slice(0, -1) : undefined;
  return prefix ? topic.startsWith(prefix) : false;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Minimal MCP (Model Context Protocol) bridge for loading tools from MCP servers.
 *
 * Supports stdio transport: spawns the MCP server as a child process and
 * communicates via JSON-RPC over stdin/stdout.
 *
 * Wraps each MCP tool as a Kuzushi ModuleTool, making MCP servers loadable
 * as copilot modules.
 */

import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createInterface } from "node:readline";
import { isRecord } from "../utils.js";
import { formatToolInputValidationError, validateToolInput } from "./input-validation.js";
import { createProblemDetails, ProblemCode, problemToolResult } from "./problem-details.js";
import type { CopilotModule, ExecutionContext, ModuleTool, ToolResult } from "./types.js";

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: string;
  method: string;
  params?: Record<string, unknown>;
}

/**
 * Tool definition as advertised by `tools/list` on an MCP server.
 *
 * Per MCP spec 2025-03-26 / 2025-06-18, `inputSchema` is a JSON Schema object
 * with `type: "object"`. `annotations` is an optional bag of hints the server
 * may advertise — `readOnlyHint` / `destructiveHint` / `idempotentHint` /
 * `openWorldHint` per the `ToolAnnotationsSchema` in the `@modelcontextprotocol/sdk`
 * package. All annotations are advisory — the MCP spec states clients should
 * not make trust decisions purely on annotations from untrusted servers.
 */
interface McpToolDefinition {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  annotations?: {
    title?: string;
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  };
}

interface McpToolResult {
  content: Array<{ type: string; text?: string }>;
  isError?: boolean;
}

/**
 * Options controlling how an MCP server is bridged into a CopilotModule.
 */
export interface CreateMcpModuleOptions {
  /**
   * Per-tool-call timeout in milliseconds. Applies to `tools/call` RPCs and to
   * the underlying transport request. Defaults to 60_000 (60 s). Use `0` to
   * disable the bridge-level timeout (transport-level timeouts may still apply).
   */
  timeoutMs?: number;
  /**
   * Bearer token sent as `Authorization: Bearer <token>` on every HTTP request
   * to the MCP server (HTTP transport only). If unset, falls back to the
   * `KUZUSHI_MCP_TOKEN` environment variable.
   */
  authToken?: string;
  /**
   * When true, MCP tools are bridged with `headless: true` by default, even
   * when the server doesn't advertise `readOnlyHint: true` (or does advertise
   * `destructiveHint: true`). The default (false) is safer: untrusted MCP
   * servers cannot automatically have their tools scheduled by `kuzushi run`
   * / the DAG pipeline. See docs/mcp-server-requirements.md §5 for details.
   */
  trustHeadless?: boolean;
  /**
   * Optional logger for non-fatal diagnostics — invalid schemas, malformed
   * annotations, etc. Defaults to no-op. Passing `console` works.
   */
  logger?: { warn(msg: string): void };
}

const DEFAULT_MCP_TIMEOUT_MS = 60_000;

/**
 * Connect to an MCP server and wrap its tools as a CopilotModule.
 *
 * @param serverSpec — Either a URL (http://...) for streamable HTTP or a
 *   command string for stdio. Stdio format: `"npx @some/mcp-server"` or
 *   `"python mcp_server.py"`.
 * @param moduleId — The module ID to assign (e.g. `"pentest"`, `"mcp-tools"`).
 * @param options — Optional bridge tuning — auth, timeouts, headless trust.
 */
export async function createMcpModule(
  serverSpec: string,
  moduleId: string,
  options: CreateMcpModuleOptions = {},
): Promise<{ module: CopilotModule; dispose: () => void }> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_MCP_TIMEOUT_MS;
  const authToken = options.authToken ?? process.env.KUZUSHI_MCP_TOKEN;
  const trustHeadless = options.trustHeadless === true;
  const logger = options.logger ?? { warn: () => {} };

  const client: McpClient =
    serverSpec.startsWith("http://") || serverSpec.startsWith("https://")
      ? new HttpMcpClient(serverSpec, { timeoutMs, authToken })
      : new StdioMcpClient(serverSpec, { timeoutMs });
  await client.initialize();

  const mcpTools = await client.listTools();

  const tools: ModuleTool[] = mcpTools.map((mcpTool) =>
    bridgeTool(mcpTool, moduleId, client, {
      timeoutMs,
      trustHeadless,
      logger,
    }),
  );

  const module: CopilotModule = {
    id: moduleId,
    displayName: `MCP: ${moduleId}`,
    category: "offense",
    version: "0.0.0",
    description: `MCP server module (${serverSpec}). ${tools.length} tools.`,
    tools,
    async dispose() {
      client.close();
    },
  };

  return {
    module,
    dispose: () => client.close(),
  };
}

// ---------------------------------------------------------------------------
// Tool bridging
// ---------------------------------------------------------------------------

/**
 * Bridge a single MCP `McpToolDefinition` to a Kuzushi `ModuleTool`.
 *
 * Exported for tests — the bridge is pure given an `McpClient`-shaped caller.
 */
export function bridgeTool(
  mcpTool: McpToolDefinition,
  moduleId: string,
  client: Pick<McpClient, "callTool">,
  opts: {
    timeoutMs: number;
    trustHeadless: boolean;
    logger: { warn(msg: string): void };
  },
): ModuleTool {
  const { schema, schemaValid } = normalizeInputSchema(
    mcpTool.inputSchema,
    `${moduleId}:${mcpTool.name}`,
    opts.logger,
  );
  const headless = decideHeadless({
    annotations: mcpTool.annotations,
    schemaValid,
    trustHeadless: opts.trustHeadless,
  });

  return {
    name: `${moduleId}:${mcpTool.name}`,
    description: mcpTool.description ?? `MCP tool: ${mcpTool.name}`,
    inputSchema: schema,
    headless,
    async execute(input: unknown, _ctx: ExecutionContext): Promise<ToolResult> {
      const validation = validateToolInput(input, schema);
      if (!validation.ok) {
        const detail = formatToolInputValidationError(
          `${moduleId}:${mcpTool.name}`,
          validation.issues,
        );
        return problemToolResult(
          createProblemDetails({
            code: ProblemCode.InputValidationFailed,
            title: "MCP tool input validation failed",
            status: 400,
            detail,
            instance: `${moduleId}:${mcpTool.name}`,
            errors: validation.issues.map((issue) => ({
              path: issue.path,
              message: issue.message,
            })),
          }),
        );
      }
      try {
        const result = await callWithTimeout(
          () => client.callTool(mcpTool.name, coerceArguments(input)),
          opts.timeoutMs,
          `MCP tool "${mcpTool.name}" timed out after ${opts.timeoutMs}ms`,
        );
        const output = stringifyToolContent(result);
        return { ok: !result.isError, output: output || "(no output)" };
      } catch (err) {
        return {
          ok: false,
          output: `MCP tool error: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    },
  };
}

/**
 * Deep-clone an MCP tool's `inputSchema` verbatim, preserving `required`,
 * `additionalProperties`, nested object / array schemas, and enum constraints.
 *
 * If the schema is missing, non-object, or doesn't declare `type: "object"` at
 * the top level, fall back to an empty-object schema and return
 * `schemaValid: false` — callers use that signal to avoid marking the tool as
 * `headless` (we can't trust the tool's input surface).
 */
export function normalizeInputSchema(
  raw: unknown,
  qualifiedName: string,
  logger: { warn(msg: string): void },
): { schema: Record<string, unknown>; schemaValid: boolean } {
  if (raw === undefined || raw === null) {
    return { schema: { type: "object", properties: {} }, schemaValid: false };
  }
  if (typeof raw !== "object" || Array.isArray(raw)) {
    logger.warn(
      `MCP tool "${qualifiedName}" advertises a non-object inputSchema; ` +
        `substituting empty object schema.`,
    );
    return { schema: { type: "object", properties: {} }, schemaValid: false };
  }
  const obj = raw as Record<string, unknown>;
  if (obj.type !== "object") {
    logger.warn(
      `MCP tool "${qualifiedName}" inputSchema.type is "${String(obj.type)}" ` +
        `(expected "object"); substituting empty object schema.`,
    );
    return { schema: { type: "object", properties: {} }, schemaValid: false };
  }
  // Deep clone to avoid shared-reference mutations across repeated tool calls.
  return { schema: deepClone(obj), schemaValid: true };
}

/**
 * Pick a `headless` value for a bridged tool. MCP annotations are advisory and
 * not universally present, so:
 *
 * 1. If `trustHeadless: true`, default to true unless the server explicitly
 *    says `destructiveHint: true` without also saying `readOnlyHint: true`.
 * 2. Otherwise, headless is true ONLY when `readOnlyHint: true` AND
 *    `destructiveHint !== true`. All other cases are non-headless (safer).
 * 3. Tools with a malformed schema are always non-headless — we cannot
 *    reason about their input surface.
 */
export function decideHeadless(args: {
  annotations?: McpToolDefinition["annotations"];
  schemaValid: boolean;
  trustHeadless: boolean;
}): boolean {
  if (!args.schemaValid) return false;
  const a = args.annotations ?? {};
  if (args.trustHeadless) {
    // Operator has opted in. Still respect an explicit destructive hint.
    if (a.destructiveHint === true && a.readOnlyHint !== true) return false;
    return true;
  }
  return a.readOnlyHint === true && a.destructiveHint !== true;
}

function coerceArguments(input: unknown): Record<string, unknown> {
  if (input && typeof input === "object" && !Array.isArray(input)) {
    return input as Record<string, unknown>;
  }
  // Should be unreachable after schema validation. Preserve a closed payload
  // instead of inventing an implicit `{ value }` wire contract.
  return {};
}

function stringifyToolContent(result: McpToolResult): string {
  if (!result || !Array.isArray(result.content)) {
    // Non-spec response shape. Stringify whatever we got so we don't drop it.
    try {
      return JSON.stringify(result);
    } catch {
      return String(result);
    }
  }
  const parts: string[] = [];
  for (const chunk of result.content) {
    if (chunk == null) continue;
    if (chunk.type === "text" && typeof chunk.text === "string") {
      parts.push(chunk.text);
      continue;
    }
    // Spec allows `image`, `resource`, etc. content types. Render a
    // best-effort JSON fallback so operators at least see something.
    try {
      parts.push(JSON.stringify(chunk));
    } catch {
      parts.push(String(chunk));
    }
  }
  return parts.join("\n");
}

function parseToolsListResult(result: unknown): McpToolDefinition[] {
  if (!isRecord(result)) {
    throw new Error("MCP tools/list returned a non-object result.");
  }
  if (result.tools === undefined) return [];
  if (!Array.isArray(result.tools)) {
    throw new Error("MCP tools/list returned an invalid tools array.");
  }
  return result.tools.map((tool, index) => parseMcpToolDefinition(tool, index));
}

function parseMcpToolDefinition(tool: unknown, index: number): McpToolDefinition {
  if (!isRecord(tool) || typeof tool.name !== "string" || tool.name.length === 0) {
    throw new Error(`MCP tools/list returned an invalid tool at index ${index}.`);
  }
  return {
    name: tool.name,
    ...(typeof tool.description === "string" ? { description: tool.description } : {}),
    ...(isRecord(tool.inputSchema) ? { inputSchema: { ...tool.inputSchema } } : {}),
    ...(isRecord(tool.annotations)
      ? { annotations: parseMcpToolAnnotations(tool.annotations) }
      : {}),
  };
}

function parseMcpToolAnnotations(
  annotations: Record<string, unknown>,
): McpToolDefinition["annotations"] {
  return {
    ...(typeof annotations.title === "string" ? { title: annotations.title } : {}),
    ...(typeof annotations.readOnlyHint === "boolean"
      ? { readOnlyHint: annotations.readOnlyHint }
      : {}),
    ...(typeof annotations.destructiveHint === "boolean"
      ? { destructiveHint: annotations.destructiveHint }
      : {}),
    ...(typeof annotations.idempotentHint === "boolean"
      ? { idempotentHint: annotations.idempotentHint }
      : {}),
    ...(typeof annotations.openWorldHint === "boolean"
      ? { openWorldHint: annotations.openWorldHint }
      : {}),
  };
}

function parseMcpToolResult(result: unknown, toolName: string): McpToolResult {
  if (!isRecord(result)) {
    throw new Error(`MCP tool "${toolName}" returned a non-object result.`);
  }
  if (!Array.isArray(result.content)) {
    throw new Error(`MCP tool "${toolName}" returned an invalid content array.`);
  }
  return {
    content: result.content.map((item, index) => parseMcpContentItem(item, toolName, index)),
    ...(typeof result.isError === "boolean" ? { isError: result.isError } : {}),
  };
}

function parseMcpContentItem(
  item: unknown,
  toolName: string,
  index: number,
): McpToolResult["content"][number] {
  if (!isRecord(item) || typeof item.type !== "string") {
    throw new Error(`MCP tool "${toolName}" returned invalid content at index ${index}.`);
  }
  return {
    type: item.type,
    ...(typeof item.text === "string" ? { text: item.text } : {}),
  };
}

function deepClone<T>(value: T): T {
  if (typeof structuredClone === "function") {
    return structuredClone(value);
  }
  // Fallback for ancient runtimes; Node 22 always has structuredClone but the
  // project targets >=22 so this is effectively unreachable.
  return JSON.parse(JSON.stringify(value)) as T;
}

async function callWithTimeout<T>(
  fn: () => Promise<T>,
  timeoutMs: number,
  message: string,
): Promise<T> {
  if (timeoutMs <= 0) return fn();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race<T>([
      fn(),
      new Promise<T>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(message)), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// MCP client transports
// ---------------------------------------------------------------------------

/** Shared shape implemented by both transports. */
export interface McpClient {
  initialize(): Promise<void>;
  listTools(): Promise<McpToolDefinition[]>;
  callTool(name: string, args: Record<string, unknown>): Promise<McpToolResult>;
  close(): void;
}

interface HttpClientOptions {
  timeoutMs: number;
  authToken?: string;
}

/**
 * HTTP MCP client (Streamable HTTP transport per MCP spec 2025-03-26).
 *
 * Sends JSON-RPC requests as POST bodies. The server chooses response
 * encoding based on the Accept header — this client accepts both
 * `application/json` (single response) and `text/event-stream` (streamed
 * responses / server notifications). The final matching response by `id`
 * is returned; SSE framing is parsed inline.
 *
 * Session tracking: if the server returns `Mcp-Session-Id` during
 * initialize, it is echoed on every subsequent request.
 *
 * Auth: if `authToken` is provided (or `KUZUSHI_MCP_TOKEN` is set), it's
 * sent as `Authorization: Bearer <token>` on every request.
 */
class HttpMcpClient implements McpClient {
  private sessionId: string | null = null;
  private initialized = false;
  private closed = false;

  constructor(
    private readonly url: string,
    private readonly opts: HttpClientOptions,
  ) {}

  async initialize(): Promise<void> {
    const result = await this.sendRequest("initialize", {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "kuzushi", version: "0.17.0" },
    });
    // MCP initialize response: { protocolVersion, capabilities, serverInfo }
    if (!result || typeof result !== "object") {
      throw new Error("MCP server did not return a valid initialize response.");
    }
    // Fire-and-forget the initialized notification.
    await this.sendNotification("notifications/initialized", {});
    this.initialized = true;
  }

  async listTools(): Promise<McpToolDefinition[]> {
    if (!this.initialized) throw new Error("MCP client not initialized.");
    const result = await this.sendRequest("tools/list", {});
    return parseToolsListResult(result);
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<McpToolResult> {
    if (!this.initialized) throw new Error("MCP client not initialized.");
    const result = await this.sendRequest("tools/call", { name, arguments: args });
    return parseMcpToolResult(result, name);
  }

  close(): void {
    this.closed = true;
  }

  private async sendRequest(method: string, params: Record<string, unknown>): Promise<unknown> {
    if (this.closed) throw new Error("MCP client is closed.");
    const id = randomUUID();
    const body: JsonRpcRequest = { jsonrpc: "2.0", id, method, params };

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    };
    if (this.sessionId) headers["Mcp-Session-Id"] = this.sessionId;
    if (this.opts.authToken) headers.Authorization = `Bearer ${this.opts.authToken}`;

    const controller = new AbortController();
    const timeoutMs = this.opts.timeoutMs > 0 ? this.opts.timeoutMs : DEFAULT_MCP_TIMEOUT_MS;
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    let response: Response;
    try {
      response = await fetch(this.url, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }
    if (!response.ok) {
      throw new Error(`MCP HTTP ${method} failed: HTTP ${response.status}`);
    }

    const returnedSession = response.headers.get("Mcp-Session-Id");
    if (returnedSession) this.sessionId = returnedSession;

    const contentType = response.headers.get("content-type") ?? "";
    if (contentType.includes("application/json")) {
      const json = (await response.json()) as unknown;
      return parseJsonRpcResponse(json, id, method);
    }
    if (contentType.includes("text/event-stream")) {
      const text = await response.text();
      const matching = findMatchingSseResponse(text, id);
      if (!matching) {
        throw new Error(`MCP HTTP ${method}: no matching response for id ${id}`);
      }
      return parseJsonRpcResponse(matching, id, method);
    }
    throw new Error(`MCP HTTP ${method}: unexpected Content-Type "${contentType}"`);
  }

  private async sendNotification(method: string, params: Record<string, unknown>): Promise<void> {
    if (this.closed) return;
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.sessionId) headers["Mcp-Session-Id"] = this.sessionId;
    if (this.opts.authToken) headers.Authorization = `Bearer ${this.opts.authToken}`;
    try {
      await fetch(this.url, {
        method: "POST",
        headers,
        body: JSON.stringify({ jsonrpc: "2.0", method, params }),
      });
    } catch {
      // notifications are best-effort
    }
  }
}

function parseJsonRpcResponse(msg: unknown, expectedId: string, method: string): unknown {
  if (!isRecord(msg)) {
    throw new Error(`MCP HTTP ${method}: invalid JSON-RPC response envelope`);
  }
  if (msg.jsonrpc !== "2.0") {
    throw new Error(`MCP HTTP ${method}: invalid JSON-RPC version`);
  }
  if (msg.id !== expectedId) {
    throw new Error(
      `MCP HTTP ${method}: response id mismatch (${String(msg.id)} !== ${expectedId})`,
    );
  }
  const hasResult = "result" in msg;
  const hasError = "error" in msg;
  if (hasResult && hasError) {
    throw new Error(`MCP HTTP ${method}: response cannot include both result and error`);
  }
  if (!hasResult && !hasError) {
    throw new Error(`MCP HTTP ${method}: response must include result or error`);
  }
  if (hasError) {
    if (!isRecord(msg.error) || typeof msg.error.message !== "string") {
      throw new Error(`MCP HTTP ${method}: invalid JSON-RPC error object`);
    }
    throw new Error(msg.error.message);
  }
  return msg.result;
}

/**
 * Scan an SSE body for a `data:` frame whose parsed JSON-RPC response matches
 * the requested id. Returns null if nothing matches. Tolerates interleaved
 * notifications and comments.
 */
function findMatchingSseResponse(body: string, expectedId: string): unknown | null {
  for (const frame of body.split(/\n\n+/)) {
    const dataLines = frame
      .split("\n")
      .filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(5).trim());
    if (dataLines.length === 0) continue;
    const joined = dataLines.join("\n");
    try {
      const msg = JSON.parse(joined) as unknown;
      if (isRecord(msg) && msg.id === expectedId) return msg;
    } catch {
      // skip unparsable frame
    }
  }
  return null;
}

interface StdioClientOptions {
  timeoutMs: number;
}

/**
 * Minimal stdio MCP client — spawns a subprocess and communicates via JSON-RPC.
 */
class StdioMcpClient implements McpClient {
  private process: ReturnType<typeof spawn> | null = null;
  private pendingRequests = new Map<
    string,
    {
      resolve: (value: unknown) => void;
      reject: (reason: Error) => void;
    }
  >();
  private initialized = false;

  constructor(
    private readonly command: string,
    private readonly opts: StdioClientOptions,
  ) {}

  async initialize(): Promise<void> {
    const [cmd, ...args] = this.command.split(/\s+/);
    if (!cmd) throw new Error("Empty MCP server command.");

    this.process = spawn(cmd, args, {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env },
    });

    // Parse JSON-RPC responses from stdout
    const rl = createInterface({ input: this.process.stdout! });
    rl.on("line", (line) => {
      try {
        const msg = JSON.parse(line) as unknown;
        if (isRecord(msg) && typeof msg.id === "string" && this.pendingRequests.has(msg.id)) {
          const pending = this.pendingRequests.get(msg.id)!;
          this.pendingRequests.delete(msg.id);
          try {
            pending.resolve(parseJsonRpcResponse(msg, msg.id, "stdio"));
          } catch (err) {
            pending.reject(err instanceof Error ? err : new Error(String(err)));
          }
        }
      } catch {
        // Ignore non-JSON lines (server logs, etc.)
      }
    });

    this.process.on("exit", () => {
      for (const pending of this.pendingRequests.values()) {
        pending.reject(new Error("MCP server process exited."));
      }
      this.pendingRequests.clear();
    });

    // Send initialize request
    await this.sendRequest("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "kuzushi", version: "0.13.0" },
    });

    // Send initialized notification
    this.sendNotification("notifications/initialized", {});
    this.initialized = true;
  }

  async listTools(): Promise<McpToolDefinition[]> {
    if (!this.initialized) throw new Error("MCP client not initialized.");
    const result = await this.sendRequest("tools/list", {});
    return parseToolsListResult(result);
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<McpToolResult> {
    if (!this.initialized) throw new Error("MCP client not initialized.");
    const result = await this.sendRequest("tools/call", { name, arguments: args });
    return parseMcpToolResult(result, name);
  }

  close(): void {
    if (this.process) {
      this.process.kill();
      this.process = null;
    }
  }

  private sendRequest(method: string, params: Record<string, unknown>): Promise<unknown> {
    return new Promise((resolve, reject) => {
      if (!this.process?.stdin?.writable) {
        reject(new Error("MCP server stdin not writable."));
        return;
      }

      const id = randomUUID();
      const request: JsonRpcRequest = { jsonrpc: "2.0", id, method, params };
      const timeoutMs = this.opts.timeoutMs > 0 ? this.opts.timeoutMs : DEFAULT_MCP_TIMEOUT_MS;

      const timeout = setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          reject(new Error(`MCP request timed out: ${method}`));
        }
      }, timeoutMs);

      this.pendingRequests.set(id, {
        resolve: (value) => {
          clearTimeout(timeout);
          resolve(value);
        },
        reject: (reason) => {
          clearTimeout(timeout);
          reject(reason);
        },
      });

      this.process.stdin.write(`${JSON.stringify(request)}\n`);
    });
  }

  private sendNotification(method: string, params: Record<string, unknown>): void {
    if (!this.process?.stdin?.writable) return;
    const notification = { jsonrpc: "2.0", method, params };
    this.process.stdin.write(`${JSON.stringify(notification)}\n`);
  }
}

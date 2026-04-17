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
import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "./types.js";

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: string;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

interface McpToolDefinition {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

interface McpToolResult {
  content: Array<{ type: string; text?: string }>;
  isError?: boolean;
}

/**
 * Connect to an MCP server and wrap its tools as a CopilotModule.
 *
 * @param serverSpec — Either a URL (http://...) for SSE or a command string for stdio.
 *   Stdio format: "npx @some/mcp-server" or "python mcp_server.py"
 * @param moduleId — The module ID to assign (e.g. "pentest", "mcp-tools").
 */
export async function createMcpModule(
  serverSpec: string,
  moduleId: string,
): Promise<{ module: CopilotModule; dispose: () => void }> {
  const client: McpClient =
    serverSpec.startsWith("http://") || serverSpec.startsWith("https://")
      ? new HttpMcpClient(serverSpec)
      : new StdioMcpClient(serverSpec);
  await client.initialize();

  const mcpTools = await client.listTools();

  const tools: ModuleTool[] = mcpTools.map((mcpTool) => ({
    name: `${moduleId}:${mcpTool.name}`,
    description: mcpTool.description ?? `MCP tool: ${mcpTool.name}`,
    inputSchema: mcpTool.inputSchema ?? { type: "object", properties: {} },
    headless: true,
    async execute(input: unknown, _ctx: ToolExecutionContext): Promise<ToolResult> {
      try {
        const result = await client.callTool(mcpTool.name, input as Record<string, unknown>);
        const text = result.content
          .filter((c) => c.type === "text" && c.text)
          .map((c) => c.text!)
          .join("\n");
        return { ok: !result.isError, output: text || "(no output)" };
      } catch (err) {
        return {
          ok: false,
          output: `MCP tool error: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    },
  }));

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

/** Shared shape implemented by both transports. */
interface McpClient {
  initialize(): Promise<void>;
  listTools(): Promise<McpToolDefinition[]>;
  callTool(name: string, args: Record<string, unknown>): Promise<McpToolResult>;
  close(): void;
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
 */
class HttpMcpClient implements McpClient {
  private sessionId: string | null = null;
  private initialized = false;
  private closed = false;

  constructor(private readonly url: string) {}

  async initialize(): Promise<void> {
    const result = await this.sendRequest("initialize", {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "kuzushi", version: "0.16.0" },
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
    const result = (await this.sendRequest("tools/list", {})) as { tools?: McpToolDefinition[] };
    return result.tools ?? [];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<McpToolResult> {
    if (!this.initialized) throw new Error("MCP client not initialized.");
    return this.sendRequest("tools/call", { name, arguments: args }) as Promise<McpToolResult>;
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

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
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
      const json = (await response.json()) as JsonRpcResponse;
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

function parseJsonRpcResponse(msg: JsonRpcResponse, expectedId: string, method: string): unknown {
  if (msg.id !== expectedId) {
    throw new Error(`MCP HTTP ${method}: response id mismatch (${msg.id} !== ${expectedId})`);
  }
  if (msg.error) {
    throw new Error(msg.error.message);
  }
  return msg.result;
}

/**
 * Scan an SSE body for a `data:` frame whose parsed JSON-RPC response matches
 * the requested id. Returns null if nothing matches. Tolerates interleaved
 * notifications and comments.
 */
function findMatchingSseResponse(body: string, expectedId: string): JsonRpcResponse | null {
  for (const frame of body.split(/\n\n+/)) {
    const dataLines = frame
      .split("\n")
      .filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(5).trim());
    if (dataLines.length === 0) continue;
    const joined = dataLines.join("\n");
    try {
      const msg = JSON.parse(joined) as JsonRpcResponse;
      if (msg.id === expectedId) return msg;
    } catch {
      // skip unparsable frame
    }
  }
  return null;
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

  constructor(private readonly command: string) {}

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
        const msg = JSON.parse(line) as JsonRpcResponse;
        if (msg.id && this.pendingRequests.has(msg.id)) {
          const pending = this.pendingRequests.get(msg.id)!;
          this.pendingRequests.delete(msg.id);
          if (msg.error) {
            pending.reject(new Error(msg.error.message));
          } else {
            pending.resolve(msg.result);
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
    const result = (await this.sendRequest("tools/list", {})) as { tools: McpToolDefinition[] };
    return result.tools ?? [];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<McpToolResult> {
    if (!this.initialized) throw new Error("MCP client not initialized.");
    return this.sendRequest("tools/call", { name, arguments: args }) as Promise<McpToolResult>;
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

      this.pendingRequests.set(id, { resolve, reject });

      const timeout = setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          reject(new Error(`MCP request timed out: ${method}`));
        }
      }, 30000);

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

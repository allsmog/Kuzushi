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
  // For now, only support stdio transport
  if (serverSpec.startsWith("http://") || serverSpec.startsWith("https://")) {
    throw new Error(
      `HTTP/SSE MCP transport is not yet implemented. ` +
        `Use a stdio command instead: /load mcp:npx @some/mcp-server`,
    );
  }

  const client = new StdioMcpClient(serverSpec);
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

/**
 * Minimal stdio MCP client — spawns a subprocess and communicates via JSON-RPC.
 */
class StdioMcpClient {
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

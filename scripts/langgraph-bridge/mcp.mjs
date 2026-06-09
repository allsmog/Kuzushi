import { statSync } from "node:fs";
import process from "node:process";
import { MultiServerMCPClient } from "@langchain/mcp-adapters";

export async function mcpToolsForRequest(request) {
  if (!agentMcpsEnabled(request)) return { tools: [], close: async () => {} };
  const client = new MultiServerMCPClient({
    mcpServers: mcpServerConfig(request),
    onConnectionError: (server, error) => {
      throw new Error(`requested MCP server ${server} failed to start: ${error?.message ?? error}`);
    },
  });
  const tools = await client.getTools();
  return { tools, close: async () => client.close?.() };
}

function agentMcpsEnabled(request) {
  const value = process.env.KUZUSHI_AGENT_MCPS;
  if (value === "0" || value === "false") return false;
  if (request?.toolPolicy?.mcps === true) return true;
  return value === "1" || value === "true";
}

function mcpServerConfig(request) {
  const cwd = mcpCwdFor(request);
  const env = { ...process.env, ...mcpEnvironment(request) };
  return {
    treesitter: stdioServer("KUZUSHI_MCP_TREESITTER_BIN", "kuzushi-mcp-treesitter", cwd, env),
    joern: stdioServer("KUZUSHI_MCP_JOERN_BIN", "kuzushi-mcp-joern", cwd, env),
    codeql: stdioServer("KUZUSHI_MCP_CODEQL_BIN", "kuzushi-mcp-codeql", cwd, env),
  };
}

function stdioServer(envName, fallbackCommand, cwd, env) {
  return {
    transport: "stdio",
    command: process.env[envName] || fallbackCommand,
    args: [],
    cwd,
    env,
  };
}

function mcpCwdFor(request) {
  const candidate = request?.cwd;
  if (!directoryExists(candidate)) return process.cwd();
  return candidate;
}

function directoryExists(candidate) {
  if (typeof candidate !== "string" || candidate.length === 0) return false;
  try {
    return statSync(candidate).isDirectory();
  } catch {
    return false;
  }
}

function mcpEnvironment(request) {
  const raw = request?.runtimeOptions?.mcpEnvironment ?? request?.runtime_options?.mcp_environment;
  return raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
}

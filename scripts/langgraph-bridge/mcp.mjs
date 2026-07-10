import { statSync } from "node:fs";
import process from "node:process";
import { MultiServerMCPClient } from "@langchain/mcp-adapters";

export async function mcpToolsForRequest(request) {
  if (!agentMcpsEnabled(request)) return { tools: [], close: async () => {} };
  const mcpServers = mcpServerConfig(request);
  const client = new MultiServerMCPClient({
    mcpServers,
    onConnectionError: (server, error) => {
      throw new Error(mcpConnectionFailureMessage(server, error, mcpServers));
    },
  });
  const tools = await client.getTools();
  return { tools, close: async () => client.close?.() };
}

export function mcpConnectionFailureMessage(server, error, serverConfig = {}) {
  const name = mcpServerName(server);
  const command = mcpServerCommand(name, server, serverConfig);
  const cause = mcpFailureCause(error ?? server?.error ?? server?.cause ?? server?.reason);
  return `requested MCP server ${name} failed to start (command: ${command}): ${cause}`;
}

function mcpServerName(server) {
  if (typeof server === "string" && server.trim().length > 0) return server;
  for (const candidate of [server?.name, server?.serverName, server?.server?.name]) {
    if (typeof candidate === "string" && candidate.trim().length > 0) return candidate;
  }
  return "unknown";
}

function mcpServerCommand(name, server, serverConfig) {
  for (const candidate of [
    serverConfig?.[name]?.command,
    server?.command,
    server?.config?.command,
  ]) {
    if (typeof candidate === "string" && candidate.trim().length > 0) return candidate;
  }
  return "unknown";
}

function mcpFailureCause(error) {
  const direct = nonEmptyString(error);
  if (direct) return direct;
  const nested = firstNonEmptyString([
    error?.message,
    error?.error?.message,
    error?.cause?.message,
  ]);
  return nested ?? serializedFailure(error) ?? "connection failed without a reported cause";
}

function firstNonEmptyString(candidates) {
  return candidates.map(nonEmptyString).find(Boolean);
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

function serializedFailure(error) {
  if (!error || typeof error !== "object") return undefined;
  try {
    const serialized = JSON.stringify(error);
    return serialized && serialized !== "{}" ? serialized : undefined;
  } catch {
    return undefined;
  }
}

function agentMcpsEnabled(request) {
  const value = process.env.KUZUSHI_AGENT_MCPS;
  if (value === "0" || value === "false") return false;
  if (request?.toolPolicy?.mcps === true) return true;
  return value === "1" || value === "true";
}

export function mcpServerConfig(request) {
  const cwd = mcpCwdFor(request);
  const env = { ...process.env, ...mcpEnvironment(request) };
  const plan = attachmentPlan(request);
  if (plan.length > 0) return plannedServerConfig(plan, cwd, env);
  return defaultServerConfig(cwd, env);
}

// The artifact-gated plan computed by `mcp_attachment_plan_for_target`
// (kuzushi-core). When present it is authoritative: only the listed
// servers attach, so a missing CPG or CodeQL DB never queues a server
// that would fail at first tool call.
function attachmentPlan(request) {
  const raw = request?.toolPolicy?.mcpsAttached ?? request?.toolPolicy?.mcps_attached;
  if (!Array.isArray(raw)) return [];
  return raw.filter((entry) => typeof entry?.name === "string" && entry.name.length > 0);
}

function plannedServerConfig(plan, cwd, env) {
  const servers = {};
  for (const attachment of plan) {
    servers[attachment.name] = plannedServer(attachment, cwd, env);
  }
  return servers;
}

function plannedServer(attachment, cwd, env) {
  const token = attachment.name.toUpperCase().replaceAll("-", "_");
  return {
    transport: "stdio",
    command: process.env[`KUZUSHI_MCP_${token}_BIN`] || `kuzushi-mcp-${attachment.name}`,
    args: [],
    cwd,
    env: { ...env, ...artifactEnv(attachment, token) },
  };
}

// Artifact-backed servers read their input path from
// `KUZUSHI_MCP_<NAME>_ARTIFACT`; the joern server predates that
// convention and reads `KUZUSHI_JOERN_CPG`.
function artifactEnv(attachment, token) {
  const path = attachment.artifactPath ?? attachment.artifact_path;
  if (typeof path !== "string" || path.length === 0) return {};
  const env = { [`KUZUSHI_MCP_${token}_ARTIFACT`]: path };
  if (attachment.name === "joern") env.KUZUSHI_JOERN_CPG = path;
  return env;
}

// Legacy surface for callers that only set `toolPolicy.mcps = true`
// (or force `KUZUSHI_AGENT_MCPS=1`) without an attachment plan.
function defaultServerConfig(cwd, env) {
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

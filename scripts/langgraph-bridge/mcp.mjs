import { realpathSync, statSync } from "node:fs";
import { sep } from "node:path";
import process from "node:process";
import { MultiServerMCPClient } from "@langchain/mcp-adapters";

export async function mcpToolsForRequest(request) {
  if (!agentMcpsEnabled(request)) return { tools: [], close: async () => {} };
  const mcpServers = mcpServerConfig(request);
  if (Object.keys(mcpServers).length === 0) return { tools: [], close: async () => {} };
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
  const readRoots = mcpReadRootsFor(request);
  if (readRoots.length === 0) return {};
  const cwd = mcpCwdFor(request, readRoots);
  const plan = attachmentPlan(request);
  if (plan.length > 0) return plannedServerConfig(plan, cwd, request, readRoots);
  return defaultServerConfig(cwd, request, readRoots);
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

function plannedServerConfig(plan, cwd, request, readRoots) {
  const servers = {};
  for (const attachment of plan) {
    servers[attachment.name] = plannedServer(attachment, cwd, request, readRoots);
  }
  return servers;
}

function plannedServer(attachment, cwd, request, readRoots) {
  const token = attachment.name.toUpperCase().replaceAll("-", "_");
  const artifact = artifactEnv(attachment, token, readRoots);
  return {
    transport: "stdio",
    command: process.env[`KUZUSHI_MCP_${token}_BIN`] || `kuzushi-mcp-${attachment.name}`,
    args: [],
    cwd,
    env: serverEnvironment(attachment.name, request, readRoots, artifact, true),
  };
}

// Artifact-backed servers read their input path from
// `KUZUSHI_MCP_<NAME>_ARTIFACT`.
function artifactEnv(attachment, token, readRoots) {
  const path = attachment.artifactPath ?? attachment.artifact_path;
  if (typeof path !== "string" || path.length === 0) return {};
  const authorizedPath = authorizedArtifactPath(path, readRoots);
  return { [`KUZUSHI_MCP_${token}_ARTIFACT`]: authorizedPath };
}

function authorizedArtifactPath(path, readRoots) {
  let canonical;
  try {
    canonical = realpathSync(path);
  } catch (error) {
    throw new Error(`planned MCP artifact is unavailable: ${path}`, { cause: error });
  }
  if (!readRoots.some((root) => pathWithinRoot(canonical, root))) {
    throw new Error(`planned MCP artifact is outside the read roots: ${path}`);
  }
  const metadata = statSync(canonical);
  if (!metadata.isFile() && !metadata.isDirectory()) {
    throw new Error(`planned MCP artifact is not a regular file or directory: ${path}`);
  }
  return canonical;
}

// Legacy surface for callers that only set `toolPolicy.mcps = true`
// (or force `KUZUSHI_AGENT_MCPS=1`) without an attachment plan.
function defaultServerConfig(cwd, request, readRoots) {
  return {
    treesitter: stdioServer(
      "treesitter",
      "KUZUSHI_MCP_TREESITTER_BIN",
      "kuzushi-mcp-treesitter",
      cwd,
      request,
      readRoots,
    ),
    cpg: stdioServer(
      "cpg",
      "KUZUSHI_MCP_CPG_BIN",
      "kuzushi-mcp-cpg",
      cwd,
      request,
      readRoots,
    ),
    codeql: stdioServer(
      "codeql",
      "KUZUSHI_MCP_CODEQL_BIN",
      "kuzushi-mcp-codeql",
      cwd,
      request,
      readRoots,
    ),
  };
}

function stdioServer(name, envName, fallbackCommand, cwd, request, readRoots) {
  return {
    transport: "stdio",
    command: process.env[envName] || fallbackCommand,
    args: [],
    cwd,
    env: serverEnvironment(name, request, readRoots),
  };
}

function mcpCwdFor(request, readRoots) {
  const candidate = request?.cwd;
  if (!directoryExists(candidate)) return readRoots[0];
  const canonical = realpathSync(candidate);
  return readRoots.some((root) => pathWithinRoot(canonical, root)) ? canonical : readRoots[0];
}

function pathWithinRoot(candidate, root) {
  return candidate === root || candidate.startsWith(`${root}${sep}`);
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

const COMMON_CHILD_ENV = ["PATH"];
const READ_CAPABILITY_SERVERS = new Set([
  "treesitter",
  "cpg",
  "codeql",
  "context",
  "entry-points",
  "threat-model",
  "threat-intel",
  "x-ray",
  "findings",
]);
const SERVER_CHILD_ENV = {
  codeql: [
    "HOME",
    "TMPDIR",
    "XDG_CACHE_HOME",
    "KUZUSHI_CODEQL_BIN",
    "KUZUSHI_CODEQL_CACHE_DIR",
    "KUZUSHI_CODEQL_PREWARM",
  ],
};

function serverEnvironment(name, request, readRoots, fixed = {}, forceReadCapability = false) {
  const requested = mcpEnvironment(request);
  const env = selectedEnvironment(requested, [
    ...COMMON_CHILD_ENV,
    ...(SERVER_CHILD_ENV[name] ?? []),
  ]);
  if (forceReadCapability || READ_CAPABILITY_SERVERS.has(name)) {
    env.KUZUSHI_MCP_READ_ROOTS = JSON.stringify(readRoots);
  }
  return Object.assign(env, fixed);
}

function selectedEnvironment(requested, names) {
  const env = {};
  for (const name of names) {
    const value = requested[name] ?? process.env[name];
    if (typeof value === "string") env[name] = value;
  }
  return env;
}

function mcpReadRootsFor(request) {
  const raw = request?.toolPolicy?.mcpReadRoots ?? request?.toolPolicy?.mcp_read_roots;
  if (!Array.isArray(raw)) return [];
  const roots = raw.map(canonicalReadRoot);
  return [...new Set(roots)];
}

function canonicalReadRoot(root) {
  if (typeof root !== "string" || root.length === 0) {
    throw new Error("MCP read roots must be non-empty path strings");
  }
  let canonical;
  try {
    canonical = realpathSync(root);
  } catch (error) {
    throw new Error(`MCP read root is unavailable: ${root}`, { cause: error });
  }
  if (!statSync(canonical).isDirectory()) {
    throw new Error(`MCP read root is not a directory: ${root}`);
  }
  return canonical;
}

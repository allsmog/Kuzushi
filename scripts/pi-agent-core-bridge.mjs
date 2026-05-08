#!/usr/bin/env node
import { spawn } from "node:child_process";
import {
  chmodSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

/**
 * Cross-process exclusive lock around an OAuth credentials read-modify-write.
 *
 * Multiple bridge processes (e.g. four tmux panes from run-all.sh) can race
 * on token refresh: each reads the bag, calls the OAuth refresh endpoint,
 * and writes the bag back. Without locking, only one writer's refresh-token
 * survives and the others are silently invalidated by Anthropic on the next
 * call. We use an atomic O_EXCL create on a sibling `.lock` file as a
 * cross-process mutex; the file is unlinked on release.
 */
async function withCredentialsLock(filePath, fn, { timeoutMs = 30_000, pollMs = 80 } = {}) {
  const lockPath = `${filePath}.lock`;
  mkdirSync(path.dirname(lockPath), { recursive: true });
  const start = Date.now();
  let fd;
  while (true) {
    try {
      fd = openSync(lockPath, "wx", 0o600);
      break;
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      if (Date.now() - start > timeoutMs) {
        // Stale lock recovery: if the lock file is older than the timeout
        // assume the holder crashed and steal it. Worst case is one extra
        // refresh, not a security issue.
        try {
          rmSync(lockPath, { force: true });
        } catch {
          /* ignore */
        }
        continue;
      }
      await new Promise((resolve) => setTimeout(resolve, pollMs));
    }
  }
  try {
    return await fn();
  } finally {
    try {
      closeSync(fd);
    } catch {
      /* ignore */
    }
    try {
      rmSync(lockPath, { force: true });
    } catch {
      /* ignore */
    }
  }
}

async function readStdin() {
  let data = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) {
    data += chunk;
  }
  return data;
}

function providerEnvName(provider) {
  return `${provider.toUpperCase().replace(/[^A-Z0-9]/g, "_")}_API_KEY`;
}

function normalizeThinkingLevel(value) {
  const normalized = String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/[\s_-]+/g, "");
  if (!normalized) return undefined;
  if (normalized === "xhigh" || normalized === "xtrahigh" || normalized === "extrahigh") {
    return "xhigh";
  }
  if (normalized === "high") return "high";
  if (normalized === "medium" || normalized === "med") return "medium";
  if (normalized === "low") return "low";
  return undefined;
}

function parseModelSpec(spec) {
  const idx = spec.indexOf(":");
  if (idx <= 0 || idx === spec.length - 1) {
    throw new Error(`model must use provider:model syntax, got ${JSON.stringify(spec)}`);
  }
  return [spec.slice(0, idx), spec.slice(idx + 1)];
}

function extractTextFromState(agent) {
  const messages = agent?.state?.messages;
  if (!Array.isArray(messages)) return "";
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const message = messages[i];
    if (message?.role !== "assistant" && message?.type !== "assistant") continue;
    const content = message.content;
    if (typeof content === "string") return content;
    if (Array.isArray(content)) {
      return content
        .map((part) => {
          if (typeof part === "string") return part;
          if (typeof part?.text === "string") return part.text;
          if (typeof part?.content === "string") return part.content;
          return "";
        })
        .join("");
    }
  }
  return "";
}

/**
 * Sum the per-turn `usage` blocks pi-agent-core attaches to assistant
 * messages. The library records cost in dollars under `usage.cost.total`
 * and token counts as `usage.input` / `usage.output` (plus cache fields).
 * Multi-turn agent loops can have several assistant messages, so we sum
 * across all of them rather than reading only the last one.
 */
function aggregateAgentUsage(agent) {
  const messages = agent?.state?.messages;
  if (!Array.isArray(messages)) return undefined;
  let inputTokens = 0;
  let outputTokens = 0;
  let costUsd = 0;
  let touched = false;
  for (const message of messages) {
    if (message?.role !== "assistant" && message?.type !== "assistant") continue;
    const usage = message?.usage;
    if (!usage || typeof usage !== "object") continue;
    touched = true;
    inputTokens += Number(usage.input ?? usage.input_tokens ?? 0) || 0;
    outputTokens += Number(usage.output ?? usage.output_tokens ?? 0) || 0;
    const cost = usage.cost;
    if (cost && typeof cost === "object") {
      const total = Number(cost.total ?? 0);
      if (Number.isFinite(total)) costUsd += total;
    }
  }
  if (!touched) return undefined;
  return { inputTokens, outputTokens, costUsd };
}

function maybeParseJson(text) {
  if (!text) return undefined;
  const trimmed = text.trim();
  const fence = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/);
  const candidate = fence ? fence[1].trim() : trimmed;
  try {
    return JSON.parse(candidate);
  } catch {
    const start = candidate.indexOf("{");
    const end = candidate.lastIndexOf("}");
    if (start >= 0 && end > start) {
      try {
        return JSON.parse(candidate.slice(start, end + 1));
      } catch {
        return undefined;
      }
    }
    return undefined;
  }
}

const WHITEBOX_STATIC_TOOL_PROFILE = "whitebox-static";
const WHITEBOX_STATIC_READ_ONLY_TOOLS = ["Read", "Glob", "Grep", "LS"];
const FORBIDDEN_WHITEBOX_TOOLS = new Set([
  "bash",
  "shell",
  "sh",
  "zsh",
  "fish",
  "powershell",
  "cmd",
  "write",
  "edit",
  "multiedit",
  "patch",
  "applypatch",
  "apply_patch",
  "notebookedit",
]);

function normalizeToolName(name) {
  return String(name ?? "")
    .replace(/[^a-zA-Z0-9_]/g, "")
    .toLowerCase();
}

function isForbiddenWhiteboxTool(name) {
  return FORBIDDEN_WHITEBOX_TOOLS.has(normalizeToolName(name));
}

function normalizeAgentToolPolicy(request) {
  const raw =
    request.toolPolicy && typeof request.toolPolicy === "object" ? request.toolPolicy : {};
  const profile = String(raw.profile ?? "default");
  const tools = Array.isArray(raw.tools) ? raw.tools.map((tool) => String(tool)) : [];
  if (profile !== WHITEBOX_STATIC_TOOL_PROFILE) {
    return { profile: "default", tools: [] };
  }

  const selectedTools = tools.length > 0 ? tools : WHITEBOX_STATIC_READ_ONLY_TOOLS;
  for (const tool of selectedTools) {
    if (isForbiddenWhiteboxTool(tool)) {
      throw new Error(
        `whitebox-static cannot enable execution or write tool ${JSON.stringify(tool)}`,
      );
    }
    if (
      !WHITEBOX_STATIC_READ_ONLY_TOOLS.some(
        (allowed) => allowed.toLowerCase() === tool.toLowerCase(),
      )
    ) {
      throw new Error(
        `whitebox-static can only enable read-only repo tools, got ${JSON.stringify(tool)}`,
      );
    }
  }
  return { profile, tools: selectedTools };
}

function repoRoot(cwd) {
  const root = realpathSync(path.resolve(cwd));
  const stat = statSync(root);
  if (!stat.isDirectory()) throw new Error(`cwd is not a directory: ${root}`);
  return root;
}

function resolveRepoPath(root, rawPath = ".") {
  const candidate = path.resolve(root, String(rawPath || "."));
  const normalizedRoot = root.endsWith(path.sep) ? root : `${root}${path.sep}`;
  if (candidate !== root && !candidate.startsWith(normalizedRoot)) {
    throw new Error(`path escapes repository root: ${rawPath}`);
  }
  return candidate;
}

function relativeRepoPath(root, filePath) {
  const relative = path.relative(root, filePath).replaceAll(path.sep, "/");
  return relative || ".";
}

function isSkippedRepoEntry(name) {
  return [
    ".git",
    ".hg",
    ".kuzushi",
    ".next",
    ".turbo",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
  ].includes(name);
}

function isTextBuffer(buffer) {
  return !buffer.subarray(0, 4096).includes(0);
}

function readRepoTextFile(root, rawPath, maxBytes = 32768) {
  const filePath = resolveRepoPath(root, rawPath);
  const stat = statSync(filePath);
  if (!stat.isFile()) throw new Error(`not a file: ${rawPath}`);
  const cap = Math.max(1, Math.min(Number(maxBytes) || 32768, 131072));
  const buffer = readFileSync(filePath);
  if (!isTextBuffer(buffer)) throw new Error(`binary file refused: ${rawPath}`);
  const sliced = buffer.subarray(0, cap);
  return {
    text: sliced.toString("utf8"),
    relativePath: relativeRepoPath(root, filePath),
    bytes: buffer.length,
    truncated: buffer.length > sliced.length,
  };
}

function listRepoFiles(root, rawPath = ".", maxFiles = 200) {
  const start = resolveRepoPath(root, rawPath);
  const files = [];
  function visit(current) {
    if (files.length >= maxFiles) return;
    const stat = statSync(current);
    if (stat.isFile()) {
      files.push(current);
      return;
    }
    if (!stat.isDirectory()) return;
    const entries = readdirSync(current, { withFileTypes: true }).sort((a, b) =>
      a.name.localeCompare(b.name),
    );
    for (const entry of entries) {
      if (isSkippedRepoEntry(entry.name)) continue;
      visit(path.join(current, entry.name));
      if (files.length >= maxFiles) return;
    }
  }
  visit(start);
  return files;
}

function globToRegExp(pattern) {
  const escaped = String(pattern || "**/*")
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replaceAll("**", "\0")
    .replaceAll("*", "[^/]*")
    .replaceAll("\0", ".*");
  return new RegExp(`^${escaped}$`);
}

function createWhiteboxReadOnlyTools(cwd) {
  const root = repoRoot(cwd);
  return {
    Read: {
      name: "Read",
      label: "Read",
      description: "Read a text file under the repository root.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "Repository-relative file path." },
          maxBytes: { type: "number", description: "Maximum bytes to return." },
        },
        required: ["path"],
        additionalProperties: false,
      },
      executionMode: "sequential",
      execute: async (_toolCallId, params) => {
        const result = readRepoTextFile(root, params.path, params.maxBytes);
        return {
          content: [{ type: "text", text: result.text }],
          details: result,
        };
      },
    },
    LS: {
      name: "LS",
      label: "List",
      description: "List files and directories under the repository root.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "Repository-relative directory path." },
          maxEntries: { type: "number", description: "Maximum entries to return." },
        },
        additionalProperties: false,
      },
      execute: async (_toolCallId, params) => {
        const dir = resolveRepoPath(root, params.path ?? ".");
        const entries = readdirSync(dir, { withFileTypes: true })
          .sort((a, b) => a.name.localeCompare(b.name))
          .slice(0, Math.max(1, Math.min(Number(params.maxEntries) || 100, 500)))
          .map((entry) => `${entry.isDirectory() ? "dir " : "file"} ${entry.name}`);
        return {
          content: [{ type: "text", text: entries.join("\n") }],
          details: { path: relativeRepoPath(root, dir), count: entries.length },
        };
      },
    },
    Glob: {
      name: "Glob",
      label: "Glob",
      description: "Find repository files matching a glob pattern.",
      parameters: {
        type: "object",
        properties: {
          pattern: { type: "string", description: "Glob pattern such as src/**/*.ts." },
          path: { type: "string", description: "Optional repository-relative search root." },
          maxResults: { type: "number", description: "Maximum matching files." },
        },
        required: ["pattern"],
        additionalProperties: false,
      },
      execute: async (_toolCallId, params) => {
        const maxResults = Math.max(1, Math.min(Number(params.maxResults) || 100, 500));
        const matcher = globToRegExp(params.pattern);
        const matches = listRepoFiles(root, params.path ?? ".", maxResults * 4)
          .map((filePath) => relativeRepoPath(root, filePath))
          .filter((relative) => matcher.test(relative))
          .slice(0, maxResults);
        return {
          content: [{ type: "text", text: matches.join("\n") }],
          details: { pattern: params.pattern, count: matches.length },
        };
      },
    },
    Grep: {
      name: "Grep",
      label: "Grep",
      description: "Search text files under the repository root.",
      parameters: {
        type: "object",
        properties: {
          query: { type: "string", description: "Literal text to search for." },
          path: { type: "string", description: "Optional repository-relative search root." },
          maxResults: { type: "number", description: "Maximum matching lines." },
        },
        required: ["query"],
        additionalProperties: false,
      },
      execute: async (_toolCallId, params) => {
        const maxResults = Math.max(1, Math.min(Number(params.maxResults) || 50, 200));
        const query = String(params.query ?? "");
        const matches = [];
        for (const filePath of listRepoFiles(root, params.path ?? ".", 1000)) {
          if (matches.length >= maxResults) break;
          let read;
          try {
            read = readRepoTextFile(root, relativeRepoPath(root, filePath), 65536);
          } catch {
            continue;
          }
          read.text.split(/\r?\n/).forEach((line, index) => {
            if (matches.length < maxResults && line.includes(query)) {
              matches.push(`${read.relativePath}:${index + 1}: ${line}`);
            }
          });
        }
        return {
          content: [{ type: "text", text: matches.join("\n") }],
          details: { query, count: matches.length },
        };
      },
    },
  };
}

function buildAgentTools(request) {
  const policy = normalizeAgentToolPolicy(request);
  if (policy.profile !== WHITEBOX_STATIC_TOOL_PROFILE) return [];
  const available = createWhiteboxReadOnlyTools(request.cwd);
  return policy.tools.map((tool) => {
    const canonicalName = WHITEBOX_STATIC_READ_ONLY_TOOLS.find(
      (allowed) => allowed.toLowerCase() === tool.toLowerCase(),
    );
    return available[canonicalName];
  });
}

function subscribeText(agent, onText) {
  if (typeof agent?.subscribe !== "function") return;
  agent.subscribe((event) => {
    if (event?.type !== "message_update") return;
    const assistantEvent = event.assistantMessageEvent;
    if (assistantEvent?.type === "text_delta" && typeof assistantEvent.delta === "string") {
      onText(assistantEvent.delta);
    }
  });
}

async function runAgent(AgentCtor, model, request) {
  const agentTools = buildAgentTools(request);
  const allowedToolNames = new Set(agentTools.map((tool) => tool.name.toLowerCase()));
  const systemPrompt = appendStructuredOutputContract(
    request.systemPrompt ?? request.system_prompt ?? "",
    request.structuredOutput ?? request.structured_output ?? request.outputFormat,
  );
  const thinkingLevel =
    normalizeThinkingLevel(request.thinkingLevel) ??
    normalizeThinkingLevel(process.env.KUZUSHI_THINKING_LEVEL) ??
    normalizeThinkingLevel(process.env.KUZUSHI_REASONING_EFFORT) ??
    "low";
  const agent = new AgentCtor({
    initialState: {
      systemPrompt,
      model,
      tools: agentTools,
      messages: [],
      thinkingLevel,
    },
    beforeToolCall: async ({ toolCall }) => {
      const name = toolCall?.name ?? "";
      if (isForbiddenWhiteboxTool(name)) {
        return { block: true, reason: `whitebox-static blocks execution/write tool ${name}` };
      }
      if (allowedToolNames.size > 0 && !allowedToolNames.has(String(name).toLowerCase())) {
        return { block: true, reason: `whitebox-static only allows read-only repo tools` };
      }
      return undefined;
    },
    getApiKey: async (provider) =>
      (await getFreshOAuthAccessTokenForProvider(provider)) ??
      providerAuthToken(provider) ??
      configuredProviderApiKey(provider, request) ??
      process.env[providerEnvName(provider)] ??
      (provider === "openai" ? process.env.OPENAI_API_KEY : undefined),
  });

  let text = "";
  subscribeText(agent, (delta) => {
    text += delta;
  });

  if (typeof agent.prompt === "function") {
    const result = await agent.prompt(request.prompt);
    if (typeof result === "string") text += result;
  } else if (typeof agent.run === "function") {
    const result = await agent.run(request.prompt);
    if (typeof result === "string") text += result;
  } else if (typeof agent.followUp === "function") {
    const promptMessage = {
      role: "user",
      content: [{ type: "text", text: request.prompt }],
    };
    agent.followUp(promptMessage);
  } else {
    throw new Error("Unsupported pi-agent-core Agent API: no prompt/run/followUp method found");
  }

  if (typeof agent.waitForIdle === "function") {
    await agent.waitForIdle();
  }

  if (!text.trim()) {
    text = extractTextFromState(agent);
  }

  return {
    text: text.trim(),
    usage: aggregateAgentUsage(agent),
    errorMessage: agent?.state?.errorMessage ?? undefined,
  };
}

function appendStructuredOutputContract(systemPrompt, contract) {
  if (!contract || typeof contract !== "object") return systemPrompt;
  const name =
    typeof contract.name === "string" && contract.name.trim()
      ? contract.name.trim()
      : "structured-output";
  const schema = contract.schema ?? {};
  const strict = contract.strict === false ? "" : "strict ";
  return [
    systemPrompt,
    "",
    "Structured output contract:",
    `Return only ${strict}JSON for \`${name}\`. Do not include markdown fences, prose, or trailing commentary.`,
    "Required JSON schema:",
    JSON.stringify(schema, null, 2),
  ]
    .filter((line, index) => index > 0 || String(line).trim())
    .join("\n");
}

function oauthCredentialsPath(home = os.homedir()) {
  return path.join(home, ".kuzushi", "oauth-credentials.json");
}

function readOauthCredentials(home = os.homedir()) {
  const filePath = oauthCredentialsPath(home);
  if (!existsSync(filePath)) return {};
  try {
    const parsed = JSON.parse(readFileSync(filePath, "utf8"));
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function writeOauthCredentials(bag, home = os.homedir()) {
  const filePath = oauthCredentialsPath(home);
  const dir = path.dirname(filePath);
  mkdirSync(dir, { recursive: true });
  // Harden the parent directory in case it was created earlier with a permissive umask.
  try {
    chmodSync(dir, 0o700);
  } catch {
    /* ignore — best-effort */
  }
  // Atomic-ish write: tmp + rename, so a crashed writer can't leave a partial file.
  const tmpPath = `${filePath}.tmp.${process.pid}`;
  writeFileSync(tmpPath, `${JSON.stringify(bag, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  try {
    chmodSync(tmpPath, 0o600);
  } catch {
    /* ignore */
  }
  // renameSync is atomic on the same filesystem.
  renameSync(tmpPath, filePath);
  try {
    chmodSync(filePath, 0o600);
  } catch {
    /* ignore */
  }
  return filePath;
}

function isProviderCreds(value) {
  return (
    value &&
    typeof value === "object" &&
    typeof value.refresh === "string" &&
    typeof value.access === "string" &&
    typeof value.expires === "number"
  );
}

function normalizeOAuthProvider(provider) {
  const normalized = String(provider ?? "")
    .trim()
    .toLowerCase();
  if (normalized === "anthropic" || normalized === "claude") return "anthropic";
  if (normalized === "openai-codex" || normalized === "codex") return "openai-codex";
  throw new Error("auth login supports providers: openai-codex, anthropic");
}

async function loadOAuthModule() {
  try {
    return await import("@mariozechner/pi-ai/oauth");
  } catch (error) {
    throw new Error(
      `Could not load @mariozechner/pi-ai/oauth for OAuth login/refresh: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

async function getFreshOAuthAccessTokenForProvider(provider) {
  if (provider !== "anthropic" && provider !== "openai-codex") return undefined;
  // Fast path: token still fresh — no lock needed, no I/O race.
  const bagInitial = readOauthCredentials();
  const credsInitial = bagInitial[provider];
  if (!isProviderCreds(credsInitial)) return undefined;
  if (Date.now() < credsInitial.expires) return credsInitial.access;

  // Refresh path: serialise across processes with a sibling lockfile so
  // concurrent bridge invocations (multiple tmux panes) don't each refresh
  // and overwrite each other's refresh token.
  return withCredentialsLock(oauthCredentialsPath(), async () => {
    // Re-read under lock — another holder may have just refreshed for us.
    const bag = readOauthCredentials();
    const creds = bag[provider];
    if (!isProviderCreds(creds)) return undefined;
    if (Date.now() < creds.expires) return creds.access;

    try {
      const oauth = await loadOAuthModule();
      const refresh =
        provider === "anthropic" ? oauth.refreshAnthropicToken : oauth.refreshOpenAICodexToken;
      if (typeof refresh !== "function") return undefined;
      const next = await refresh(creds.refresh);
      if (!isProviderCreds(next)) return undefined;
      writeOauthCredentials({ ...bag, [provider]: next });
      return next.access;
    } catch {
      // Never surface refresh-error details — they may include redirect URLs
      // or other artefacts that contain authorisation codes.
      return undefined;
    }
  });
}

function providerAuthToken(provider) {
  if (provider === "anthropic") {
    return process.env.ANTHROPIC_AUTH_TOKEN ?? process.env.ANTHROPIC_OAUTH_TOKEN;
  }
  return undefined;
}

function configuredProviderApiKey(provider, request) {
  const providerEnv = providerEnvName(provider);
  if (request.apiKeyEnv === providerEnv) return request.apiKey;
  if (request.apiKeyEnv && request.apiKeyEnv !== "OPENAI_API_KEY") return request.apiKey;
  return undefined;
}

async function runOAuthLogin(rawProvider) {
  const provider = normalizeOAuthProvider(rawProvider);
  const oauth = await loadOAuthModule();
  const login = provider === "anthropic" ? oauth.loginAnthropic : oauth.loginOpenAICodex;
  if (typeof login !== "function") {
    throw new Error(`@mariozechner/pi-ai/oauth does not expose a login flow for ${provider}`);
  }

  const creds = await login({
    onAuth: (info) => {
      process.stdout.write(`Open this URL to authorize ${provider}: ${info.url}\n`);
      tryOpenBrowser(info.url);
    },
    onPrompt: async () => promptManualCode(),
    onManualCodeInput: async () => promptManualCode(),
    onProgress: (message) => process.stdout.write(`[oauth] ${message}\n`),
  });
  const persistable = {
    ...creds,
    refresh: String(creds?.refresh ?? ""),
    access: String(creds?.access ?? ""),
    expires: Number(creds?.expires ?? 0),
  };
  if (!persistable.refresh || !persistable.access) {
    throw new Error(`${provider} OAuth flow returned no usable credentials`);
  }
  const filePath = await withCredentialsLock(oauthCredentialsPath(), async () => {
    const bag = readOauthCredentials();
    return writeOauthCredentials({ ...bag, [provider]: persistable });
  });
  process.stdout.write(`${provider} OAuth credentials saved to ${filePath}\n`);
}

function tryOpenBrowser(url) {
  if (process.env.KUZUSHI_DISABLE_BROWSER_OPEN === "1") return;
  const command =
    process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  try {
    const child = spawn(command, args, { stdio: "ignore", detached: true });
    child.on("error", () => {
      /* xdg-open / open / cmd missing — URL was printed for manual use. */
    });
    child.unref();
  } catch {
    /* URL is printed for manual use. */
  }
}

async function promptManualCode() {
  process.stdout.write(
    "\nIf the browser cannot reach the local callback, paste the final redirect URL or code#state fragment.\n> ",
  );
  const readline = await import("node:readline/promises");
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: process.stdin.isTTY,
  });
  try {
    return (await rl.question("")).trim();
  } finally {
    rl.close();
  }
}

/**
 * `ping` envelope handler. Minimum-viable Anthropic Messages API call
 * — 1 token round-trip with no tools, no system prompt, no streaming.
 * Surfaces wall latency + token counts so an operator can confirm
 * credentials and connectivity in <1 s. Used by `kuzushi auth ping`.
 */
async function handlePing(request) {
  const [provider, modelId] = parseModelSpec(request.model);
  if (provider !== "anthropic") {
    throw new Error(
      `auth ping currently only supports anthropic (got ${provider}). ` +
        "OpenAI / Gemini support is a follow-up.",
    );
  }
  const oauthToken = await getFreshOAuthAccessTokenForProvider("anthropic");
  const envOauth = providerAuthToken("anthropic");
  const apiKey = configuredProviderApiKey("anthropic", request) ?? process.env.ANTHROPIC_API_KEY;
  if (!oauthToken && !envOauth && !apiKey) {
    throw new Error(
      "auth ping: no Anthropic credentials. Run `kuzushi auth login anthropic` " +
        "or set ANTHROPIC_OAUTH_TOKEN / ANTHROPIC_API_KEY.",
    );
  }
  const headers = {
    "content-type": "application/json",
    "anthropic-version": "2023-06-01",
  };
  let authMode;
  if (oauthToken || envOauth) {
    headers.authorization = `Bearer ${oauthToken ?? envOauth}`;
    headers["anthropic-beta"] = "oauth-2025-04-20";
    authMode = oauthToken ? "oauth-file" : "oauth-env";
  } else {
    headers["x-api-key"] = apiKey;
    authMode = "api-key";
  }
  const body = {
    model: modelId,
    max_tokens: 1,
    messages: [{ role: "user", content: "ok" }],
  };
  const t0 = Date.now();
  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  const text = await response.text();
  const latency_ms = Date.now() - t0;
  if (!response.ok) {
    throw new Error(
      `auth ping: Anthropic API ${response.status} ${response.statusText}: ${text.slice(0, 300)}`,
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`auth ping: Anthropic returned non-JSON body: ${text.slice(0, 200)}`);
  }
  const usage = parsed.usage ?? {};
  return {
    ok: true,
    auth_mode: authMode,
    model: modelId,
    latency_ms,
    input_tokens: usage.input_tokens ?? 0,
    output_tokens: usage.output_tokens ?? 0,
    cost_usd: approximateCostUsd(modelId, usage),
  };
}

/**
 * `next-step` envelope handler. Single-round-trip request to Anthropic's
 * Messages API with tool definitions; returns either a tool_call or a
 * final answer for the Rust-side run_tool_loop driver.
 *
 * Auth precedence: OAuth file → ANTHROPIC_OAUTH_TOKEN env → API key.
 *
 * Cost: derived from `response.usage` × per-model rate band. Rates are
 * approximate (input + output, ignoring prompt cache). Use the spend
 * ledger as the source of truth for budget enforcement, not these
 * numbers.
 */
async function handleNextStep(request) {
  const [provider, modelId] = parseModelSpec(request.model);
  if (provider !== "anthropic") {
    throw new Error(
      `next-step bridge only supports anthropic models in this version (got ${provider}). ` +
        "Open a follow-up phase to add openai/gemini.",
    );
  }

  // Resolve auth header.
  const oauthToken = await getFreshOAuthAccessTokenForProvider("anthropic");
  const envOauth = providerAuthToken("anthropic");
  const apiKey = configuredProviderApiKey("anthropic", request) ?? process.env.ANTHROPIC_API_KEY;
  if (!oauthToken && !envOauth && !apiKey) {
    throw new Error(
      "next-step: no Anthropic credentials. Set up `kuzushi auth login anthropic`, " +
        "ANTHROPIC_OAUTH_TOKEN, or ANTHROPIC_API_KEY.",
    );
  }

  const headers = {
    "content-type": "application/json",
    "anthropic-version": "2023-06-01",
  };
  if (oauthToken || envOauth) {
    headers.authorization = `Bearer ${oauthToken ?? envOauth}`;
    // Claude Code OAuth tokens require this beta tag on the Messages API.
    headers["anthropic-beta"] = "oauth-2025-04-20";
  } else {
    headers["x-api-key"] = apiKey;
  }

  const body = {
    model: modelId,
    system: request.systemPrompt ?? request.system_prompt ?? "",
    messages: request.messages ?? [],
    tools: (request.tools ?? []).map((t) => ({
      name: t.name,
      description: t.description,
      input_schema: t.input_schema ?? t.inputSchema,
    })),
    max_tokens: request.max_tokens ?? request.maxTokens ?? 4096,
  };

  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });

  const text = await response.text();
  if (!response.ok) {
    throw new Error(
      `next-step: Anthropic API ${response.status} ${response.statusText}: ${text.slice(0, 500)}`,
    );
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`next-step: Anthropic returned non-JSON body: ${text.slice(0, 200)}`);
  }

  const usage = parsed.usage ?? {};
  const cost_usd = approximateCostUsd(modelId, usage);

  // Walk content blocks. Per Anthropic's API, multiple blocks can appear
  // (e.g. text + tool_use). We surface the first tool_use as a ToolCall;
  // if there's none, the message is a Final.
  const blocks = Array.isArray(parsed.content) ? parsed.content : [];
  for (const block of blocks) {
    if (block?.type === "tool_use") {
      return {
        ok: true,
        step: "tool_call",
        call: {
          name: block.name,
          input: block.input ?? {},
          callId: block.id,
        },
        cost_usd,
      };
    }
  }

  // No tool_use → final.
  const finalText = blocks
    .filter((b) => b?.type === "text" && typeof b.text === "string")
    .map((b) => b.text)
    .join("");
  return {
    ok: true,
    step: "final",
    text: finalText,
    structured: maybeParseJson(finalText),
    cost_usd,
  };
}

/**
 * Approximate USD cost from Anthropic's `usage` block. Numbers are
 * rough — production should swap in a per-model rate card. The spend
 * ledger is the authoritative budget enforcer regardless of accuracy
 * here.
 */
function approximateCostUsd(modelId, usage) {
  const id = (modelId ?? "").toLowerCase();
  // ($/1k input tokens, $/1k output tokens).
  let inRate;
  let outRate;
  if (id.includes("haiku")) {
    inRate = 0.0008;
    outRate = 0.004;
  } else if (id.includes("opus")) {
    inRate = 0.015;
    outRate = 0.075;
  } else if (id.includes("sonnet")) {
    inRate = 0.003;
    outRate = 0.015;
  } else {
    inRate = 0.003;
    outRate = 0.015;
  }
  const input = (usage.input_tokens ?? 0) + (usage.cache_creation_input_tokens ?? 0);
  const output = usage.output_tokens ?? 0;
  return (input * inRate) / 1000 + (output * outRate) / 1000;
}

async function main() {
  if (process.argv[2] === "--oauth-login") {
    await runOAuthLogin(process.argv[3] ?? "openai-codex");
    return;
  }

  const request = JSON.parse(await readStdin());

  // Route on envelope type. Default = legacy single-shot via pi-agent-core.
  if (request.type === "next-step") {
    const result = await handleNextStep(request);
    process.stdout.write(JSON.stringify(result));
    return;
  }
  if (request.type === "ping") {
    const result = await handlePing(request);
    process.stdout.write(JSON.stringify(result));
    return;
  }

  const [{ Agent, default: DefaultAgent }, { getModel }] = await Promise.all([
    import("@mariozechner/pi-agent-core"),
    import("@mariozechner/pi-ai"),
  ]);
  const AgentCtor = Agent ?? DefaultAgent;
  if (!AgentCtor) throw new Error("@mariozechner/pi-agent-core did not export Agent");

  const [provider, modelId] = parseModelSpec(request.model);
  const model = getModel(provider, modelId);
  const { text, usage, errorMessage } = await runAgent(AgentCtor, model, request);

  // pi-agent-core swallows transport errors (auth 401, rate-limit 429,
  // upstream 5xx, network) and lands on `state.errorMessage` instead of
  // throwing. Surfacing that as `ok: false` here keeps callers from
  // mistaking an empty assistant turn for a deliberate "no result" — the
  // canonical symptom we hit was that a rotated OAuth token produced
  // {ok:true, text:"", cost_usd:0}, which downstream taint-iris-next
  // happily treated as a parse failure (and triggered its deterministic
  // fallback) instead of a fixable auth problem.
  if (!text && (errorMessage || (!usage?.inputTokens && !usage?.outputTokens))) {
    const reason =
      errorMessage ?? "agent produced no assistant turn and no token usage";
    process.stdout.write(JSON.stringify({ ok: false, error: reason }));
    return;
  }

  process.stdout.write(
    JSON.stringify({
      ok: true,
      text,
      structured: maybeParseJson(text),
      cost_usd: usage?.costUsd ?? 0,
      input_tokens: usage?.inputTokens ?? 0,
      output_tokens: usage?.outputTokens ?? 0,
    }),
  );
}

main().catch((error) => {
  process.stdout.write(
    JSON.stringify({
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    }),
  );
  process.exitCode = 1;
});

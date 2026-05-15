#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import {
  appendFileSync,
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

let bridgeLogPath = process.env.KUZUSHI_BRIDGE_LOG;
let bridgeVerbose = process.env.KUZUSHI_BRIDGE_VERBOSE === "1";

function bridgeLog(message) {
  process.stderr.write(message);
  if (!bridgeLogPath) return;
  try {
    appendFileSync(bridgeLogPath, message);
  } catch {
    /* diagnostic only */
  }
}

function runtimeOptions(request) {
  const options = request?.runtimeOptions ?? request?.runtime_options;
  return options && typeof options === "object" ? options : {};
}

function applyRuntimeOptions(request) {
  const options = runtimeOptions(request);
  const logPath = options.bridgeLogPath ?? options.bridge_log_path;
  if (typeof logPath === "string" && logPath.trim()) {
    bridgeLogPath = logPath.trim();
  }
  const verbose = options.bridgeVerbose ?? options.bridge_verbose;
  if (typeof verbose === "boolean") bridgeVerbose = verbose;
}

function mcpEnvironment(request) {
  const raw = runtimeOptions(request).mcpEnvironment ?? runtimeOptions(request).mcp_environment;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const env = {};
  for (const [key, value] of Object.entries(raw)) {
    if (typeof key !== "string" || typeof value !== "string") continue;
    const trimmed = value.trim();
    if (key && trimmed) env[key] = trimmed;
  }
  return env;
}

function mcpToolTimeoutMs(request) {
  const raw =
    runtimeOptions(request).mcpToolTimeoutMs ?? runtimeOptions(request).mcp_tool_timeout_ms;
  const value = Number(raw ?? process.env.KUZUSHI_MCP_TOOL_TIMEOUT_MS ?? 60_000);
  if (!Number.isFinite(value) || value <= 0) return 60_000;
  return Math.floor(value);
}

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

/**
 * Claude Code remote-session OAuth tokens are rate-limited on the
 * Sonnet / Opus tier unless the system prompt opens with the Claude Code
 * identity string. Haiku is unaffected. Without this prefix the API
 * returns a sub-second `429 rate_limit_error` whose message is literally
 * `"Error"` — easy to misread as a real quota signal.
 *
 * Prepend the identity string transparently whenever the bridge is about
 * to use an Anthropic OAuth bag. If the caller's system prompt already
 * starts with the line, leave it as-is so we don't double-prefix.
 */
const CLAUDE_CODE_IDENTITY_LINE = "You are Claude Code, Anthropic's official CLI for Claude.";

function applyClaudeCodeIdentityPrefix(systemPrompt) {
  const body = typeof systemPrompt === "string" ? systemPrompt : "";
  if (body.startsWith(CLAUDE_CODE_IDENTITY_LINE)) return body;
  if (!body.trim()) return CLAUDE_CODE_IDENTITY_LINE;
  return `${CLAUDE_CODE_IDENTITY_LINE}\n\n${body}`;
}

/**
 * Anthropic's Messages API checks for the Claude Code identity *as the
 * first content block* in the system field — a concatenated string like
 * "You are Claude Code...\n\nYou are an auditor." fails the check and
 * trips a sub-second rate_limit_error. Returning an array of text blocks
 * with the identity line as the first block is what pi-ai's OAuth path
 * does (see @earendil-works/pi-ai dist/providers/anthropic.js buildParams).
 */
function claudeCodeIdentitySystemBlocks(originalSystem) {
  const body = typeof originalSystem === "string" ? originalSystem : "";
  const blocks = [{ type: "text", text: CLAUDE_CODE_IDENTITY_LINE }];
  if (body.trim() && !body.startsWith(CLAUDE_CODE_IDENTITY_LINE)) {
    blocks.push({ type: "text", text: body });
  } else if (body.startsWith(CLAUDE_CODE_IDENTITY_LINE)) {
    const remainder = body.slice(CLAUDE_CODE_IDENTITY_LINE.length).replace(/^\n+/, "");
    if (remainder.trim()) blocks.push({ type: "text", text: remainder });
  }
  return blocks;
}

/**
 * Returns true if the bridge is about to authenticate to Anthropic via an
 * OAuth bearer (file bag or env token). Mirrors the precedence used by
 * `getApiKey` so the runAgent path agrees with handleNextStep/handlePing.
 */
async function anthropicOauthIsActive(request) {
  if ((await getFreshOAuthAccessTokenForProvider("anthropic")) ?? null) return true;
  if (providerAuthToken("anthropic")) return true;
  return false;
}

function providerEnvName(provider) {
  return `${provider.toUpperCase().replace(/[^A-Z0-9]/g, "_")}_API_KEY`;
}

/**
 * Pull a sampling temperature out of the request envelope. Accepts
 * camelCase (`temperature`) and snake_case (`temperature` as well — the
 * field name has no underscore). Returns undefined when absent or
 * not-a-number so the body field can be omitted entirely.
 */
function numericTemperature(request) {
  const candidate =
    request?.temperature ?? request?.samplingTemperature ?? request?.sampling_temperature;
  if (candidate === undefined || candidate === null) return undefined;
  const value = Number(candidate);
  if (!Number.isFinite(value)) return undefined;
  if (value < 0 || value > 2) return undefined;
  return value;
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
    const total = Number(usage.cost?.total ?? 0);
    if (Number.isFinite(total) && total > 0) {
      costUsd += total;
    } else {
      for (const key of ["input", "output", "cacheRead", "cacheWrite"]) {
        const value = Number(usage.cost?.[key] ?? 0);
        if (Number.isFinite(value)) costUsd += value;
      }
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

function extractTextFromResult(result) {
  if (typeof result === "string") return result;
  if (!result || typeof result !== "object") return "";
  if (typeof result.text === "string") return result.text;
  if (typeof result.output_text === "string") return result.output_text;
  if (typeof result.content === "string") return result.content;
  if (Array.isArray(result.output)) {
    const joined = result.output
      .map((part) => {
        if (typeof part === "string") return part;
        if (typeof part?.text === "string") return part.text;
        if (typeof part?.content === "string") return part.content;
        return "";
      })
      .join("");
    if (joined.trim()) return joined;
  }
  if (Array.isArray(result.content)) {
    const joined = result.content
      .map((part) => {
        if (typeof part === "string") return part;
        if (typeof part?.text === "string") return part.text;
        if (typeof part?.content === "string") return part.content;
        return "";
      })
      .join("");
    if (joined.trim()) return joined;
  }
  return "";
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

async function runOpenAiResponsesCall(provider, modelId, request) {
  if (provider === "openai-codex") {
    const bearerToken = await resolveOpenAiBearerToken(provider, request);
    if (!bearerToken) {
      throw new Error("openai-codex responses: no OAuth/API token available");
    }
    const { completeSimple, getModel } = await import("@earendil-works/pi-ai");
    const model = getModel(provider, modelId);
    if (!model) {
      throw new Error(`openai-codex responses: unknown model ${provider}:${modelId}`);
    }
    const message = await completeOpenAiCodexWithRetry(completeSimple, model, request, bearerToken);
    const text = (message.content ?? [])
      .filter((part) => part?.type === "text" && typeof part.text === "string")
      .map((part) => part.text)
      .join("");
    return {
      text: String(text || "").trim(),
      usage: codexMessageUsage(message, modelId),
    };
  }

  const base = resolveOpenAiResponsesBaseUrl();
  const payload = {
    model: modelId,
    input: request.prompt,
  };
  const systemPrompt = request.systemPrompt ?? request.system_prompt;
  if (systemPrompt) {
    payload.instructions = systemPrompt;
  }
  const args = [
    "-sS",
    "--connect-timeout",
    "10",
    "--max-time",
    String(process.env.KUZUSHI_OPENAI_RESPONSE_TIMEOUT_SEC || "60"),
    "-X",
    "POST",
    "-H",
    "Content-Type: application/json",
    "-d",
    JSON.stringify(payload),
    `${base}/responses`,
  ];
  const bearerToken = await resolveOpenAiBearerToken(provider, request);
  if (bearerToken) {
    args.splice(9, 0, "-H", `Authorization: Bearer ${bearerToken}`);
  }
  const result = spawnSync("curl", args, { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`openai responses curl failed: ${result.stderr?.slice(0, 300)}`);
  }
  const text = result.stdout ?? "";
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`openai responses returned non-JSON: ${text.slice(0, 200)}`);
  }
  if (parsed?.error) {
    throw new Error(`openai responses error: ${JSON.stringify(parsed.error).slice(0, 400)}`);
  }
  const outputText =
    parsed.output_text ??
    parsed.output
      ?.flatMap?.((item) => item.content ?? [])
      .map?.((part) => part.text ?? "")
      .join?.("") ??
    "";
  return {
    text: String(outputText || "").trim(),
    usage: openAiResponsesUsage(parsed?.usage, modelId),
  };
}

/// Coerce a pi-ai single-message `usage` into the `{ inputTokens, outputTokens,
/// costUsd }` shape the rest of the bridge uses. Falls back to the rate-card
/// approximation when pi-ai doesn't surface a cost (codex OAuth responses
/// generally don't carry one).
function codexMessageUsage(message, modelId) {
  const usage = message?.usage;
  if (!usage || typeof usage !== "object") return undefined;
  const inputTokens = Number(usage.input ?? usage.input_tokens ?? 0) || 0;
  const outputTokens = Number(usage.output ?? usage.output_tokens ?? 0) || 0;
  let costUsd = Number(usage.cost?.total ?? 0);
  if (!Number.isFinite(costUsd) || costUsd <= 0) {
    costUsd = approximateOpenAiCostUsd(modelId, {
      input_tokens: inputTokens,
      output_tokens: outputTokens,
    });
  }
  return { inputTokens, outputTokens, costUsd };
}

function openAiResponsesUsage(usage, modelId) {
  const safeUsage = usage && typeof usage === "object" ? usage : {};
  const inputTokens = Number(safeUsage.input_tokens ?? 0) || 0;
  const outputTokens = Number(safeUsage.output_tokens ?? 0) || 0;
  return {
    inputTokens,
    outputTokens,
    costUsd: approximateOpenAiCostUsd(modelId, safeUsage),
  };
}

async function completeOpenAiCodexWithRetry(completeSimple, model, request, bearerToken) {
  const context = {
    systemPrompt: request.systemPrompt ?? request.system_prompt,
    messages: [{ role: "user", content: request.prompt, timestamp: Date.now() }],
  };
  const options = {
    apiKey: bearerToken,
    reasoning:
      normalizeThinkingLevel(request.thinkingLevel) ??
      normalizeThinkingLevel(process.env.KUZUSHI_THINKING_LEVEL) ??
      "low",
  };
  const attempts = 3;
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    let message;
    try {
      message = await completeSimple(model, context, options);
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      if (!shouldRetryOpenAiCodexError(lastError.message) || attempt === attempts) {
        throw new Error(`openai-codex responses error: ${lastError.message}`);
      }
      await sleep(openAiCodexRetryDelayMs(attempt));
      continue;
    }

    if (!message?.errorMessage) return message;

    lastError = new Error(String(message.errorMessage));
    if (!shouldRetryOpenAiCodexError(lastError.message) || attempt === attempts) {
      throw new Error(`openai-codex responses error: ${lastError.message}`);
    }
    if (bridgeVerbose) {
      bridgeLog(
        `[bridge] openai-codex transient error on attempt ${attempt}/${attempts}: ${lastError.message}\n`,
      );
    }
    await sleep(openAiCodexRetryDelayMs(attempt));
  }
  throw new Error(`openai-codex responses error: ${lastError?.message ?? "unknown error"}`);
}

function shouldRetryOpenAiCodexError(message) {
  const normalized = String(message ?? "").toLowerCase();
  return [
    "websocket closed 1006",
    "websocket closed",
    "socket hang up",
    "econnreset",
    "etimedout",
    "network error",
    "fetch failed",
    "429",
    "rate limit",
    "temporarily unavailable",
    "internal server error",
    "bad gateway",
    "service unavailable",
    "gateway timeout",
  ].some((needle) => normalized.includes(needle));
}

function openAiCodexRetryDelayMs(attempt) {
  return Math.min(250 * 2 ** (attempt - 1), 1_000);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function resolveOpenAiBearerToken(provider, request) {
  const freshOauth =
    provider === "openai-codex"
      ? await getFreshOAuthAccessTokenForProvider("openai-codex")
      : undefined;
  return (
    freshOauth ??
    providerAuthToken(provider) ??
    configuredProviderApiKey(provider, request) ??
    process.env[providerEnvName(provider)] ??
    process.env.OPENAI_API_KEY ??
    undefined
  );
}

function resolveOpenAiResponsesBaseUrl(request = undefined) {
  const fallback = "https://api.openai.com/v1";
  const raw = String(
    request?.base_url ?? request?.baseUrl ?? process.env.OPENAI_BASE_URL ?? fallback,
  ).trim();
  if (!raw) return fallback;
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return fallback;
  }
  const hostname = parsed.hostname.toLowerCase();
  const isDefaultOpenAiHost = hostname === "api.openai.com";
  if (isDefaultOpenAiHost && parsed.port && parsed.port !== "443") {
    parsed.port = "";
  }
  const normalizedPath = parsed.pathname.replace(/\/+$/, "");
  if (normalizedPath === "" || normalizedPath === "/") {
    parsed.pathname = "/v1";
  }
  return parsed.toString().replace(/\/$/, "");
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

async function buildAgentTools(request) {
  const policy = normalizeAgentToolPolicy(request);
  const tools = [];
  if (policy.profile === WHITEBOX_STATIC_TOOL_PROFILE) {
    const available = createWhiteboxReadOnlyTools(request.cwd);
    for (const tool of policy.tools) {
      const canonicalName = WHITEBOX_STATIC_READ_ONLY_TOOLS.find(
        (allowed) => allowed.toLowerCase() === tool.toLowerCase(),
      );
      tools.push(available[canonicalName]);
    }
  }
  for (const mcpTool of await buildMcpAgentTools(request)) {
    tools.push(mcpTool);
  }
  return tools;
}

const KUZUSHI_MCP_SERVERS = [
  {
    profile: "tree-sitter",
    binary: process.env.KUZUSHI_MCP_TREESITTER_BIN || "kuzushi-mcp-treesitter",
  },
  {
    profile: "joern",
    binary: process.env.KUZUSHI_MCP_JOERN_BIN || "kuzushi-mcp-joern",
  },
  {
    profile: "codeql",
    binary: process.env.KUZUSHI_MCP_CODEQL_BIN || "kuzushi-mcp-codeql",
  },
];

const mcpServerHandles = new Map();

async function buildMcpAgentTools(request) {
  if (!agentMcpsEnabled(request)) return [];
  const tools = [];
  for (const spec of KUZUSHI_MCP_SERVERS) {
    const handle = await ensureMcpServer(spec, request);
    if (!handle) continue;
    for (const tool of handle.tools) {
      tools.push(wrapMcpToolForAgent(handle, tool));
    }
  }
  if (bridgeVerbose) {
    bridgeLog(
      `[kuzushi-bridge] MCP tools: ${tools.map((tool) => tool.name).join(", ") || "(none)"}\n`,
    );
  }
  return tools;
}

function agentMcpsEnabled(request) {
  if (request?.toolPolicy && request.toolPolicy.mcps === true) return true;
  const value = process.env.KUZUSHI_AGENT_MCPS;
  return value === "1" || value === "true";
}

async function ensureMcpServer(spec, request) {
  const cwd = mcpCwdFor(request);
  const cacheKey = `${spec.profile}:${cwd}`;
  const cached = mcpServerHandles.get(cacheKey);
  if (cached) {
    const handle = await cached;
    if (handle?.alive) return handle;
    mcpServerHandles.delete(cacheKey);
  }

  const promise = spawnMcpServer(spec, cwd, request);
  mcpServerHandles.set(cacheKey, promise);
  const handle = await promise;
  if (!handle) mcpServerHandles.delete(cacheKey);
  return handle;
}

function mcpCwdFor(request) {
  const candidate = request?.cwd;
  if (typeof candidate !== "string" || candidate.length === 0) return process.cwd();
  try {
    if (statSync(candidate).isDirectory()) return candidate;
  } catch {
    /* fall through */
  }
  return process.cwd();
}

async function spawnMcpServer(spec, cwd, request) {
  let child;
  try {
    child = spawn(spec.binary, [], {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, ...mcpEnvironment(request) },
      cwd: cwd ?? process.cwd(),
    });
  } catch (error) {
    bridgeLog(
      `[kuzushi-bridge] could not spawn MCP server ${spec.binary}: ${error.message ?? error}\n`,
    );
    return null;
  }

  const handle = {
    profile: spec.profile,
    binary: spec.binary,
    child,
    alive: true,
    timeoutMs: mcpToolTimeoutMs(request),
    nextId: 1,
    pending: new Map(),
    buffer: "",
    tools: [],
  };
  child.on("error", (error) => {
    bridgeLog(`[kuzushi-bridge] MCP server ${spec.binary} errored: ${error.message ?? error}\n`);
    handle.alive = false;
  });
  child.on("exit", () => {
    handle.alive = false;
    for (const [, resolver] of handle.pending) {
      resolver.reject(new Error(`MCP server ${spec.binary} exited`));
    }
    handle.pending.clear();
  });
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => receiveMcpStdout(handle, chunk));
  child.stderr.on("data", (chunk) => {
    if (bridgeVerbose) {
      bridgeLog(`[mcp:${spec.profile}] ${String(chunk).trimEnd()}\n`);
    }
  });

  try {
    await sendMcpRequest(handle, "initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "kuzushi-bridge", version: "0" },
    });
    const list = await sendMcpRequest(handle, "tools/list", undefined);
    if (Array.isArray(list?.tools)) {
      handle.tools = list.tools;
    }
  } catch (error) {
    bridgeLog(
      `[kuzushi-bridge] MCP server ${spec.binary} init failed: ${error.message ?? error}\n`,
    );
    handle.alive = false;
  }
  return handle;
}

function sendMcpRequest(handle, method, params) {
  return new Promise((resolve, reject) => {
    if (!handle.alive) {
      reject(new Error(`MCP server ${handle.binary} is not alive`));
      return;
    }
    const id = handle.nextId++;
    handle.pending.set(id, { resolve, reject });
    const body = { jsonrpc: "2.0", id, method };
    if (params !== undefined) body.params = params;
    handle.child.stdin.write(`${JSON.stringify(body)}\n`);
  });
}

function receiveMcpStdout(handle, chunk) {
  handle.buffer += chunk;
  let newlineIndex = handle.buffer.indexOf("\n");
  while (newlineIndex >= 0) {
    const line = handle.buffer.slice(0, newlineIndex).trim();
    handle.buffer = handle.buffer.slice(newlineIndex + 1);
    newlineIndex = handle.buffer.indexOf("\n");
    if (!line) continue;
    let payload;
    try {
      payload = JSON.parse(line);
    } catch {
      continue;
    }
    if (typeof payload?.id !== "number") continue;
    const resolver = handle.pending.get(payload.id);
    if (!resolver) continue;
    handle.pending.delete(payload.id);
    if (payload.error) {
      resolver.reject(
        new Error(`MCP error: ${payload.error.message ?? JSON.stringify(payload.error)}`),
      );
    } else {
      resolver.resolve(payload.result);
    }
  }
}

function wrapMcpToolForAgent(handle, mcpTool) {
  const safeName = mcpTool.name.replace(/[^a-zA-Z0-9_]/g, "_");
  return {
    name: safeName,
    label: safeName,
    description: `[mcp:${handle.profile}] ${mcpTool.description}`,
    parameters: mcpTool.inputSchema ??
      mcpTool.input_schema ?? {
        type: "object",
        additionalProperties: true,
      },
    execute: async (_toolCallId, params) => {
      const startedAt = Date.now();
      const verbose = bridgeVerbose;
      if (verbose) {
        bridgeLog(
          `[mcp:${handle.profile}] -> ${mcpTool.name} ${JSON.stringify(params ?? {}).slice(0, 200)}\n`,
        );
      }
      const timeoutMs = handle.timeoutMs;
      const call = sendMcpRequest(handle, "tools/call", {
        name: mcpTool.name,
        arguments: params ?? {},
      });
      let timer;
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`MCP tool ${mcpTool.name} timed out after ${timeoutMs}ms`)),
          timeoutMs,
        );
      });

      let result;
      try {
        result = await Promise.race([call, timeout]);
      } catch (error) {
        const text = `MCP tool ${mcpTool.name} failed: ${error?.message ?? error}`;
        if (verbose) bridgeLog(`[mcp:${handle.profile}] !! ${text}\n`);
        return { content: [{ type: "text", text }], details: { error: text } };
      } finally {
        clearTimeout(timer);
      }

      const text =
        Array.isArray(result?.content) && result.content[0]?.text
          ? String(result.content[0].text)
          : JSON.stringify(result, null, 2);
      if (verbose) {
        bridgeLog(
          `[mcp:${handle.profile}] <- ${mcpTool.name} ${Date.now() - startedAt}ms ${text.length}B\n`,
        );
      }
      return {
        content: [{ type: "text", text }],
        details: result,
      };
    },
  };
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

function subscribeMessageEnd(agent, onMessageEnd) {
  if (typeof agent?.subscribe !== "function") return;
  agent.subscribe((event) => {
    if (event?.type !== "message_end") return;
    onMessageEnd(event.message);
  });
}

function sanitizeMaxOutputTokens(request) {
  const raw = request.maxOutputTokens ?? request.max_output_tokens ?? request.maxTokens;
  if (typeof raw !== "number" || !Number.isFinite(raw) || raw <= 0) {
    return null;
  }
  return Math.floor(raw);
}

function makeStreamFnWithMaxTokens(maxOutputTokens) {
  let streamSimplePromise;
  return function streamFnWithMaxTokens(model, llmContext, options) {
    streamSimplePromise =
      streamSimplePromise ?? import("@earendil-works/pi-ai").then((mod) => mod.streamSimple);
    return (async function* () {
      const streamSimple = await streamSimplePromise;
      const stream = streamSimple(model, llmContext, {
        ...options,
        maxTokens: maxOutputTokens,
      });
      for await (const event of stream) yield event;
    })();
  };
}

async function runAgent(AgentCtor, model, request) {
  const [provider, modelId] = parseModelSpec(String(request.model ?? ""));
  const agentTools = await buildAgentTools(request);
  const allowedToolNames = new Set(agentTools.map((tool) => tool.name.toLowerCase()));
  let systemPrompt = appendStructuredOutputContract(
    request.systemPrompt ?? request.system_prompt ?? "",
    request.structuredOutput ?? request.structured_output ?? request.outputFormat,
  );
  if (model?.provider === "anthropic" && (await anthropicOauthIsActive(request))) {
    systemPrompt = applyClaudeCodeIdentityPrefix(systemPrompt);
  }
  const thinkingLevel = normalizeThinkingLevel(request.thinkingLevel) ?? "low";

  if (provider === "openai" || provider === "openai-codex") {
    const { text: openaiText, usage: openaiUsage } = await runOpenAiResponsesCall(
      provider,
      modelId,
      { ...request, systemPrompt },
    );
    if (!openaiText) {
      throw new Error(`openai responses returned empty output_text for ${provider}:${modelId}`);
    }
    writeDebugDump({
      model,
      agentTools: [],
      thinkingLevel,
      request,
      systemPrompt,
      text: openaiText,
    });
    writeFullPromptDump(request);
    return {
      text: openaiText,
      usage: openaiUsage,
      errorMessage: undefined,
      truncated: false,
      stopReason: undefined,
    };
  }

  const maxOutputTokens = sanitizeMaxOutputTokens(request);
  const streamFn = maxOutputTokens ? makeStreamFnWithMaxTokens(maxOutputTokens) : undefined;
  const temperature = numericTemperature(request);
  const initialState = {
    systemPrompt,
    model,
    tools: agentTools,
    messages: [],
    thinkingLevel,
  };
  if (temperature !== undefined) {
    // pi-agent-core forwards options.temperature into the provider's
    // sampling param; null means "use provider default" so we only set
    // the field when the caller asked for a specific value.
    initialState.temperature = temperature;
  }
  const agent = new AgentCtor({
    initialState,
    ...(streamFn ? { streamFn } : {}),
    beforeToolCall: async ({ toolCall }) => {
      const name = toolCall?.name ?? "";
      if (isForbiddenWhiteboxTool(name)) {
        return { block: true, reason: `whitebox-static blocks execution/write tool ${name}` };
      }
      if (allowedToolNames.size > 0 && !allowedToolNames.has(String(name).toLowerCase())) {
        return { block: true, reason: `whitebox-static only allows configured read-only tools` };
      }
      return undefined;
    },
    getApiKey: async (provider) =>
      (await getFreshOAuthAccessTokenForProvider(provider)) ??
      providerAuthToken(provider) ??
      configuredProviderApiKey(provider, request) ??
      process.env[providerEnvName(provider)] ??
      inheritedOpenAiAuthToken(provider) ??
      (provider === "openai" ? process.env.OPENAI_API_KEY : undefined),
  });

  let text = "";
  subscribeText(agent, (delta) => {
    text += delta;
  });
  let truncated = false;
  let lastStopReason;
  subscribeMessageEnd(agent, (message) => {
    if (message?.role !== "assistant") return;
    if (typeof message.stopReason !== "string") return;
    lastStopReason = message.stopReason;
    if (message.stopReason === "length" || message.stopReason === "max_tokens") {
      truncated = true;
    }
  });
  if (bridgeVerbose) {
    agent.subscribe?.((event) => {
      if (event?.type === "agent_end") bridgeLog("[bridge] agent_end\n");
      else if (event?.type === "turn_end") {
        bridgeLog(`[bridge] turn_end stop=${event?.message?.stopReason ?? "?"}\n`);
      } else if (event?.type === "turn_start") bridgeLog("[bridge] turn_start\n");
      else if (event?.type === "tool_start") {
        bridgeLog(`[bridge] tool_start ${event?.toolCall?.name ?? "?"}\n`);
      } else if (event?.type === "tool_end") bridgeLog("[bridge] tool_end\n");
      else if (event?.type === "error") {
        bridgeLog(`[bridge] error: ${event?.message ?? JSON.stringify(event).slice(0, 200)}\n`);
      }
    });
  }

  if (typeof agent.prompt === "function") {
    const result = await agent.prompt(request.prompt);
    text += extractTextFromResult(result);
  } else if (typeof agent.run === "function") {
    const result = await agent.run(request.prompt);
    text += extractTextFromResult(result);
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
  const finalText = text.trim();
  if (!finalText) {
    let provider = "unknown";
    let modelId = "unknown";
    try {
      [provider, modelId] = parseModelSpec(String(request.model ?? ""));
    } catch {
      provider = String(model?.provider ?? "unknown");
      modelId = String(model?.id ?? "unknown");
    }
    const baseUrlSet = Boolean(process.env.OPENAI_BASE_URL);
    const openAiAuthSet = Boolean(
      process.env.OPENAI_API_KEY ??
        process.env.OPENAI_AUTH_TOKEN ??
        process.env.OPENAI_OAUTH_TOKEN ??
        inheritedOpenAiAuthToken(provider),
    );
    throw new Error(
      `empty_model_output provider=${provider} model=${modelId} ` +
        `OPENAI_BASE_URL=${baseUrlSet ? "set" : "unset"} ` +
        `OPENAI_AUTH=${openAiAuthSet ? "set" : "unset"}`,
    );
  }

  writeDebugDump({
    model,
    agentTools,
    thinkingLevel,
    request,
    systemPrompt,
    text: finalText,
  });
  writeFullPromptDump(request);

  return {
    text: finalText,
    usage: aggregateAgentUsage(agent),
    errorMessage: agent?.state?.errorMessage ?? undefined,
    truncated,
    stopReason: lastStopReason,
  };
}

function writeDebugDump({ model, agentTools, thinkingLevel, request, systemPrompt, text }) {
  const dumpPath = process.env.KUZUSHI_BRIDGE_DEBUG_DUMP;
  if (!dumpPath) return;
  try {
    const dump = {
      ts: Date.now(),
      model: describeModel(model),
      toolCount: agentTools.length,
      toolNames: agentTools.map((tool) => tool.name),
      thinkingLevel,
      promptLen: (request.prompt ?? "").length,
      promptHead: (request.prompt ?? "").slice(0, 1500),
      systemPromptLen: systemPrompt.length,
      systemPromptHead: systemPrompt.slice(0, 800),
      responseLen: text.length,
      responseHead: text.slice(0, 4000),
      responseTail: text.slice(-500),
    };
    appendFileSync(dumpPath, `${JSON.stringify(dump)}\n`);
  } catch {
    /* diagnostic only */
  }
}

function describeModel(model) {
  if (typeof model === "string") return model;
  for (const key of ["id", "name", "model", "modelId"]) {
    const value = model?.[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  try {
    return JSON.stringify(model);
  } catch {
    return String(model);
  }
}

function writeFullPromptDump(request) {
  const root = process.env.KUZUSHI_BRIDGE_DEBUG_FULL_PROMPT;
  if (!root) return;
  try {
    mkdirSync(root, { recursive: true });
    const filename = `prompt-${Date.now()}-${process.pid}.txt`;
    writeFileSync(path.join(root, filename), request.prompt ?? "");
  } catch {
    /* diagnostic only */
  }
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

function codexAuthPath(home = os.homedir()) {
  const codexHome = String(process.env.CODEX_HOME ?? "").trim();
  return path.join(codexHome ? path.resolve(codexHome) : path.join(home, ".codex"), "auth.json");
}

function readCodexAuth(home = os.homedir()) {
  const filePath = codexAuthPath(home);
  if (!existsSync(filePath)) return {};
  try {
    const parsed = JSON.parse(readFileSync(filePath, "utf8"));
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function inheritedOpenAiAuthToken(provider) {
  const normalized = String(provider ?? "")
    .trim()
    .toLowerCase();
  if (normalized !== "openai-codex" && normalized !== "codex" && normalized !== "openai") {
    return undefined;
  }
  const auth = readCodexAuth();
  const accessToken = nonEmptyString(auth?.tokens?.access_token);
  if (normalized === "openai-codex" || normalized === "codex") {
    return accessToken;
  }
  return nonEmptyString(auth?.OPENAI_API_KEY) ?? accessToken;
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
    return await import("@earendil-works/pi-ai/oauth");
  } catch (error) {
    throw new Error(
      `Could not load @earendil-works/pi-ai/oauth for OAuth login/refresh: ${
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
  if (provider === "openai-codex" || provider === "openai") {
    return process.env.OPENAI_AUTH_TOKEN ?? process.env.OPENAI_OAUTH_TOKEN;
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
    throw new Error(`@earendil-works/pi-ai/oauth does not expose a login flow for ${provider}`);
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
  if (provider === "openai-codex" || provider === "openai") {
    const t0 = Date.now();
    const result = await runAgent(
      null,
      { provider, id: modelId },
      {
        model: `${provider}:${modelId}`,
        system_prompt: "You are an auth ping probe. Reply with ok.",
        prompt: "ok",
        cwd: process.cwd(),
      },
    );
    const latency_ms = Date.now() - t0;

    const auth_mode = (await resolveOpenAiBearerToken(provider, request))
      ? "oauth-or-api-key"
      : process.env.OPENAI_BASE_URL
        ? "runtime-base-url"
        : "runtime";
    return {
      ok: true,
      auth_mode,
      model: modelId,
      latency_ms,
      input_tokens: 0,
      output_tokens: 0,
      cost_usd: 0,
      note: "openai-codex ping verifies provider round-trip; token/cost fields unavailable in this bridge path",
      text_preview: String(result.text ?? "").slice(0, 120),
    };
  }
  if (provider !== "anthropic") {
    throw new Error(`auth ping unsupported provider: ${provider}`);
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
  // Claude Code OAuth bags rate-limit Sonnet/Opus unless `system` is an
  // array whose first text block is exactly the Claude Code identity
  // line. A concatenated string with the identity prefix is NOT enough.
  if (oauthToken || envOauth) {
    body.system = claudeCodeIdentitySystemBlocks("");
  }
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
  if (provider === "openai" || provider === "openai-codex") {
    return handleOpenAiNextStep(provider, modelId, request);
  }
  if (provider !== "anthropic") {
    throw new Error(`next-step bridge does not support ${provider} models yet.`);
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

  const rawSystem = request.systemPrompt ?? request.system_prompt ?? "";
  const body = {
    model: modelId,
    system: oauthToken || envOauth ? claudeCodeIdentitySystemBlocks(rawSystem) : rawSystem,
    messages: request.messages ?? [],
    tools: (request.tools ?? []).map((t) => ({
      name: t.name,
      description: t.description,
      input_schema: t.input_schema ?? t.inputSchema,
    })),
    max_tokens: request.max_tokens ?? request.maxTokens ?? 4096,
  };
  // Sampling temperature when the caller wants determinism (deep-audit
  // verdict consistency, structured-output triage). Only set when
  // explicitly provided; otherwise let the provider default apply.
  const temperature = numericTemperature(request);
  if (temperature !== undefined) {
    body.temperature = temperature;
  }

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
        costUsd: cost_usd,
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
    costUsd: cost_usd,
  };
}

async function handleOpenAiNextStep(provider, modelId, request) {
  if (provider === "openai-codex") {
    return handleOpenAiCodexTextNextStep(provider, modelId, request);
  }

  const bearerToken = await resolveOpenAiBearerToken(provider, request);
  if (!bearerToken) {
    throw new Error(
      `next-step: no OpenAI credentials for ${provider}. Set up kuzushi auth login openai-codex, ` +
        "OPENAI_API_KEY, or the configured provider API key.",
    );
  }

  const payload = {
    model: modelId,
    input: openAiInputFromAnthropicMessages(request.messages ?? []),
    tools: (request.tools ?? []).map(openAiToolDefinition),
    max_output_tokens: request.max_tokens ?? request.maxTokens ?? 4096,
  };
  const systemPrompt = request.systemPrompt ?? request.system_prompt;
  if (systemPrompt) payload.instructions = systemPrompt;
  const temperature = numericTemperature(request);
  if (temperature !== undefined) payload.temperature = temperature;

  const response = await fetch(`${resolveOpenAiResponsesBaseUrl(request)}/responses`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${bearerToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(
      `next-step: OpenAI Responses API ${response.status} ${response.statusText}: ${text.slice(
        0,
        500,
      )}`,
    );
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`next-step: OpenAI returned non-JSON body: ${text.slice(0, 200)}`);
  }
  if (parsed?.error) {
    throw new Error(`next-step: OpenAI error: ${JSON.stringify(parsed.error).slice(0, 500)}`);
  }

  const usage = parsed.usage ?? {};
  const cost_usd = approximateOpenAiCostUsd(modelId, usage);
  const toolCall = firstOpenAiFunctionCall(parsed);
  if (toolCall) {
    return {
      ok: true,
      step: "tool_call",
      call: toolCall,
      cost_usd,
    };
  }

  const finalText = extractOpenAiOutputText(parsed);
  return {
    ok: true,
    step: "final",
    text: finalText,
    structured: maybeParseJson(finalText),
    cost_usd,
  };
}

async function handleOpenAiNextStepPreflight(provider, modelId, request) {
  if (provider === "openai-codex") {
    await runOpenAiResponsesCall(provider, modelId, {
      ...request,
      systemPrompt: "You are a tool-loop preflight probe. Reply with ok.",
      prompt: "Return ok.",
      maxOutputTokens: 16,
    });
    return {
      ok: true,
      step: "final",
      text: "ok",
      cost_usd: 0,
    };
  }

  const bearerToken = await resolveOpenAiBearerToken(provider, request);
  if (!bearerToken) {
    throw new Error(
      `next-step preflight: no OpenAI credentials for ${provider}. Set up kuzushi auth login ` +
        "openai-codex, OPENAI_API_KEY, or the configured provider API key.",
    );
  }
  const payload = {
    model: modelId,
    input: "Return ok.",
    max_output_tokens: 16,
  };
  const response = await fetch(`${resolveOpenAiResponsesBaseUrl(request)}/responses`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${bearerToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(
      `next-step preflight: OpenAI Responses API ${response.status} ${response.statusText}: ${text.slice(
        0,
        500,
      )}`,
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`next-step preflight: OpenAI returned non-JSON body: ${text.slice(0, 200)}`);
  }
  if (parsed?.error) {
    throw new Error(
      `next-step preflight: OpenAI error: ${JSON.stringify(parsed.error).slice(0, 500)}`,
    );
  }
  return {
    ok: true,
    step: "final",
    text: "ok",
    cost_usd: approximateOpenAiCostUsd(modelId, parsed.usage ?? {}),
  };
}

async function handleOpenAiCodexTextNextStep(provider, modelId, request) {
  const { text } = await runOpenAiResponsesCall(provider, modelId, {
    ...request,
    systemPrompt: openAiCodexNextStepSystemPrompt(request),
    prompt: openAiCodexNextStepPrompt(request),
  });
  const parsed = maybeParseJson(text);
  if (!parsed || typeof parsed !== "object") {
    throw new Error(`next-step: openai-codex returned non-JSON step: ${String(text).slice(0, 500)}`);
  }
  return openAiCodexTextStepResponse(parsed, text);
}

function openAiCodexNextStepSystemPrompt(request) {
  return [
    request.systemPrompt ?? request.system_prompt ?? "",
    "",
    "You are driving one step of a tool loop. Reply with exactly one JSON object and no prose.",
    'To call a tool, reply: {"step":"tool_call","call":{"name":"TOOL","input":{...},"callId":"unique-id"}}',
    'To finish, reply: {"step":"final","text":"...","structured":{... optional ...}}',
    "Use only the listed tools. Keep callId stable and unique.",
  ]
    .filter((part) => String(part).trim().length > 0)
    .join("\n");
}

function openAiCodexNextStepPrompt(request) {
  return [
    "Available tools:",
    JSON.stringify(request.tools ?? [], null, 2),
    "",
    "Conversation so far:",
    JSON.stringify(request.messages ?? [], null, 2),
    "",
    "Return the next JSON step now.",
  ].join("\n");
}

function openAiCodexTextStepResponse(parsed, rawText) {
  const step = String(parsed.step ?? "").trim();
  if (step === "tool_call") {
    const call = parsed.call;
    if (!call || typeof call !== "object" || typeof call.name !== "string") {
      throw new Error(`next-step: openai-codex tool_call missing call.name: ${rawText.slice(0, 500)}`);
    }
    return {
      ok: true,
      step: "tool_call",
      call: {
        name: call.name,
        input: call.input && typeof call.input === "object" ? call.input : {},
        callId: String(call.callId ?? call.call_id ?? `call_${Date.now()}`),
      },
      cost_usd: Number(parsed.cost_usd ?? parsed.costUsd ?? 0) || 0,
    };
  }
  if (step === "final") {
    const text = typeof parsed.text === "string" ? parsed.text : "";
    return {
      ok: true,
      step: "final",
      text,
      structured: parsed.structured ?? maybeParseJson(text),
      cost_usd: Number(parsed.cost_usd ?? parsed.costUsd ?? 0) || 0,
    };
  }
  throw new Error(`next-step: openai-codex returned unexpected step ${JSON.stringify(parsed.step)}`);
}

function openAiToolDefinition(tool) {
  return {
    type: "function",
    name: tool.name,
    description: tool.description,
    parameters: tool.input_schema ?? tool.inputSchema ?? { type: "object", properties: {} },
  };
}

function openAiInputFromAnthropicMessages(messages) {
  const input = [];
  for (const message of messages) {
    const role = message?.role === "assistant" ? "assistant" : "user";
    const content = message?.content;
    if (typeof content === "string") {
      input.push({ role, content });
      continue;
    }
    if (!Array.isArray(content)) continue;
    const textParts = [];
    for (const part of content) {
      if (typeof part === "string") {
        textParts.push(part);
      } else if (part?.type === "text" && typeof part.text === "string") {
        textParts.push(part.text);
      } else if (part?.type === "tool_use") {
        input.push({
          type: "function_call",
          call_id: part.id,
          name: part.name,
          arguments: JSON.stringify(part.input ?? {}),
        });
      } else if (part?.type === "tool_result") {
        input.push({
          type: "function_call_output",
          call_id: part.tool_use_id,
          output: String(part.content ?? ""),
        });
      }
    }
    if (textParts.length > 0) {
      input.push({ role, content: textParts.join("\n") });
    }
  }
  return input;
}

function firstOpenAiFunctionCall(parsed) {
  for (const item of Array.isArray(parsed?.output) ? parsed.output : []) {
    if (item?.type !== "function_call") continue;
    return {
      name: item.name,
      input: parseFunctionArguments(item.arguments),
      callId: item.call_id ?? item.id ?? `call_${Date.now()}`,
    };
  }
  return undefined;
}

function parseFunctionArguments(argumentsText) {
  if (!argumentsText) return {};
  try {
    return JSON.parse(argumentsText);
  } catch {
    return {};
  }
}

function extractOpenAiOutputText(parsed) {
  if (typeof parsed?.output_text === "string") return parsed.output_text;
  const chunks = [];
  for (const item of Array.isArray(parsed?.output) ? parsed.output : []) {
    if (item?.type === "message" && Array.isArray(item.content)) {
      for (const part of item.content) {
        if (typeof part?.text === "string") chunks.push(part.text);
      }
    }
  }
  return chunks.join("");
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

function approximateOpenAiCostUsd(modelId, usage) {
  const id = String(modelId ?? "").toLowerCase();
  let inRate = 0.00125;
  let outRate = 0.01;
  if (id.includes("mini")) {
    inRate = 0.00015;
    outRate = 0.0006;
  } else if (id.includes("gpt-5")) {
    inRate = 0.00125;
    outRate = 0.01;
  } else if (id.includes("gpt-4.1") || id.includes("gpt-4o")) {
    inRate = 0.005;
    outRate = 0.015;
  }
  const input =
    usage.input_tokens ??
    usage.inputTokens ??
    usage.prompt_tokens ??
    usage.promptTokens ??
    0;
  const output =
    usage.output_tokens ??
    usage.outputTokens ??
    usage.completion_tokens ??
    usage.completionTokens ??
    0;
  return ((Number(input) || 0) * inRate) / 1000 + ((Number(output) || 0) * outRate) / 1000;
}

async function main() {
  if (process.argv[2] === "--oauth-login") {
    await runOAuthLogin(process.argv[3] ?? "openai-codex");
    return;
  }

  const request = JSON.parse(await readStdin());
  applyRuntimeOptions(request);

  // Route on envelope type. Default = legacy single-shot via pi-agent-core.
  if (request.type === "next-step") {
    const result = await handleNextStep(request);
    process.stdout.write(JSON.stringify(result));
    return;
  }
  if (request.type === "next-step-preflight") {
    const [provider, modelId] = parseModelSpec(request.model);
    const result =
      provider === "openai" || provider === "openai-codex"
        ? await handleOpenAiNextStepPreflight(provider, modelId, request)
        : { ok: true, step: "final", text: "ok", cost_usd: 0 };
    process.stdout.write(JSON.stringify(result));
    return;
  }
  if (request.type === "ping") {
    const result = await handlePing(request);
    process.stdout.write(JSON.stringify(result));
    return;
  }

  const [{ Agent, default: DefaultAgent }, { getModel }] = await Promise.all([
    import("@earendil-works/pi-agent-core"),
    import("@earendil-works/pi-ai"),
  ]);
  const AgentCtor = Agent ?? DefaultAgent;
  if (!AgentCtor) throw new Error("@earendil-works/pi-agent-core did not export Agent");

  const [provider, modelId] = parseModelSpec(request.model);
  const model =
    provider === "openai" || provider === "openai-codex"
      ? { provider, id: modelId }
      : getModel(provider, modelId);
  const { text, usage, errorMessage, truncated, stopReason } = await runAgent(
    AgentCtor,
    model,
    request,
  );

  if (!text && (errorMessage || (!usage?.inputTokens && !usage?.outputTokens))) {
    const reason = errorMessage ?? "agent produced no assistant turn and no token usage";
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
      truncated,
      stopReason,
    }),
  );
}

function shutdownMcpServers() {
  for (const promiseOrHandle of mcpServerHandles.values()) {
    Promise.resolve(promiseOrHandle)
      .then((handle) => {
        if (!handle) return;
        try {
          handle.child?.stdin?.end?.();
        } catch {
          /* ignore */
        }
        try {
          handle.child?.kill?.();
        } catch {
          /* ignore */
        }
      })
      .catch(() => undefined);
  }
}

main()
  .catch((error) => {
    process.stdout.write(
      JSON.stringify({
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      }),
    );
    process.exitCode = 1;
  })
  .finally(() => {
    shutdownMcpServers();
    setImmediate(() => process.exit(process.exitCode ?? 0));
  });

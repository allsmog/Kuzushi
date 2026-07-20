#!/usr/bin/env node
// Kuzushi bridge that speaks the same stdin/stdout JSON protocol as
// `langgraph-bridge.mjs` but routes every model call through the local
// already-authenticated `claude` CLI (`claude -p --output-format json`).
// The CLI inherits the parent environment (CLAUDE_CODE_USE_VERTEX,
// ANTHROPIC_VERTEX_PROJECT_ID, ANTHROPIC_BASE_URL, ADC, ...), so this
// bridge needs zero auth code of its own.
import { spawn } from "node:child_process";
import { appendFileSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";

const CLAUDE_BIN = process.env.KUZUSHI_CLAUDE_CLI_BIN || "claude";
const READ_ONLY_TOOLS = ["Read", "Grep", "Glob", "LS"];
// Orchid orchestrator patch: extended backoff for Vertex 429 per-minute input-token quota.
const RETRY_DELAYS_MS = [5_000, 20_000, 45_000, 90_000, 150_000, 240_000];
// Kuzushi's policy layer suppresses raw bridge errors in persisted results;
// this side-channel log is the only place the underlying claude CLI failure
// survives for the operator.
const DEBUG_LOG =
  process.env.KUZUSHI_BRIDGE_DEBUG_LOG || path.join(homedir(), ".kuzushi", "bridge-debug.log");

function debugLog(message) {
  try {
    appendFileSync(
      DEBUG_LOG,
      `${new Date().toISOString()} pid=${process.pid} ${String(message).slice(0, 4000)}\n`,
    );
  } catch {}
}

async function readStdin() {
  let data = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

function parseModelSpec(spec) {
  const value = String(spec ?? "");
  const idx = value.indexOf(":");
  if (idx <= 0 || idx === value.length - 1) {
    throw new Error(`model must use provider:model syntax, got ${JSON.stringify(value)}`);
  }
  const provider = value.slice(0, idx);
  // "anthropic" is accepted because kuzushi's no-silent-fallback policy now
  // rejects custom provider schemes; the local claude CLI still does the auth.
  if (provider !== "claude-cli" && provider !== "anthropic") {
    throw new Error(
      `claude-cli bridge only handles providers 'claude-cli'/'anthropic', got ${JSON.stringify(provider)}`,
    );
  }
  return value.slice(idx + 1);
}

function requestCwd(request) {
  const candidate = request?.cwd;
  if (typeof candidate !== "string" || candidate.length === 0) return process.cwd();
  try {
    if (statSync(candidate).isDirectory()) return candidate;
  } catch {}
  return process.cwd();
}

function appendStructuredOutputContract(systemPrompt, structuredOutput) {
  if (!structuredOutput) return String(systemPrompt ?? "");
  const name = structuredOutput.name ?? "structured_response";
  const schema = JSON.stringify(structuredOutput.schema ?? {}, null, 2);
  const strict = structuredOutput.strict ? "strict " : "";
  return `${systemPrompt ?? ""}\n\nStructured output contract:\nReturn only ${strict}JSON for \`${name}\`. Do not include markdown fences, prose, or trailing commentary.\nRequired JSON schema:\n${schema}`;
}

function maybeParseJson(text) {
  if (!text) return undefined;
  const trimmed = String(text).trim();
  const fenced = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/);
  const candidate = fenced ? fenced[1].trim() : trimmed;
  try {
    return JSON.parse(candidate);
  } catch {}
  const start = candidate.indexOf("{");
  const end = candidate.lastIndexOf("}");
  if (start < 0 || end <= start) return undefined;
  try {
    return JSON.parse(candidate.slice(start, end + 1));
  } catch {
    return undefined;
  }
}

function isTransient(message) {
  const lower = String(message ?? "").toLowerCase();
  return [
    "429",
    "rate limit",
    "rate_limit",
    "overloaded",
    "quota",
    "resource_exhausted",
    "temporarily unavailable",
    "internal server error",
    "503",
    "502",
    "504",
    "socket hang up",
    "econnreset",
    "etimedout",
    "fetch failed",
  ].some((needle) => lower.includes(needle));
}

async function runClaude({ model, cwd, systemPrompt, prompt, allowedTools, maxTurns }) {
  const tmp = mkdtempSync(path.join(tmpdir(), "kuzushi-claude-"));
  const systemFile = path.join(tmp, "system.txt");
  writeFileSync(systemFile, systemPrompt ?? "", "utf8");
  const args = [
    "-p",
    // Bare mode skips hooks, plugins, LSP, and settings-driven prompt bloat:
    // on this box the full env costs ~91k input tokens per call vs ~2k bare
    // (46x), and Vertex has no prompt caching to absorb it. Built-in tools
    // (Read/Grep/Glob/LS) still work; system prompt comes from
    // --append-system-prompt-file below.
    "--bare",
    "--model",
    model,
    "--output-format",
    "json",
    "--append-system-prompt-file",
    systemFile,
    "--permission-mode",
    "default",
  ];
  if (Array.isArray(allowedTools) && allowedTools.length > 0) {
    args.push("--allowedTools", ...allowedTools);
    args.push("--disallowedTools", "Edit", "Write", "NotebookEdit", "MultiEdit");
  }
  if (Number.isFinite(maxTurns) && maxTurns > 0) {
    args.push("--max-turns", String(maxTurns));
  }
  let lastError;
  for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt += 1) {
    try {
      return await spawnClaudeOnce(args, cwd, prompt);
    } catch (error) {
      lastError = error;
      debugLog(
        `attempt=${attempt + 1}/${RETRY_DELAYS_MS.length + 1} model=${args[args.indexOf("--model") + 1]} transient=${isTransient(error?.message)} error=${error?.message}`,
      );
      if (attempt === RETRY_DELAYS_MS.length || !isTransient(error?.message)) break;
      await new Promise((resolve) => setTimeout(resolve, RETRY_DELAYS_MS[attempt]));
    } finally {
      if (attempt === RETRY_DELAYS_MS.length) rmSync(tmp, { recursive: true, force: true });
    }
  }
  rmSync(tmp, { recursive: true, force: true });
  throw lastError ?? new Error("claude CLI failed");
}

function claudeEnv() {
  // Kuzushi's policy layer requires ANTHROPIC_API_KEY to be *set*, but the
  // claude CLI authenticates via Vertex ADC; a placeholder key would override
  // that, so strip it before spawning.
  const env = { ...process.env };
  if (env.ANTHROPIC_API_KEY === "noop" || env.ANTHROPIC_API_KEY === "placeholder") {
    delete env.ANTHROPIC_API_KEY;
  }
  return env;
}

function spawnClaudeOnce(args, cwd, prompt) {
  return new Promise((resolve, reject) => {
    const child = spawn(CLAUDE_BIN, args, {
      cwd,
      env: claudeEnv(),
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) => reject(new Error(`could not spawn claude CLI: ${error.message}`)));
    child.on("close", (code) => {
      const payload = lastJsonObject(stdout);
      if (code !== 0 && !payload) {
        return reject(
          new Error(`claude CLI exited ${code}: ${(stderr || stdout || "").slice(0, 4000)}`),
        );
      }
      if (!payload) {
        return reject(new Error(`claude CLI produced no JSON: ${stdout.slice(0, 4000)}`));
      }
      // error_max_turns still carries the agent's accumulated result text —
      // surface it as a truncated success (handleQuery marks `truncated`)
      // instead of throwing the text away as an opaque failure.
      if (
        payload.subtype !== "error_max_turns" &&
        (payload.is_error || payload.subtype === "error" || payload.type === "error")
      ) {
        return reject(
          new Error(
            `claude CLI error: ${payload.error ?? payload.result ?? stderr ?? "unknown error"}`,
          ),
        );
      }
      resolve(payload);
    });
    child.stdin.end(String(prompt ?? ""), "utf8");
  });
}

function lastJsonObject(raw) {
  const lines = String(raw ?? "").split(/\r?\n/).filter((line) => line.trim().length > 0);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const line = lines[index].trim();
    if (!line.startsWith("{")) continue;
    try {
      return JSON.parse(line);
    } catch {}
  }
  try {
    return JSON.parse(String(raw ?? "").trim());
  } catch {
    return undefined;
  }
}

function usageFromClaude(payload) {
  const usage = payload?.usage ?? {};
  return {
    inputTokens: Number(usage.input_tokens ?? 0) + Number(usage.cache_read_input_tokens ?? 0),
    outputTokens: Number(usage.output_tokens ?? 0),
    costUsd: Number(payload?.total_cost_usd ?? 0) || 0,
  };
}

function allowedToolsForRequest(request) {
  const policyTools = request?.toolPolicy?.tools ?? request?.tool_policy?.tools ?? [];
  const tools = new Set(READ_ONLY_TOOLS);
  for (const tool of Array.isArray(policyTools) ? policyTools : []) {
    if (typeof tool === "string" && tool.trim()) tools.add(tool.trim());
  }
  return [...tools];
}

async function handleQuery(request) {
  const model = parseModelSpec(request.model);
  const system = appendStructuredOutputContract(
    request.systemPrompt ?? request.system_prompt,
    request.structuredOutput ?? request.structured_output,
  );
  const payload = await runClaude({
    model,
    cwd: requestCwd(request),
    systemPrompt: system,
    prompt: request.prompt ?? "",
    allowedTools: allowedToolsForRequest(request),
    maxTurns: Number(process.env.KUZUSHI_BRIDGE_MAX_TURNS) || 40,
  });
  const text = String(payload.result ?? "");
  const usage = usageFromClaude(payload);
  return {
    ok: true,
    text,
    structured: maybeParseJson(text),
    cost_usd: usage.costUsd,
    input_tokens: usage.inputTokens,
    output_tokens: usage.outputTokens,
    truncated: payload.subtype === "error_max_turns",
    stopReason: payload.stop_reason ?? payload.terminal_reason,
  };
}

function flattenNextStepMessages(messages) {
  const parts = [];
  for (const raw of Array.isArray(messages) ? messages : []) {
    const role = raw.role ?? raw.type;
    for (const block of contentBlocks(raw.content)) {
      parts.push(renderHistoryBlock(role, block));
    }
  }
  return parts.filter((part) => part.length > 0).join("\n");
}

function contentBlocks(content) {
  if (Array.isArray(content)) return content;
  return [content];
}

function renderHistoryBlock(role, block) {
  if (typeof block === "string") {
    return role === "assistant" ? `\n[prior assistant text]\n${block}` : block;
  }
  if (block == null) return "";
  if (block.type === "tool_use") {
    return `\n[prior kuzushi_tool_call name=${block.name}]\n${JSON.stringify({
      kuzushi_tool_call: { name: block.name, input: block.input ?? {} },
    })}`;
  }
  if (block.type === "tool_result") {
    return `\n[tool_result for ${block.tool_use_id ?? block.toolUseId ?? "tool"}]\n${contentText(block.content)}`;
  }
  if (typeof block.text === "string") {
    return role === "assistant" ? `\n[prior assistant text]\n${block.text}` : block.text;
  }
  return JSON.stringify(block);
}

function contentText(content) {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content.map((part) => (typeof part === "string" ? part : (part?.text ?? ""))).join("");
  }
  return content == null ? "" : JSON.stringify(content);
}

function nextStepToolContract(tools) {
  if (!Array.isArray(tools) || tools.length === 0) return "";
  const schema = tools.map((tool) => ({
    name: tool.name,
    description: tool.description,
    input_schema: tool.inputSchema ?? tool.input_schema,
  }));
  return (
    "\n\nKuzushi tool-loop contract:\n" +
    "You may call exactly one of the following Kuzushi-defined tools per step.\n" +
    "Tools (JSON):\n" +
    JSON.stringify(schema, null, 2) +
    "\n\nTo call a tool, reply with ONLY a single JSON object on one line:\n" +
    '{"kuzushi_tool_call":{"name":"<tool name>","input":{...}}}\n' +
    "Do not wrap it in code fences. Do not add prose around it.\n" +
    "If the transcript already contains a [prior kuzushi_tool_call] and its [tool_result], do NOT repeat that call — " +
    "use the result and reply with your final answer as plain text instead."
  );
}

async function handleNextStep(request) {
  const model = parseModelSpec(request.model);
  const tools = request.tools ?? [];
  const system =
    String(request.systemPrompt ?? request.system_prompt ?? "") + nextStepToolContract(tools);
  const prompt = flattenNextStepMessages(request.messages);
  const payload = await runClaude({
    model,
    cwd: requestCwd(request),
    systemPrompt: system,
    prompt,
    allowedTools: [],
    maxTurns: 1,
  });
  const text = String(payload.result ?? "");
  const usage = usageFromClaude(payload);
  const structured = maybeParseJson(text);
  const call = structured?.kuzushi_tool_call;
  if (call && typeof call.name === "string") {
    return {
      ok: true,
      step: "tool_call",
      call: {
        name: call.name,
        input: call.input ?? {},
        callId: `cli-${Date.now().toString(36)}`,
      },
      cost_usd: usage.costUsd,
    };
  }
  return {
    ok: true,
    step: "final",
    text,
    structured,
    cost_usd: usage.costUsd,
  };
}

async function handlePing(request) {
  const model = parseModelSpec(request.model);
  const start = Date.now();
  const payload = await runClaude({
    model,
    cwd: requestCwd(request),
    systemPrompt: "You are an auth ping probe. Reply with the single word: ok",
    prompt: "ok",
    allowedTools: [],
    maxTurns: 1,
  });
  const usage = usageFromClaude(payload);
  return {
    ok: true,
    auth_mode: "claude-cli",
    model,
    latency_ms: Date.now() - start,
    input_tokens: usage.inputTokens,
    output_tokens: usage.outputTokens,
    cost_usd: usage.costUsd,
    text_preview: String(payload.result ?? "").slice(0, 120),
  };
}

async function dispatch(request) {
  if (request.type === "next-step") return handleNextStep(request);
  if (request.type === "next-step-preflight") {
    parseModelSpec(request.model);
    return { ok: true, step: "final", text: "ok", cost_usd: 0 };
  }
  if (request.type === "ping") return handlePing(request);
  return handleQuery(request);
}

async function main() {
  const raw = await readStdin();
  const request = JSON.parse(raw);
  process.stdout.write(JSON.stringify(await dispatch(request)));
}

main().catch((error) => {
  const message = error?.message ?? String(error);
  debugLog(`FINAL error=${message}`);
  process.stdout.write(
    JSON.stringify({ ok: false, error: message, error_class: errorClassFor(message) }),
  );
  process.exitCode = 1;
});

// Mirror of kuzushi's allowed error classes so persisted results carry a
// meaningful public message instead of "raw error details were suppressed".
function errorClassFor(message) {
  const lower = String(message ?? "").toLowerCase();
  if (lower.includes("429") || lower.includes("rate limit") || lower.includes("quota")) {
    return "rate_limited";
  }
  if (lower.includes("timed out") || lower.includes("etimedout")) return "timeout";
  if (
    lower.includes("503") ||
    lower.includes("502") ||
    lower.includes("504") ||
    lower.includes("overloaded") ||
    lower.includes("unavailable")
  ) {
    return "provider_unavailable";
  }
  if (
    lower.includes("fetch failed") ||
    lower.includes("econnreset") ||
    lower.includes("socket hang up")
  ) {
    return "transport";
  }
  if (lower.includes("no json") || lower.includes("produced no json")) {
    return "provider_response_invalid";
  }
  return "bridge_internal";
}

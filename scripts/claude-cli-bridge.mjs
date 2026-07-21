#!/usr/bin/env node
// Kuzushi bridge that speaks the same stdin/stdout JSON protocol as
// `langgraph-bridge.mjs` but routes every model call through the local
// already-authenticated `claude` CLI (`claude -p --output-format json`).
// The CLI inherits the parent environment (CLAUDE_CODE_USE_VERTEX,
// ANTHROPIC_VERTEX_PROJECT_ID, ANTHROPIC_BASE_URL, ADC, ...), so this
// bridge needs zero auth code of its own.
//
// Hardening audit fixes (2026-07-20, items from the ops audit; this file is
// untracked so the change log lives here):
//  - Redaction policy for ~/.kuzushi/bridge-debug.log and error surfaces:
//    the CLI's stdout carries model result text (scanned proprietary source,
//    finding details) and is now summarized as a byte count instead of being
//    embedded raw in error messages / the debug log. stderr (CLI
//    diagnostics) stays, capped. Set KUZUSHI_BRIDGE_LOG_RAW=1 to opt back
//    into raw bodies while debugging.
//  - Env scrubbing: a real ANTHROPIC_API_KEY is also stripped when
//    CLAUDE_CODE_USE_VERTEX is set — a stale key would silently override
//    Vertex ADC auth (no-silent-fallback).
//  - bridge-debug.log is size-bounded: one-generation rotation at 5 MB
//    (.log -> .log.1); it previously grew without limit.
//  - error_max_turns: a truncated run no longer returns `structured` output;
//    when the caller demanded a structured contract the bridge fails with
//    error_class=provider_response_invalid instead of letting a cut-off
//    transcript masquerade as an authoritative triage verdict. Plain-text
//    queries keep `truncated: true` so callers can decide.
import { spawn } from "node:child_process";
import {
  appendFileSync,
  mkdtempSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
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

const DEBUG_LOG_ROTATE_BYTES = 5 * 1024 * 1024;

function debugLog(message) {
  try {
    rotateDebugLogIfOversized();
    appendFileSync(
      DEBUG_LOG,
      `${new Date().toISOString()} pid=${process.pid} ${String(message).slice(0, 4000)}\n`,
    );
  } catch {}
}

// One-generation rotation so the side-channel error log can never grow
// without bound (it previously had no cap at all).
function rotateDebugLogIfOversized() {
  try {
    if (statSync(DEBUG_LOG).size >= DEBUG_LOG_ROTATE_BYTES) {
      renameSync(DEBUG_LOG, `${DEBUG_LOG}.1`);
    }
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

async function runClaude({ model, cwd, systemPrompt, prompt, allowedTools, maxTurns, mcpServers }) {
  const tmp = mkdtempSync(path.join(tmpdir(), "kuzushi-claude-"));
  const systemFile = path.join(tmp, "system.txt");
  writeFileSync(systemFile, systemPrompt ?? "", "utf8");
  const args = [
    "-p",
    // Bare mode skips hooks, plugins, LSP, and settings-driven prompt bloat:
    // on this box the full env costs ~91k input tokens per call vs ~2k bare
    // (46x), and Vertex has no prompt caching to absorb it. Built-in tools
    // (Read/Grep/Glob/LS) still work; system prompt comes from
    // --append-system-prompt-file below. Bare mode still honors an explicit
    // --mcp-config, which carries the kuzushi MCP attachment plan below.
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
  const mcpAllowed = [];
  if (mcpServers && Object.keys(mcpServers).length > 0) {
    const mcpFile = path.join(tmp, "mcp.json");
    writeFileSync(mcpFile, JSON.stringify({ mcpServers }), "utf8");
    args.push("--mcp-config", mcpFile, "--strict-mcp-config");
    // Server-level allow: every tool the planned kuzushi MCP server exports.
    mcpAllowed.push(...Object.keys(mcpServers).map((name) => `mcp__${name}`));
  }
  if ((Array.isArray(allowedTools) && allowedTools.length > 0) || mcpAllowed.length > 0) {
    args.push("--allowedTools", ...(allowedTools ?? []), ...mcpAllowed);
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
  // that, so strip it before spawning. When Vertex mode is explicitly on,
  // strip ANY key — a stale real key silently switching the auth path is a
  // no-silent-fallback violation, not a convenience.
  const env = { ...process.env };
  const placeholder =
    env.ANTHROPIC_API_KEY === "noop" || env.ANTHROPIC_API_KEY === "placeholder";
  const vertex = env.CLAUDE_CODE_USE_VERTEX === "1" || env.CLAUDE_CODE_USE_VERTEX === "true";
  if (placeholder || (vertex && env.ANTHROPIC_API_KEY)) {
    delete env.ANTHROPIC_API_KEY;
  }
  return env;
}

// Redaction boundary for anything that reaches error messages or the debug
// log: stdout is model output (scanned source, finding text) and is reduced
// to a byte count; stderr is CLI diagnostics and stays, capped. Opt back
// into raw bodies with KUZUSHI_BRIDGE_LOG_RAW=1.
function describeFailure(stderr, stdout) {
  if (process.env.KUZUSHI_BRIDGE_LOG_RAW === "1") {
    return (stderr || stdout || "").slice(0, 4000);
  }
  const diagnostics = String(stderr ?? "").slice(0, 2000);
  const body = `stdout=${Buffer.byteLength(String(stdout ?? ""), "utf8")}B suppressed (may contain scanned source; KUZUSHI_BRIDGE_LOG_RAW=1 to include)`;
  return diagnostics.trim().length > 0 ? `${diagnostics} [${body}]` : body;
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
        return reject(new Error(`claude CLI exited ${code}: ${describeFailure(stderr, stdout)}`));
      }
      if (!payload) {
        return reject(new Error(`claude CLI produced no JSON: ${describeFailure(stderr, stdout)}`));
      }
      // error_max_turns still carries the agent's accumulated result text —
      // surface it as a truncated success (handleQuery marks `truncated`)
      // instead of throwing the text away as an opaque failure.
      if (
        payload.subtype !== "error_max_turns" &&
        (payload.is_error || payload.subtype === "error" || payload.type === "error")
      ) {
        // payload.result is model output — route it through the redaction
        // boundary rather than embedding scanned content in the error.
        const detail =
          payload.error ?? describeFailure(stderr, payload.result ?? "") ?? "unknown error";
        return reject(new Error(`claude CLI error: ${detail}`));
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

// Translate the artifact-gated MCP attachment plan (computed by
// `mcp_attachment_plan_for_target` in kuzushi-core) into a claude CLI
// `--mcp-config` server map. Same env contract as the langgraph bridge:
// `KUZUSHI_MCP_<NAME>_ARTIFACT` for the backing artifact and
// `KUZUSHI_MCP_READ_ROOTS` for the read capability.
function mcpServersForRequest(request) {
  const raw = request?.toolPolicy?.mcpsAttached ?? request?.tool_policy?.mcps_attached;
  const plan = Array.isArray(raw)
    ? raw.filter((entry) => typeof entry?.name === "string" && entry.name.length > 0)
    : [];
  debugLog(`mcp plan entries=${plan.length} names=${plan.map((entry) => entry.name).join(",")}`);
  if (plan.length === 0) return undefined;
  const readRoots = request?.toolPolicy?.mcpReadRoots ?? request?.tool_policy?.mcp_read_roots ?? [];
  const servers = {};
  for (const attachment of plan) {
    servers[attachment.name] = mcpServerEntry(attachment, readRoots);
  }
  return servers;
}

function mcpServerEntry(attachment, readRoots) {
  const token = attachment.name.toUpperCase().replaceAll("-", "_");
  const env = { KUZUSHI_MCP_READ_ROOTS: JSON.stringify(readRoots) };
  const artifact = attachment.artifactPath ?? attachment.artifact_path;
  if (typeof artifact === "string" && artifact.length > 0) {
    env[`KUZUSHI_MCP_${token}_ARTIFACT`] = artifact;
    if (attachment.name === "joern") env.KUZUSHI_JOERN_CPG = artifact;
  }
  return {
    command: process.env[`KUZUSHI_MCP_${token}_BIN`] || `kuzushi-mcp-${attachment.name}`,
    args: [],
    env,
  };
}

async function handleQuery(request) {
  const model = parseModelSpec(request.model);
  const structuredContract = request.structuredOutput ?? request.structured_output;
  const system = appendStructuredOutputContract(
    request.systemPrompt ?? request.system_prompt,
    structuredContract,
  );
  const payload = await runClaude({
    model,
    cwd: requestCwd(request),
    systemPrompt: system,
    prompt: request.prompt ?? "",
    allowedTools: allowedToolsForRequest(request),
    maxTurns: Number(process.env.KUZUSHI_BRIDGE_MAX_TURNS) || 40,
    mcpServers: mcpServersForRequest(request),
  });
  const text = String(payload.result ?? "");
  const usage = usageFromClaude(payload);
  const truncated = payload.subtype === "error_max_turns";
  if (truncated && structuredContract) {
    // A max-turns cut is not a final answer. Text that happens to parse as
    // JSON mid-transcript must never masquerade as an authoritative
    // structured verdict (e.g. a triage that silently dropped findings).
    const error = new Error(
      `claude CLI hit max turns before a final structured answer (cost $${usage.costUsd.toFixed(4)} already spent)`,
    );
    error.errorClass = "provider_response_invalid";
    throw error;
  }
  return {
    ok: true,
    text,
    structured: truncated ? undefined : maybeParseJson(text),
    cost_usd: usage.costUsd,
    input_tokens: usage.inputTokens,
    output_tokens: usage.outputTokens,
    truncated,
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
    JSON.stringify({
      ok: false,
      error: message,
      error_class: error?.errorClass ?? errorClassFor(message),
    }),
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

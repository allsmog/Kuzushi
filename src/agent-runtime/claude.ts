import { spawn as childSpawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import {
  type Options as ClaudeOptions,
  query as claudeQuery,
  type SDKAssistantMessage,
  type SDKMessage,
  type SDKResultMessage,
  type SDKToolProgressMessage,
  type SDKToolUseSummaryMessage,
  type SDKUserMessage,
  type SpawnedProcess,
  type SpawnOptions,
} from "@anthropic-ai/claude-agent-sdk";
import Anthropic from "@anthropic-ai/sdk";
import { publishAgentActivity, publishTaskActivity } from "../bus/activity.js";
import type { LlmCallCompleteEvent, LlmCallErrorEvent, LlmCallStartEvent } from "../bus/events.js";
import type { MessageBus } from "../bus/types.js";
import { getLogger } from "../logger.js";
import type { AgentRuntimeCredentials } from "../types.js";
import { normalizeCostUsd, toErrorMessage } from "../utils.js";
import type { AgentQueryExecutionResult } from "./execution.js";
import { buildSdkHooks } from "./sdk-hooks.js";
import type {
  AgentActivityPhase,
  AgentBatchRequest,
  AgentMessage,
  AgentQueryOptions,
  AgentQueryRequest,
  AgentRuntime,
  AgentSession,
} from "./types.js";

const log = getLogger("claude-runtime");

function isAbortRequested(options: AgentQueryOptions): boolean {
  return options.abortController?.signal.aborted === true;
}

// Operator escape hatch for proxies that reject `thinking.type=enabled`
// (e.g. some internal Anthropic-compatible gateways accept `adaptive`/`disabled`
// only). When set, every Claude path emits `thinking: { type: "disabled" }`.
export function thinkingForceDisabled(): boolean {
  return Boolean(process.env.KUZUSHI_DISABLE_THINKING);
}

// Detect a likely-incompatible proxy: ANTHROPIC_BASE_URL is set and the host
// is not anthropic.com. Internal gateways often reject `thinking.type=enabled`
// (the SDK's default for non-low effort). Returns the host so the caller can
// surface a helpful one-line warning at shell startup.
export function detectNonAnthropicProxy(): string | null {
  const url = process.env.ANTHROPIC_BASE_URL;
  if (!url) return null;
  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    return null;
  }
  if (host.endsWith("anthropic.com")) return null;
  return host;
}

// Idempotent banner: emit once per process lifetime when a non-Anthropic
// proxy is configured AND thinking isn't already force-disabled. Operators
// can silence with KUZUSHI_QUIET_PROXY_BANNER=1.
let proxyBannerEmitted = false;
export function warnIfNonAnthropicProxy(stream: NodeJS.WriteStream = process.stderr): void {
  if (proxyBannerEmitted) return;
  if (process.env.KUZUSHI_QUIET_PROXY_BANNER) return;
  if (thinkingForceDisabled()) return;
  const host = detectNonAnthropicProxy();
  if (!host) return;
  proxyBannerEmitted = true;
  stream.write(
    `[kuzushi] ANTHROPIC_BASE_URL points at ${host}. ` +
      `If requests fail with "thinking.type" errors, set KUZUSHI_DISABLE_THINKING=1 ` +
      `(silence this with KUZUSHI_QUIET_PROXY_BANNER=1).\n`,
  );
}

// Test-only reset for the idempotent banner state.
export function _resetProxyBannerForTests(): void {
  proxyBannerEmitted = false;
}

function abortResult(durationMs: number, numTurns: number, totalCostUsd: number): AgentMessage {
  return {
    type: "result",
    subtype: "error_aborted",
    errors: ["Aborted by operator"],
    durationMs,
    numTurns,
    totalCostUsd,
  };
}

/**
 * Extension of Anthropic.Message for responses that include parsed structured output.
 * The SDK's ParsedMessage type adds `parsed_output` when structured output (JSON schema)
 * is used, but the base Message type doesn't include it. This interface allows safe access
 * without double-casting through `unknown`.
 */
interface MessageWithParsedOutput extends Anthropic.Message {
  parsed_output?: unknown;
}

/**
 * Build a `spawnClaudeCodeProcess` hook that tracks each spawned Claude Code
 * subprocess in the provided Set. Auto-removes entries when a process exits.
 *
 * Why this exists: the SDK's `abortController` option is supposed to terminate
 * the subprocess when the signal fires, but in practice `context:build` with
 * randori stays stuck: the subprocess keeps running (and holding the terminal's
 * stdin state, breaking raw mode) long after `abort()` is called. Tracking the
 * handles lets the caller send SIGTERM/SIGKILL directly on abort or session
 * close — the one reliable way to stop the subprocess.
 *
 * Wraps node's `child_process.spawn` because `ChildProcess` already satisfies
 * the SDK's `SpawnedProcess` interface (per sdk.d.ts:3985 — "ChildProcess
 * already satisfies this interface").
 */
/**
 * Process-wide registry of every Claude Code subprocess spawned by this
 * runtime — across all sessions AND one-shot queries. Exists so the
 * shell's SIGINT handler has a single "kill everything" switch it can
 * pull without having to chase individual per-session sets through the
 * abort-controller plumbing. Belt-and-suspenders: if anything goes
 * wrong between controller.abort() and the per-scope listener, this
 * still makes Ctrl+C actually stop a hung subprocess.
 */
const globalTrackedProcesses = new Set<SpawnedProcess>();

function createTrackedSpawn(
  tracked: Set<SpawnedProcess>,
): (options: SpawnOptions) => SpawnedProcess {
  return (options: SpawnOptions): SpawnedProcess => {
    // `detached: true` puts the Claude subprocess in its own process
    // group via setsid(). Without this, the subprocess shares our pgrp
    // — and once it opens /dev/tty and issues TCSETA/TIOCSPGRP, the
    // kernel delivers terminal Ctrl+C SIGINT to the subprocess group
    // only. Our parent node process never sees Ctrl+C and the
    // onAbort chain never runs, which is exactly the "spinner keeps
    // spinning after Ctrl+C" symptom. Isolating the pgrp keeps terminal
    // signals aimed at us.
    //
    // Keep every child stdio stream off the real TTY. A process can flip
    // terminal mode through any inherited terminal fd, not just stdin; an
    // inherited stderr was enough for long context builds to put the parent
    // TUI back into cooked mode, where Ctrl+C is echoed as "^C" and Ink never
    // sees the byte. Pipe stderr and drain it instead.
    //
    // We intentionally do NOT call `proc.unref()` — we want the parent
    // to stay informed of 'exit' so the tracked set stays honest.
    const proc = childSpawn(options.command, options.args, {
      cwd: options.cwd,
      env: options.env,
      signal: options.signal,
      stdio: ["pipe", "pipe", "pipe"],
      detached: true,
    }) as unknown as SpawnedProcess;
    const stderr = (proc as { stderr?: NodeJS.ReadableStream }).stderr;
    // Buffer the tail of stderr so we can replay it when the subprocess
    // exits non-zero — operators were debugging "exit code 1" with no
    // visible cause until they discovered KUZUSHI_ABORT_DEBUG=1. The
    // *last* 8 KB of stderr is almost always the actionable error
    // ("--dangerously-skip-permissions cannot be used with root", auth
    // failures, JSON-schema rejections, etc.).
    const STDERR_TAIL_BYTES = 8 * 1024;
    let stderrTail = "";
    stderr?.on("data", (chunk: Buffer | string) => {
      const text = String(chunk);
      // Always live-tail when the operator opted in.
      if (process.env.KUZUSHI_ABORT_DEBUG) {
        try {
          process.stderr.write(text);
        } catch {
          /* best-effort debug forwarding */
        }
      }
      stderrTail = (stderrTail + text).slice(-STDERR_TAIL_BYTES);
    });
    tracked.add(proc);
    globalTrackedProcesses.add(proc);
    // child_process emits 'exit' once the process is gone — drop it from
    // both tracked sets so `killTrackedProcesses` doesn't try to kill a
    // ghost. On non-zero exit, replay the buffered stderr tail so the
    // operator sees the cause without re-running with KUZUSHI_ABORT_DEBUG=1.
    proc.once("exit", (code: number | null, signal: string | null) => {
      tracked.delete(proc);
      globalTrackedProcesses.delete(proc);
      if (
        !process.env.KUZUSHI_ABORT_DEBUG &&
        stderrTail.trim() &&
        ((typeof code === "number" && code !== 0) || signal !== null)
      ) {
        const exitDesc =
          typeof code === "number" ? `exit ${code}` : signal ? `signal ${signal}` : "unknown";
        try {
          process.stderr.write(
            `[claude-runtime] subprocess ${exitDesc} stderr tail (last ${STDERR_TAIL_BYTES} bytes):\n${stderrTail.trimEnd()}\n`,
          );
        } catch {
          /* best-effort */
        }
      }
    });
    return proc;
  };
}

/**
 * Nuclear option for Ctrl+C — SIGTERM every tracked Claude subprocess
 * regardless of which session/query spawned it, then escalate survivors
 * to SIGKILL after the normal grace window. Called from the shell's
 * SIGINT handler BEFORE the abort-controller chain runs, so the
 * subprocess is guaranteed to stop even if an abort listener was never
 * installed, raced with the spawn, or was blocked by a stuck await.
 *
 * Returns the number of processes that received SIGTERM, so callers
 * can log / diagnose.
 */
export function killAllClaudeSubprocesses(): number {
  const count = globalTrackedProcesses.size;
  if (count === 0) return 0;
  killTrackedProcesses(globalTrackedProcesses);
  return count;
}

/**
 * Send SIGTERM to every tracked subprocess, then after `graceMs` escalate
 * survivors to SIGKILL. Returns once the escalation timer is scheduled — does
 * not block on exit.
 */
function killTrackedProcesses(tracked: Set<SpawnedProcess>, graceMs = 500): void {
  if (tracked.size === 0) return;
  const survivors: SpawnedProcess[] = [];
  for (const proc of tracked) {
    if (proc.killed || proc.exitCode !== null) continue;
    try {
      // We spawn with `detached: true`, so `proc.pid` is the leader of
      // its own pgrp. Signalling the negative pid delivers to every
      // process in that group, killing any grandchildren the Claude
      // subprocess forked (e.g. ripgrep workers) in one shot. Falls
      // back to signalling the single proc if the pgrp kill fails.
      const pid = (proc as { pid?: number }).pid;
      if (typeof pid === "number" && pid > 0) {
        try {
          process.kill(-pid, "SIGTERM");
        } catch {
          proc.kill("SIGTERM");
        }
      } else {
        proc.kill("SIGTERM");
      }
      survivors.push(proc);
    } catch {
      /* process already gone */
    }
  }
  if (survivors.length === 0) return;
  setTimeout(() => {
    for (const proc of survivors) {
      if (proc.killed || proc.exitCode !== null) continue;
      try {
        const pid = (proc as { pid?: number }).pid;
        if (typeof pid === "number" && pid > 0) {
          try {
            process.kill(-pid, "SIGKILL");
          } catch {
            proc.kill("SIGKILL");
          }
        } else {
          proc.kill("SIGKILL");
        }
      } catch {
        /* already gone */
      }
    }
  }, graceMs).unref();
}

/**
 * The Claude Code CLI rejects `--dangerously-skip-permissions` when the
 * spawning process runs as root/sudo, exiting with code 1 and the message
 *   "--dangerously-skip-permissions cannot be used with root/sudo
 *    privileges for security reasons"
 *
 * That blocks every agentic detector in containers / CI runners that
 * default to UID 0 (Docker base images, Claude Code remote sandboxes,
 * GitHub Actions). This helper returns true only when it's safe to set
 * the flag — when the current effective UID isn't 0. The
 * `KUZUSHI_DANGEROUSLY_SKIP_PERMISSIONS` env var lets operators force
 * the historical behavior on either side: `1` to always set, `0` to
 * never set.
 */
/**
 * Directories that plan-mode subprocesses are allowed to read/write.
 * Without this, randori, carlini-threat-hunt and other artifact-producing tasks
 * silently retry-then-skip when sandboxed under plan mode (issue #24).
 *
 * The whitelist intentionally stays narrow: target dir (so the agent
 * can re-read sources without permission churn), the kuzushi run/plans
 * dirs (so artifacts land where the rest of the pipeline expects), and
 * Claude Code's plan-staging dir (where randori writes its threat
 * model spec).
 */
function planModeAllowedDirectories(cwd?: string): string[] {
  const dirs = new Set<string>();
  if (cwd) dirs.add(cwd);
  const home = process.env["HOME"];
  if (home) {
    dirs.add(`${home}/.kuzushi`);
    dirs.add(`${home}/.kuzushi/plans`);
    dirs.add(`${home}/.kuzushi/runs`);
    dirs.add(`${home}/.claude/plans`);
  }
  // Claude Code's well-known remote-sandbox path (mirrors the OAuth
  // resolver fallback list).
  dirs.add("/home/claude/.claude/plans");
  if (cwd) dirs.add(`${cwd}/.kuzushi`);

  // The SDK silently drops `additionalDirectories` entries that don't
  // exist on disk — `/root/.claude/plans` was getting whitelisted but
  // ignored, leaving randori writes still rejected (#29). Materialize
  // each path so the SDK accepts it, mode 0o700 to keep them
  // operator-private.
  for (const dir of dirs) {
    try {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    } catch {
      /* best-effort — a failed mkdir just means the SDK will drop
         the entry, which is what would have happened anyway */
    }
  }

  return [...dirs];
}

function shouldAllowSkipPermissions(): boolean {
  const override = process.env["KUZUSHI_DANGEROUSLY_SKIP_PERMISSIONS"];
  if (override === "1" || override?.toLowerCase() === "true") return true;
  if (override === "0" || override?.toLowerCase() === "false") return false;
  try {
    return typeof process.geteuid === "function" ? process.geteuid() !== 0 : true;
  } catch {
    return true;
  }
}

// Prevent EPIPE from crashing the process when Claude SDK subprocesses die.
// Multiple concurrent query() calls each spawn a Claude Code subprocess;
// if one exits early the parent may write to a closed pipe.
for (const stream of [process.stdout, process.stderr]) {
  stream.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EPIPE" || err.code === "ERR_STREAM_DESTROYED") return;
    throw err;
  });
}

/**
 * Subset of fields we read off each SDK content block to detect tool-use
 * activity. The SDK ships `BetaContentBlock` as a discriminated union, but
 * `mapMessage` already spreads to `Record<string, unknown>` so we work
 * against that loose shape here.
 */
interface ToolUseBlockShape {
  type?: unknown;
  name?: unknown;
  input?: unknown;
}

/**
 * Emit `task:activity` (always — drives the spinner subtitle) and
 * `${phase}:agent-activity` (only when both `phase` and `fingerprint` are
 * set — drives the "N agents active" counter) for any tool-use blocks
 * inside an SDK assistant message.
 *
 * Best-effort: every publish is wrapped in the helpers' own try/catch so a
 * broken subscriber never takes down the SDK loop.
 */
function emitActivityForAssistant(
  bus: MessageBus | null,
  contentBlocks: unknown,
  ctx: {
    runId?: string | null;
    taskId?: string;
    fingerprint?: string;
    phase?: AgentActivityPhase;
  },
): void {
  if (!bus || !Array.isArray(contentBlocks)) return;
  const taskId = ctx.taskId ?? "agent-runtime";
  const runId = ctx.runId ?? undefined;
  for (const raw of contentBlocks as ToolUseBlockShape[]) {
    if (!raw || raw.type !== "tool_use") continue;
    const toolName = typeof raw.name === "string" && raw.name.length > 0 ? raw.name : "tool";
    publishTaskActivity(bus, taskId, `Calling ${toolName}…`, { runId });
    if (ctx.phase && ctx.fingerprint) {
      publishAgentActivity(bus, ctx.phase, ctx.fingerprint, "tool-start", {
        toolName,
        toolInput: isPlainObject(raw.input) ? raw.input : undefined,
      });
    }
  }
}

/**
 * Emit a terminal `${phase}:agent-activity` envelope so the report-worker
 * clears the fingerprint from the agents-active map (`done: true`).
 */
function emitActivityDone(
  bus: MessageBus | null,
  ctx: { fingerprint?: string; phase?: AgentActivityPhase },
): void {
  if (!bus || !ctx.phase || !ctx.fingerprint) return;
  publishAgentActivity(bus, ctx.phase, ctx.fingerprint, "tool-complete", { done: true });
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Agent runtime backed by the Claude Agent SDK (@anthropic-ai/claude-agent-sdk).
 *
 * Benefits over pi-ai:
 * - Uses Claude Code's native tool implementations (Read, Grep, Glob, Bash, etc.)
 * - Prompt caching via Claude's API
 * - .claude configuration support
 * - Session persistence and resume
 */
// Semaphore to limit concurrent Claude Code subprocess spawns.
// Each query() spawns a subprocess; too many concurrent processes causes
// rapid "process exited with code 1" failures.
const MAX_CONCURRENT_QUERIES = 5;
let activeQueries = 0;
// Slots marked as leaked — a prior caller timed out waiting, so we assume
// its holder died. A subsequent release pays the leak marker down instead
// of decrementing the live count, which keeps the effective capacity honest
// even if the "dead" subprocess later recovers and releases.
let leakedSlots = 0;
const waitQueue: Array<() => void> = [];

const SLOT_TIMEOUT_MS = 600_000; // 10 minutes max wait for a slot

function effectiveActive(): number {
  return Math.max(0, activeQueries - leakedSlots);
}

async function acquireSlot(): Promise<void> {
  if (effectiveActive() < MAX_CONCURRENT_QUERIES) {
    activeQueries++;
    return;
  }
  let forcedAcquire = false;
  await new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      // Remove from queue; treat one existing holder as leaked. The next
      // healthy release() will pay the leak marker down, so ultimately
      // capacity can never drift negative or permanently below MAX.
      const idx = waitQueue.indexOf(resolve);
      if (idx >= 0) waitQueue.splice(idx, 1);
      log.warn(
        "Semaphore slot timeout — assuming leaked slot from dead subprocess, force-acquiring",
      );
      leakedSlots++;
      forcedAcquire = true;
      resolve();
    }, SLOT_TIMEOUT_MS);
    waitQueue.push(() => {
      clearTimeout(timer);
      resolve();
    });
  });
  activeQueries++;
  if (forcedAcquire) {
    // leakedSlots was incremented in the timeout handler. We own a live slot
    // now; the leak marker remains until paid down by a subsequent release.
  }
}

function releaseSlot(): void {
  if (leakedSlots > 0) {
    // Pay down the leak marker instead of touching the live count; this
    // release "belongs" to the orphaned slot, not our caller.
    leakedSlots--;
  } else {
    activeQueries = Math.max(0, activeQueries - 1);
  }
  const next = waitQueue.shift();
  if (next) next();
}

/** Exported for tests only — observes internal semaphore state. */
export function __getSemaphoreState(): { active: number; leaked: number; waiting: number } {
  return { active: activeQueries, leaked: leakedSlots, waiting: waitQueue.length };
}

/** Exported for tests only — direct access to the SDK-message activity helpers. */
export const __activityInternals = {
  emitActivityForAssistant,
  emitActivityDone,
};

export class ClaudeAgentRuntime implements AgentRuntime {
  readonly id = "claude";
  private readonly config: AgentRuntimeCredentials | undefined;
  private readonly client: Anthropic;
  /**
   * True when this runtime has no API key configured — the Batch
   * API path will throw synchronously on every attempt. Surfaced so
   * callers (`agent-runtime/execution.ts`) can skip Batch outright
   * and avoid logging a fallback warning per batch (#28).
   */
  readonly oauthMode: boolean;
  bus: MessageBus | null = null;
  runId: string | null = null;

  constructor(config?: AgentRuntimeCredentials) {
    this.config = config;
    this.oauthMode = !config?.apiKey;
    this.client = new Anthropic({
      apiKey: config?.apiKey,
      baseURL: config?.baseUrl,
    });
  }

  createSession(baseOptions: AgentQueryOptions): AgentSession {
    return new ClaudeSession(baseOptions, this.config, this.bus, this.runId);
  }

  /**
   * Submit multiple tool-less prompts as a single Anthropic Batch API call.
   * 50% cost reduction, async processing. Polls until completion.
   */
  async queryBatch(
    requests: AgentBatchRequest[],
    baseOptions: AgentQueryOptions,
  ): Promise<Map<string, AgentQueryExecutionResult>> {
    if (requests.length === 0) return new Map();

    // Batch API requires an API key — OAuth mode can't use the direct SDK client.
    // Throw so callers fall back to sequential subprocess queries.
    if (!this.config?.apiKey) {
      throw new Error("Batch API requires an API key — not available in OAuth mode");
    }

    let model = baseOptions.model ?? "claude-sonnet-4-6";
    if (model.includes(":")) model = model.split(":").slice(1).join(":");
    const isHaiku = model.includes("haiku");

    // Minimum cacheable tokens by model (below this, cache_control silently wastes the write premium)
    const minCacheTokens =
      isHaiku || model.includes("opus") || model.includes("orchid") ? 4096 : 2048;

    const batchRequests = requests.map((req) => {
      const systemBlocks: Anthropic.TextBlockParam[] = [];
      const sysPrompt = req.systemPrompt ?? baseOptions.systemPromptPrefix;
      if (sysPrompt) {
        const estimatedTokens = Math.ceil(sysPrompt.length / 4);
        systemBlocks.push({
          type: "text" as const,
          text: sysPrompt,
          ...(estimatedTokens >= minCacheTokens
            ? { cache_control: { type: "ephemeral" as const, ttl: "1h" as const } }
            : {}),
        });
      }

      // Build output_config — effort errors on Haiku, so skip it
      const outputConfig: Record<string, unknown> = {};
      if (baseOptions.outputFormat) {
        outputConfig.format = {
          type: "json_schema" as const,
          schema: baseOptions.outputFormat.schema,
        };
      }
      if (baseOptions.effort && !isHaiku) {
        outputConfig.effort = baseOptions.effort;
      }

      const thinkingDisabled =
        baseOptions.thinkingDisabled ||
        isHaiku ||
        baseOptions.effort === "low" ||
        thinkingForceDisabled();

      const params: Anthropic.MessageCreateParamsNonStreaming = {
        model,
        max_tokens: baseOptions.maxOutputTokens ?? 16000,
        // When thinking is enabled, temperature must be 1 (or omitted).
        // Only set temperature explicitly when thinking is disabled.
        ...(baseOptions.temperature !== undefined
          ? { temperature: baseOptions.temperature }
          : thinkingDisabled
            ? { temperature: 0 }
            : {}),
        system: systemBlocks.length > 0 ? systemBlocks : undefined,
        messages: [{ role: "user" as const, content: req.prompt }],
        stream: false,
        service_tier: "standard_only",
        ...(Object.keys(outputConfig).length > 0 ? { output_config: outputConfig } : {}),
        ...(thinkingDisabled ? { thinking: { type: "disabled" as const } } : {}),
      };

      return { custom_id: req.id, params };
    });

    log.info(`Submitting batch of ${batchRequests.length} requests`);
    let batch = await this.client.messages.batches.create({ requests: batchRequests });
    log.info(`Batch ${batch.id} submitted, polling for completion`);

    const startMs = Date.now();
    // Exponential backoff: batches typically run for minutes. A fixed 2 s
    // poll wastes ~30 retrieves per minute after the first minute; this
    // starts at 2 s and grows to a 30 s cap.
    const INITIAL_POLL_MS = 2_000;
    const MAX_POLL_MS_PER_CYCLE = 30_000;
    const BACKOFF_FACTOR = 1.5;
    const MAX_POLL_MS = 600_000; // 10 minutes overall cap
    let pollDelay = INITIAL_POLL_MS;

    while (batch.processing_status !== "ended") {
      await new Promise((r) => setTimeout(r, pollDelay));
      pollDelay = Math.min(MAX_POLL_MS_PER_CYCLE, Math.floor(pollDelay * BACKOFF_FACTOR));
      batch = await this.client.messages.batches.retrieve(batch.id);
      if (Date.now() - startMs > MAX_POLL_MS) {
        await this.client.messages.batches.cancel(batch.id);
        throw new Error(`Batch ${batch.id} timed out after ${MAX_POLL_MS}ms`);
      }
    }

    const durationMs = Date.now() - startMs;
    log.info(
      `Batch ${batch.id} completed in ${durationMs}ms — succeeded: ${batch.request_counts.succeeded}, errored: ${batch.request_counts.errored}`,
    );

    // Stream results
    const results = new Map<string, AgentQueryExecutionResult>();
    const decoder = await this.client.messages.batches.results(batch.id);

    // Model-aware pricing at batch rate (50% of standard)
    const isOrchid = model.includes("orchid");
    const isOpus = model.includes("opus");
    const inputRate = (isHaiku ? 1 : isOrchid ? 25 : isOpus ? 5 : 3) * 0.5;
    const outputRate = (isHaiku ? 5 : isOrchid ? 125 : isOpus ? 25 : 15) * 0.5;

    for await (const item of decoder) {
      if (item.result.type === "succeeded") {
        const msg = item.result.message;
        const textBlock = msg.content.find((b): b is Anthropic.TextBlock => b.type === "text");
        const usage = msg.usage;
        const inputCost = (usage.input_tokens / 1_000_000) * inputRate;
        const outputCost = (usage.output_tokens / 1_000_000) * outputRate;
        const cacheReadTokens = usage.cache_read_input_tokens ?? 0;
        const cacheSavings = (cacheReadTokens / 1_000_000) * (inputRate * 0.9);

        results.set(item.custom_id, {
          resultText: textBlock?.text ?? "",
          structuredOutput: (msg as MessageWithParsedOutput).parsed_output ?? undefined,
          executionError: null,
          costUsd: normalizeCostUsd(inputCost + outputCost - cacheSavings),
        });
      } else {
        const errorMsg =
          item.result.type === "errored" ? JSON.stringify(item.result.error) : item.result.type;
        results.set(item.custom_id, {
          resultText: "",
          structuredOutput: undefined,
          executionError: errorMsg,
          costUsd: 0,
        });
      }
    }

    return results;
  }

  /**
   * Direct Anthropic API call for tool-less queries. Skips the Claude Code
   * subprocess entirely — no spawn overhead, no tool initialization.
   *
   * Best practices applied:
   * - Streaming with finalMessage() for large outputs (avoids HTTP timeouts)
   * - cache_control with 1h TTL for system prompt reuse across pipeline
   * - Typed error handling (RateLimitError, APIError)
   * - Effort not set on Haiku (would error)
   * - Right-sized max_tokens based on output needs
   */
  private async *queryDirect(request: AgentQueryRequest): AsyncIterable<AgentMessage> {
    const startedAtMs = Date.now();
    const turnRunId = this.runId ?? "";

    // Strip provider prefix
    let model = request.options.model ?? "claude-sonnet-4-6";
    if (model.includes(":")) model = model.split(":").slice(1).join(":");
    const isHaiku = model.includes("haiku");

    // Only apply cache_control when system prompt meets minimum token threshold.
    // Below the minimum, caching silently fails and we waste the 1.25x write premium.
    const minCacheTokens =
      isHaiku || model.includes("opus") || model.includes("orchid") ? 4096 : 2048;
    const systemBlocks: Anthropic.TextBlockParam[] = [];
    if (request.options.systemPromptPrefix) {
      const estimatedTokens = Math.ceil(request.options.systemPromptPrefix.length / 4);
      systemBlocks.push({
        type: "text",
        text: request.options.systemPromptPrefix,
        ...(estimatedTokens >= minCacheTokens
          ? { cache_control: { type: "ephemeral", ttl: "1h" } }
          : {}),
      });
    }

    // Emit llm:call-start
    if (this.bus) {
      try {
        await this.bus.publish<LlmCallStartEvent>({
          type: "llm:call-start",
          meta: { id: crypto.randomUUID(), timestamp: new Date().toISOString(), runId: turnRunId },
          payload: { model, promptLength: request.prompt.length, runId: turnRunId },
        });
      } catch {
        /* non-fatal */
      }
    }

    try {
      // Build output_config — effort errors on Haiku, so skip it
      const outputConfig: Record<string, unknown> = {};
      if (request.options.outputFormat) {
        outputConfig.format = {
          type: "json_schema" as const,
          schema: request.options.outputFormat.schema,
        };
      }
      if (request.options.effort && !isHaiku) {
        outputConfig.effort = request.options.effort;
      }

      // Right-size max_tokens: classification tasks need minimal output
      const maxTokens = request.options.maxOutputTokens ?? 16000;

      // Thinking: disable for classification, use adaptive+omitted for analysis
      // display: "omitted" skips streaming thinking tokens (faster time-to-first-text)
      const shouldDisableThinking =
        request.options.thinkingDisabled ||
        isHaiku ||
        request.options.effort === "low" ||
        thinkingForceDisabled();

      // Use streaming + finalMessage() to avoid HTTP timeouts on large outputs
      const stream = this.client.messages.stream({
        model,
        max_tokens: maxTokens,
        // When thinking is enabled, temperature must be 1 (or omitted).
        ...(request.options.temperature !== undefined
          ? { temperature: request.options.temperature }
          : shouldDisableThinking
            ? { temperature: 0 }
            : {}),
        metadata: { user_id: turnRunId || "kuzushi" },
        system: systemBlocks.length > 0 ? systemBlocks : undefined,
        messages: [{ role: "user", content: request.prompt }],
        ...(Object.keys(outputConfig).length > 0 ? { output_config: outputConfig } : {}),
        thinking: shouldDisableThinking
          ? { type: "disabled" as const }
          : { type: "adaptive" as const, display: "omitted" },
      });

      const response = await stream.finalMessage();
      const durationMs = Date.now() - startedAtMs;

      // Check stop_reason for truncation or refusal
      if (response.stop_reason === "refusal") {
        log.warn(`Model refused request (${model}, ${durationMs}ms)`);
        yield {
          type: "result",
          subtype: "error_runtime",
          errors: ["Model refused the request for safety reasons"],
          durationMs,
          numTurns: 0,
          totalCostUsd: 0,
        };
        return;
      }
      if (response.stop_reason === "max_tokens") {
        log.warn(`Response truncated at ${maxTokens} max_tokens (${model}, ${durationMs}ms)`);
      }

      // Extract cost from usage (model-aware pricing)
      const isOrchid = model.includes("orchid");
      const isOpus = model.includes("opus");
      const inputRate = isHaiku ? 1 : isOrchid ? 25 : isOpus ? 5 : 3;
      const outputRate = isHaiku ? 5 : isOrchid ? 125 : isOpus ? 25 : 15;
      const inputCost = (response.usage.input_tokens / 1_000_000) * inputRate;
      const outputCost = (response.usage.output_tokens / 1_000_000) * outputRate;
      const cacheReadTokens = response.usage.cache_read_input_tokens ?? 0;
      const cacheSavings = (cacheReadTokens / 1_000_000) * (inputRate * 0.9); // 90% savings on cached tokens
      const totalCostUsd = normalizeCostUsd(inputCost + outputCost - cacheSavings);

      // Extract text result
      const textBlock = response.content.find((b): b is Anthropic.TextBlock => b.type === "text");
      const resultText = textBlock?.text ?? "";

      // Emit llm:call-complete
      if (this.bus) {
        try {
          await this.bus.publish<LlmCallCompleteEvent>({
            type: "llm:call-complete",
            meta: {
              id: crypto.randomUUID(),
              timestamp: new Date().toISOString(),
              runId: turnRunId,
            },
            payload: {
              model,
              durationMs,
              tokensUsed: response.usage.input_tokens + response.usage.output_tokens,
              costUsd: totalCostUsd,
              runId: turnRunId,
            },
          });
        } catch {
          /* non-fatal */
        }
      }

      yield {
        type: "result",
        subtype: "success",
        result: resultText,
        structuredOutput: (response as MessageWithParsedOutput).parsed_output ?? undefined,
        durationMs,
        numTurns: 1,
        totalCostUsd,
      };
    } catch (error) {
      const durationMs = Date.now() - startedAtMs;
      const retryable =
        error instanceof Anthropic.RateLimitError || error instanceof Anthropic.InternalServerError;
      if (isAbortRequested(request.options)) {
        yield abortResult(durationMs, 0, 0);
        return;
      }

      log.error(
        `Direct API query failed (${durationMs}ms, retryable=${retryable}): ${toErrorMessage(error)}`,
      );

      if (this.bus) {
        try {
          await this.bus.publish<LlmCallErrorEvent>({
            type: "llm:call-error",
            meta: {
              id: crypto.randomUUID(),
              timestamp: new Date().toISOString(),
              runId: turnRunId,
            },
            payload: { model, error: toErrorMessage(error), retryable, runId: turnRunId },
          });
        } catch {
          /* non-fatal */
        }
      }

      yield {
        type: "result",
        subtype: "error_runtime",
        errors: [toErrorMessage(error)],
        durationMs,
        numTurns: 0,
        totalCostUsd: 0,
      };
    }
  }

  async *query(request: AgentQueryRequest): AsyncIterable<AgentMessage> {
    // Fast path: tool-less calls go directly to Anthropic API — no subprocess.
    // Only when an API key is available — OAuth mode must use subprocess path.
    if (
      !request.options.allowedTools?.length &&
      !request.options.disallowedTools?.length &&
      this.config?.apiKey
    ) {
      yield* this.queryDirect(request);
      return;
    }

    await acquireSlot();
    const startedAtMs = Date.now();
    let totalCostUsd = 0;
    let numTurns = 0;

    const options: ClaudeOptions = {
      cwd: request.options.cwd,
      permissionMode: mapPermissionMode(request.options.permissionMode),
      allowDangerouslySkipPermissions: shouldAllowSkipPermissions(),
      persistSession: false,
      // Under root's `plan`-mode fallback, the SDK enforces a strict
      // sandbox that blocks Read/Write outside the cwd. Tasks like
      // threat-model-randori legitimately need to read prior run dirs
      // and write plan artifacts. Whitelist the kuzushi/Claude-Code
      // workspace dirs so plan mode degrades gracefully (issue #24).
      additionalDirectories: planModeAllowedDirectories(request.options.cwd),
    };

    // Model
    if (request.options.model) {
      // Strip provider prefix (e.g. "anthropic:claude-sonnet-4-6" -> "claude-sonnet-4-6")
      const model = request.options.model.includes(":")
        ? request.options.model.split(":").slice(1).join(":")
        : request.options.model;
      options.model = model;
    }

    // Tools — use `tools` to restrict available tools (not just auto-approve).
    // With bypassPermissions, `allowedTools` only auto-approves but doesn't
    // restrict availability. `tools` actually removes tools from the model's context.
    if (request.options.allowedTools) {
      options.tools = request.options.allowedTools;
    }
    if (request.options.disallowedTools) {
      options.disallowedTools = request.options.disallowedTools;
    }

    // Structured output — pass schema to SDK which handles enforcement natively.
    // No system prompt injection needed — the SDK enforces the schema directly.
    if (request.options.outputFormat) {
      options.outputFormat = {
        type: "json_schema",
        schema: request.options.outputFormat.schema,
      };
    }

    // Budget
    if (request.options.maxBudgetUsd) {
      options.maxBudgetUsd = request.options.maxBudgetUsd;
    }

    // System prompt — use Claude Code's default with appended instructions
    if (request.options.systemPromptPrefix) {
      options.systemPrompt = {
        type: "preset",
        preset: "claude_code",
        append: request.options.systemPromptPrefix,
      };
    }

    // API key / base URL from config — always pass env so subprocess
    // inherits credentials even when agentRuntimeConfig is not set.
    const env: Record<string, string | undefined> = { ...process.env };
    if (this.config?.apiKey) {
      env.ANTHROPIC_API_KEY = this.config.apiKey;
    }
    if (this.config?.baseUrl) {
      env.ANTHROPIC_BASE_URL = this.config.baseUrl;
    }
    // Claude Code refuses to launch inside another Claude Code session.
    // Strip the nesting detection variable so subprocesses can run.
    delete env.CLAUDECODE;
    delete env.CLAUDE_CODE_SESSION_ID;
    // Raise the default 32K output token cap so large structured outputs
    // (e.g., PASTA threat models) don't get truncated mid-response.
    env.CLAUDE_CODE_MAX_OUTPUT_TOKENS = "100000";
    options.env = env;

    // Plugins — load Claude Code plugins in the subprocess
    if (request.options.plugins && request.options.plugins.length > 0) {
      options.plugins = request.options.plugins;
    }

    // PreToolUse input normalizer — rewrites camelCase aliases
    // (filePath → file_path, text → content, etc.) so the SDK's Zod
    // validation doesn't reject perfectly reasonable tool calls. Without
    // this, weaker sub-Claude models burn phases in a retry loop on
    // "Validation failed for tool Write".
    (options as unknown as { hooks?: Record<string, unknown> }).hooks = buildSdkHooks({
      onNormalize: (toolName, renames) => {
        log.debug(`${toolName} input normalized: ${renames.join(", ")}`);
      },
      canUseTool: request.options.canUseTool,
    });

    // Abort controller
    if (request.options.abortController) {
      options.abortController = request.options.abortController;
    }

    // Track the subprocess so we can directly SIGTERM/SIGKILL it when the
    // caller's abort signal fires. The SDK's own abort-on-signal handling
    // has proven unreliable for long-running phases (randori S2/S3 can
    // ignore the signal for 5+ minutes).
    const trackedProcesses = new Set<SpawnedProcess>();
    options.spawnClaudeCodeProcess = createTrackedSpawn(trackedProcesses);
    // When the caller's abortController fires, escalate to process kill.
    if (request.options.abortController) {
      const controllerSignal = request.options.abortController.signal;
      const onAbort = () => killTrackedProcesses(trackedProcesses);
      if (controllerSignal.aborted) onAbort();
      else controllerSignal.addEventListener("abort", onAbort, { once: true });
    }

    // Fallback model
    if (request.options.fallbackModel) {
      const fallback = request.options.fallbackModel.includes(":")
        ? request.options.fallbackModel.split(":").slice(1).join(":")
        : request.options.fallbackModel;
      options.fallbackModel = fallback;
    }

    // Effort level
    if (request.options.effort) {
      options.effort = request.options.effort === "xhigh" ? "high" : request.options.effort;
    }

    // Thinking — disable only when explicitly requested or for low-effort classification
    if (
      request.options.thinkingDisabled ||
      request.options.effort === "low" ||
      thinkingForceDisabled()
    ) {
      options.thinking = { type: "disabled" };
    }

    // Emit llm:call-start
    const turnRunId = this.runId ?? "";
    if (this.bus) {
      try {
        await this.bus.publish<LlmCallStartEvent>({
          type: "llm:call-start",
          meta: {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            runId: turnRunId,
          },
          payload: {
            model: request.options.model,
            promptLength: request.prompt.length,
            runId: turnRunId,
          },
        });
      } catch {
        // Non-fatal
      }
    }

    try {
      const queryResult = claudeQuery({
        prompt: request.prompt,
        options,
      });

      const activityCtx = {
        runId: this.runId,
        taskId: request.options.taskId,
        fingerprint: request.options.fingerprint,
        phase: request.options.phase,
      };

      for await (const message of queryResult) {
        // Surface tool-use activity to the bus BEFORE filtering through
        // mapMessage — assistant messages with tool-use blocks drive the
        // spinner subtitle and the "agents active" counter regardless of
        // whether the caller consumes the mapped form.
        if (message.type === "assistant") {
          const sdkAssistant = message as SDKAssistantMessage;
          emitActivityForAssistant(this.bus, sdkAssistant.message?.content, activityCtx);
        }

        const mapped = mapMessage(message);
        if (!mapped) continue;

        if (mapped.type === "result") {
          // Extract cost and metadata from SDK result
          const sdkResult = message as SDKResultMessage;
          totalCostUsd = normalizeCostUsd(sdkResult.total_cost_usd);
          numTurns = sdkResult.num_turns ?? 0;

          const durationMs = Date.now() - startedAtMs;

          // Clear the per-fingerprint agents-active row before yielding the
          // result so the UI counter drops as soon as the work is done.
          emitActivityDone(this.bus, activityCtx);

          if (sdkResult.subtype === "success" && "result" in mapped) {
            yield {
              type: "result",
              subtype: "success",
              result: mapped.result,
              structuredOutput: sdkResult.structured_output,
              durationMs,
              numTurns,
              totalCostUsd,
            };
          } else if ("errors" in mapped) {
            yield {
              type: "result",
              subtype: mapped.subtype,
              errors: mapped.errors,
              durationMs,
              numTurns,
              totalCostUsd,
            };
          }
        } else {
          yield mapped;
        }
      }

      // Emit llm:call-complete
      if (this.bus) {
        try {
          await this.bus.publish<LlmCallCompleteEvent>({
            type: "llm:call-complete",
            meta: {
              id: crypto.randomUUID(),
              timestamp: new Date().toISOString(),
              runId: turnRunId,
            },
            payload: {
              model: request.options.model,
              durationMs: Date.now() - startedAtMs,
              tokensUsed: 0,
              costUsd: totalCostUsd,
              runId: turnRunId,
            },
          });
        } catch {
          // Non-fatal
        }
      }
    } catch (error) {
      const durationMs = Date.now() - startedAtMs;
      const wasAborted = isAbortRequested(request.options);
      if (!wasAborted) {
        log.error(`Claude SDK query failed (${durationMs}ms): ${toErrorMessage(error)}`);
      }

      // Make sure the agents-active counter doesn't get stuck when the
      // SDK throws (subprocess crash, invalid auth, etc.).
      emitActivityDone(this.bus, {
        fingerprint: request.options.fingerprint,
        phase: request.options.phase,
      });

      if (wasAborted) {
        yield abortResult(durationMs, numTurns, totalCostUsd);
        return;
      }

      // Emit llm:call-error
      if (this.bus) {
        try {
          await this.bus.publish<LlmCallErrorEvent>({
            type: "llm:call-error",
            meta: {
              id: crypto.randomUUID(),
              timestamp: new Date().toISOString(),
              runId: turnRunId,
            },
            payload: {
              model: request.options.model,
              error: toErrorMessage(error),
              retryable: false,
              runId: turnRunId,
            },
          });
        } catch {
          // Non-fatal
        }
      }

      yield {
        type: "result",
        subtype: "error_runtime",
        errors: [toErrorMessage(error)],
        durationMs,
        numTurns,
        totalCostUsd,
      };
    } finally {
      // Defensive reap — normally the SDK's for-await exit cleans up, but
      // a thrown error path may leave survivors.
      killTrackedProcesses(trackedProcesses);
      releaseSlot();
    }
  }
}

/**
 * Async queue that implements AsyncIterable — used to feed SDKUserMessages
 * into a single `claudeQuery()` call. Push messages with `enqueue()`, end
 * with `done()`. The SDK subprocess stays alive as long as the iterable
 * hasn't completed.
 */
class MessageQueue implements AsyncIterable<SDKUserMessage>, AsyncIterator<SDKUserMessage> {
  private queue: SDKUserMessage[] = [];
  private resolve: ((result: IteratorResult<SDKUserMessage>) => void) | null = null;
  private isDone = false;

  enqueue(msg: SDKUserMessage): void {
    if (this.resolve) {
      const r = this.resolve;
      this.resolve = null;
      r({ done: false, value: msg });
    } else {
      this.queue.push(msg);
    }
  }

  done(): void {
    this.isDone = true;
    if (this.resolve) {
      const r = this.resolve;
      this.resolve = null;
      r({ done: true, value: undefined });
    }
  }

  next(): Promise<IteratorResult<SDKUserMessage>> {
    if (this.queue.length > 0) {
      return Promise.resolve({ done: false, value: this.queue.shift()! });
    }
    if (this.isDone) {
      return Promise.resolve({ done: true, value: undefined });
    }
    return new Promise((resolve) => {
      this.resolve = resolve;
    });
  }

  [Symbol.asyncIterator](): AsyncIterator<SDKUserMessage> {
    return this;
  }
}

/**
 * A session backed by a single Claude Code subprocess. Uses the SDK's
 * `query({ prompt: AsyncIterable<SDKUserMessage> })` to keep one process
 * alive across multiple turns. Each `query()` call pushes a user message
 * and yields response messages until a `result` arrives.
 */
class ClaudeSession implements AgentSession {
  private readonly messageQueue = new MessageQueue();
  private queryIterator: AsyncIterator<SDKMessage> | null = null;
  private closed = false;
  private slotAcquired = false;
  private queryInFlight = false; // Mutex: prevent concurrent query() calls
  // Tracks every Claude Code subprocess spawned by this session so close()
  // can directly kill them. The SDK's internal abort handling is unreliable
  // — context:build kept running for 5+ minutes past Ctrl+C without this.
  private readonly trackedProcesses = new Set<SpawnedProcess>();

  constructor(
    private readonly baseOptions: AgentQueryOptions,
    private readonly config: AgentRuntimeCredentials | undefined,
    readonly _bus: MessageBus | null,
    readonly _runId: string | null,
  ) {}

  private ensureStarted(): void {
    if (this.queryIterator) return;

    const options: ClaudeOptions = {
      cwd: this.baseOptions.cwd,
      permissionMode: mapPermissionMode(this.baseOptions.permissionMode),
      allowDangerouslySkipPermissions: shouldAllowSkipPermissions(),
      persistSession: false,
      additionalDirectories: planModeAllowedDirectories(this.baseOptions.cwd),
    };

    if (this.baseOptions.model) {
      const model = this.baseOptions.model.includes(":")
        ? this.baseOptions.model.split(":").slice(1).join(":")
        : this.baseOptions.model;
      options.model = model;
    }

    // Use `tools` to restrict available tools (not just auto-approve).
    // Consistent with the query() method which also uses `tools`.
    if (this.baseOptions.allowedTools) {
      options.tools = this.baseOptions.allowedTools;
    }
    if (this.baseOptions.disallowedTools) {
      options.disallowedTools = this.baseOptions.disallowedTools;
    }

    if (this.baseOptions.outputFormat) {
      options.outputFormat = {
        type: "json_schema",
        schema: this.baseOptions.outputFormat.schema,
      };
    }

    if (this.baseOptions.maxBudgetUsd) {
      options.maxBudgetUsd = this.baseOptions.maxBudgetUsd;
    }

    if (this.baseOptions.systemPromptPrefix) {
      options.systemPrompt = {
        type: "preset",
        preset: "claude_code",
        append: this.baseOptions.systemPromptPrefix,
      };
    }

    // Fallback model
    if (this.baseOptions.fallbackModel) {
      const fallback = this.baseOptions.fallbackModel.includes(":")
        ? this.baseOptions.fallbackModel.split(":").slice(1).join(":")
        : this.baseOptions.fallbackModel;
      options.fallbackModel = fallback;
    }

    // Effort level
    if (this.baseOptions.effort) {
      options.effort = this.baseOptions.effort === "xhigh" ? "high" : this.baseOptions.effort;
    }

    // Thinking — disable only when explicitly requested or for low-effort classification
    if (
      this.baseOptions.thinkingDisabled ||
      this.baseOptions.effort === "low" ||
      thinkingForceDisabled()
    ) {
      options.thinking = { type: "disabled" };
    }

    const env: Record<string, string | undefined> = { ...process.env };
    if (this.config?.apiKey) env.ANTHROPIC_API_KEY = this.config.apiKey;
    if (this.config?.baseUrl) env.ANTHROPIC_BASE_URL = this.config.baseUrl;
    delete env.CLAUDECODE;
    delete env.CLAUDE_CODE_SESSION_ID;
    env.CLAUDE_CODE_MAX_OUTPUT_TOKENS = "100000";
    options.env = env;

    if (this.baseOptions.abortController) {
      options.abortController = this.baseOptions.abortController;
    }

    // Plugins — load Claude Code plugins in the subprocess
    if (this.baseOptions.plugins && this.baseOptions.plugins.length > 0) {
      options.plugins = this.baseOptions.plugins;
    }

    // Same PreToolUse normalizer the one-shot query() uses — shared hook
    // set defined in sdk-hooks.ts. See rationale there.
    (options as unknown as { hooks?: Record<string, unknown> }).hooks = buildSdkHooks({
      onNormalize: (toolName, renames) => {
        log.debug(`session ${toolName} input normalized: ${renames.join(", ")}`);
      },
      canUseTool: this.baseOptions.canUseTool,
    });

    // Intercept subprocess spawn so close() can SIGTERM/SIGKILL directly.
    options.spawnClaudeCodeProcess = createTrackedSpawn(this.trackedProcesses);

    // Pass the async message queue as prompt — SDK keeps one subprocess alive
    const queryResult = claudeQuery({
      prompt: this.messageQueue,
      options,
    });

    this.queryIterator = queryResult[Symbol.asyncIterator]();
  }

  async *query(prompt: string): AsyncIterable<AgentMessage> {
    if (this.closed) throw new Error("Session is closed");
    if (this.queryInFlight)
      throw new Error("Session query already in flight — concurrent access is not supported");

    this.queryInFlight = true;
    try {
      // Acquire semaphore on first query only
      if (!this.slotAcquired) {
        await acquireSlot();
        this.slotAcquired = true;
      }

      this.ensureStarted();

      // Push user message into the queue
      const userMessage: SDKUserMessage = {
        type: "user",
        session_id: "",
        message: { role: "user", content: [{ type: "text", text: prompt }] },
        parent_tool_use_id: null,
      };
      this.messageQueue.enqueue(userMessage);

      const activityCtx = {
        runId: this._runId,
        taskId: this.baseOptions.taskId,
        fingerprint: this.baseOptions.fingerprint,
        phase: this.baseOptions.phase,
      };

      // Read messages from the subprocess until we get a result for this turn
      const iter = this.queryIterator!;
      while (true) {
        let value: SDKMessage;
        let done: boolean | undefined;
        try {
          const next = await iter.next();
          value = next.value;
          done = next.done;
        } catch (error) {
          // Subprocess crashed — self-close to release the semaphore slot, then yield error.
          emitActivityDone(this._bus, activityCtx);
          await this.close();
          if (isAbortRequested(this.baseOptions)) {
            yield abortResult(0, 0, 0);
            return;
          }
          yield {
            type: "result",
            subtype: "error_runtime",
            errors: [`Session subprocess crashed: ${toErrorMessage(error)}`],
            totalCostUsd: 0,
          };
          return;
        }

        if (done) {
          // Subprocess exited unexpectedly — self-close to release the semaphore slot.
          emitActivityDone(this._bus, activityCtx);
          await this.close();
          if (isAbortRequested(this.baseOptions)) {
            yield abortResult(0, 0, 0);
            return;
          }
          yield {
            type: "result",
            subtype: "error_runtime",
            errors: ["Session subprocess exited unexpectedly"],
            totalCostUsd: 0,
          };
          return;
        }

        if (value.type === "assistant") {
          const sdkAssistant = value as SDKAssistantMessage;
          emitActivityForAssistant(this._bus, sdkAssistant.message?.content, activityCtx);
        }

        const mapped = mapMessage(value);
        if (!mapped) continue;

        if (mapped.type === "result") {
          const sdkResult = value as SDKResultMessage;
          const totalCostUsd = normalizeCostUsd(sdkResult.total_cost_usd);
          const numTurns = sdkResult.num_turns ?? 0;

          emitActivityDone(this._bus, activityCtx);

          if (sdkResult.subtype === "success" && "result" in mapped) {
            yield {
              type: "result",
              subtype: "success",
              result: mapped.result,
              structuredOutput: sdkResult.structured_output,
              numTurns,
              totalCostUsd,
            };
          } else if ("errors" in mapped) {
            yield {
              type: "result",
              subtype: mapped.subtype,
              errors: mapped.errors,
              numTurns,
              totalCostUsd,
            };
          }
          return; // Turn complete — caller can call query() again for next turn
        }

        yield mapped;
      }
    } finally {
      this.queryInFlight = false;
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.messageQueue.done();
    // Kill every tracked subprocess immediately. SDK's abort-on-signal is
    // unreliable — closing the messageQueue sends EOF on stdin but the
    // subprocess can keep running (context:build reproducer was stuck 5+
    // minutes post-abort). SIGTERM → SIGKILL after 500ms.
    killTrackedProcesses(this.trackedProcesses);
    if (this.slotAcquired) {
      releaseSlot();
    }
  }
}

function mapPermissionMode(
  mode: string | undefined,
): "default" | "acceptEdits" | "bypassPermissions" | "plan" | "dontAsk" {
  // When running as root (containers, CI runners, Claude Code remote
  // sandboxes), the Claude CLI rejects `bypassPermissions` /
  // `--dangerously-skip-permissions` for security. Only `plan` mode is
  // root-safe and still functional. Detectors lose Bash/Edit/Write
  // tool execution but keep Read/Grep/Glob — enough for SAST work.
  // `KUZUSHI_DANGEROUSLY_SKIP_PERMISSIONS=1` forces the historical
  // behavior on hosts that explicitly opt in.
  const safeMode: "default" | "acceptEdits" | "bypassPermissions" | "plan" | "dontAsk" =
    shouldAllowSkipPermissions() ? "bypassPermissions" : "plan";
  switch (mode) {
    case "default":
    case "acceptEdits":
    case "plan":
      return mode;
    case "bypassPermissions":
    case "dontAsk":
      return safeMode;
    default:
      return safeMode;
  }
}

function mapMessage(msg: SDKMessage): AgentMessage | null {
  switch (msg.type) {
    case "result": {
      const sdkResult = msg as SDKResultMessage;
      if (sdkResult.subtype === "success") {
        return {
          type: "result",
          subtype: "success",
          result: sdkResult.result ?? "",
          structuredOutput: sdkResult.structured_output,
          totalCostUsd: normalizeCostUsd(sdkResult.total_cost_usd),
        };
      }
      return {
        type: "result",
        subtype: sdkResult.subtype ?? "error_runtime",
        errors: Array.isArray(sdkResult.errors)
          ? sdkResult.errors
          : [String(sdkResult.errors ?? "Unknown error")],
        totalCostUsd: normalizeCostUsd(sdkResult.total_cost_usd),
      };
    }

    case "assistant": {
      const sdkAssistant = msg as SDKAssistantMessage;
      const content = sdkAssistant.message?.content;
      return {
        type: "assistant",
        // BetaContentBlock[] -> Record<string, unknown>[] via spread to satisfy
        // the AgentAssistantMessage interface (strips the rigid index signature constraint)
        content: Array.isArray(content) ? content.map((block) => ({ ...block })) : [],
      };
    }

    case "tool_progress": {
      const sdkProgress = msg as SDKToolProgressMessage;
      return {
        type: "tool-progress",
        toolUseId: sdkProgress.tool_use_id ?? "",
        toolName: sdkProgress.tool_name ?? "",
        elapsedSeconds: sdkProgress.elapsed_time_seconds ?? 0,
      };
    }

    case "tool_use_summary": {
      const sdkSummary = msg as SDKToolUseSummaryMessage;
      return {
        type: "tool-summary",
        summary: sdkSummary.summary ?? "",
        precedingToolUseIds: Array.isArray(sdkSummary.preceding_tool_use_ids)
          ? sdkSummary.preceding_tool_use_ids
          : [],
      };
    }

    case "user": {
      // User messages carry tool_result blocks back to the model. Surface
      // the first tool_result so callers (e.g. randori's runPhase) can
      // detect retry loops on "Validation failed for tool X" and break
      // out instead of burning the full phase on a doomed tool call.
      const sdkUser = msg as unknown as {
        message?: { content?: unknown };
      };
      const content = sdkUser.message?.content;
      if (!Array.isArray(content)) return null;
      for (const block of content as Array<Record<string, unknown>>) {
        if (block?.["type"] !== "tool_result") continue;
        const toolUseId = typeof block["tool_use_id"] === "string" ? block["tool_use_id"] : "";
        const isError = block["is_error"] === true;
        const blockContent = block["content"];
        let text = "";
        if (typeof blockContent === "string") {
          text = blockContent;
        } else if (Array.isArray(blockContent)) {
          const parts: string[] = [];
          for (const p of blockContent as Array<Record<string, unknown>>) {
            if (typeof p?.["text"] === "string") parts.push(p["text"] as string);
          }
          text = parts.join("\n");
        }
        return {
          type: "tool-result",
          toolUseId,
          isError,
          content: text,
        };
      }
      return null;
    }

    default:
      // Skip system messages, auth status, stream events, etc.
      return null;
  }
}

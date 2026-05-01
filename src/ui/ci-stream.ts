/**
 * CI stream formatter — Phase B.5.
 *
 * When a scan runs with `--ci`, we don't want Ink's animated TUI; we want
 * one line per meaningful pipeline event so build logs stay grep-able and
 * tool integrations (Buildkite, GitHub Actions, GitLab, Drone) can parse
 * them. This module subscribes to a `UIStore`, diffs state, and prints
 * plain-text lines. Produces no ANSI colour so log renderers don't mangle.
 *
 * Output shape (one line per transition):
 *
 *   [2026-04-20T14:20:01Z] scan acme-api started
 *   [2026-04-20T14:20:12Z] stage: scan → done (8.3s)
 *   [2026-04-20T14:20:12Z] stage: triage → active (15 findings)
 *   [2026-04-20T14:20:45Z] finding: F-0001 tp crit (ssrf in src/admin.ts:88)
 *   [2026-04-20T14:21:20Z] summary: 4 tp · 10 fp · $0.87 · 1m 18s
 *   [2026-04-20T14:21:20Z] exit: 1
 */

import type { ActionableFinding, PipelineStage, ResultLine, UIState, UIStore } from "./state.js";

export interface CiStreamOptions {
  /** Where each line is written. Defaults to process.stdout. */
  write?: (line: string) => void;
  /** Include per-finding lines. Default true — flip off for very noisy scans. */
  emitFindings?: boolean;
  /**
   * Heartbeat interval in seconds. While the pipeline is in `scanning` /
   * `triaging` / `verifying` state and no other line has been written for
   * this long, emit a `heartbeat: …` line so operators can tell the
   * scan is alive vs hung. Set to 0 to disable. Default 60s — enough to
   * stay quiet on fast scans, frequent enough to reassure on slow ones
   * (a Sentry-sized agentic scan can sit silent for many minutes).
   * Field-test issue #14.
   */
  heartbeatSeconds?: number;
  /**
   * Optional run-context stamps appended to the `scan: started` line and
   * referenced in the closing `result:` line. Operators can grep these out
   * of CI logs without parsing JSON.
   */
  runContext?: {
    runId?: string;
    kuzushiVersion?: string;
    model?: string;
    gitSha?: string;
  };
}

/**
 * Attach a CI stream listener to the store. Returns an unsubscribe function.
 *
 * The implementation keeps a shadow copy of the fields it cares about and
 * emits a line only when one of them changes meaningfully. This keeps the
 * transcript tight even if the store is chatty.
 */
export function attachCiStream(store: UIStore, opts: CiStreamOptions = {}): () => void {
  const write = opts.write ?? ((line: string) => process.stdout.write(`${line}\n`));
  const emitFindings = opts.emitFindings ?? true;
  const heartbeatSeconds = opts.heartbeatSeconds ?? 60;

  let lastPhase: UIState["phase"] | null = null;
  const lastStageStatus = new Map<string, string>();
  const seenResults = new Set<string>();
  let lastThrottleKey: string | null = null;
  let startAnnounced = false;
  let endAnnounced = false;
  let lastWriteAt = Date.now();
  const writeWithHeartbeatReset = (text: string): void => {
    write(text);
    lastWriteAt = Date.now();
  };

  const unsubscribe = store.subscribe(() => {
    const state = store.getState();
    if (state.mode !== "running" && !startAnnounced) return;

    if (!startAnnounced && state.repoName) {
      const ctxStamp = formatRunContext(opts.runContext, state);
      const startLine = ctxStamp
        ? `${state.repoName} started ${ctxStamp}`
        : `${state.repoName} started`;
      writeWithHeartbeatReset(line("scan", startLine));
      startAnnounced = true;
    }

    if (state.phase !== lastPhase) {
      writeWithHeartbeatReset(line("phase", `${lastPhase ?? "(init)"} → ${state.phase}`));
      lastPhase = state.phase;
    }

    for (const stage of state.stages) {
      const prev = lastStageStatus.get(stage.id);
      if (prev !== stage.status) {
        writeWithHeartbeatReset(line("stage", formatStage(stage)));
        lastStageStatus.set(stage.id, stage.status);
      }
    }

    if (emitFindings) {
      for (const r of state.results) {
        if (r.kind !== "triage" || !r.verdict) continue;
        if (seenResults.has(r.fingerprint)) continue;
        seenResults.add(r.fingerprint);
        writeWithHeartbeatReset(line("finding", formatResult(r)));
      }
    }

    // Surface the rate-limit / throttle banner that CLAUDE.md
    // promised but never reached --ci mode (#38). Emit one line on
    // each transition (off→on, on→off, or concurrency change) so
    // operators can correlate slow scans with API rate limits.
    const throttle = state.throttle;
    const throttleKey = throttle ? `${throttle.concurrency}|${throttle.reason}` : "null";
    if (throttleKey !== lastThrottleKey) {
      if (throttle) {
        writeWithHeartbeatReset(
          line("throttle", `concurrency=${throttle.concurrency} (${throttle.reason})`),
        );
      } else if (lastThrottleKey !== null && lastThrottleKey !== "null") {
        writeWithHeartbeatReset(line("throttle", "released"));
      }
      lastThrottleKey = throttleKey;
    }

    if ((state.mode === "summary" || state.phase === "done") && !endAnnounced) {
      if (state.summary) {
        writeWithHeartbeatReset(line("summary", formatSummary(state)));
        // Emit one `error:` line per failed task so a CI grep
        // (`grep '^\[.*\] error:'`) can pull them without context.
        for (const failed of state.summary.failedTasks ?? []) {
          writeWithHeartbeatReset(line("error", `stage=task task=${failed} msg="task failed"`));
        }
        // Final `result:` line: structured verdict + exit hint so CI
        // glue scripts can branch on it without JSON parsing.
        writeWithHeartbeatReset(line("result", formatResultVerdict(state)));
      }
      endAnnounced = true;
    }
  });

  // Heartbeat — emit a reassuring "still alive" line when the pipeline
  // has been silent for too long. Without this, a long agentic scan
  // looks identical to a hung process for many minutes (issue #14).
  // Now also includes raw-finding count and running cost (#39, #45) so
  // operators can decide kill-vs-wait without grep'ing the SQLite DB.
  let heartbeatTimer: NodeJS.Timeout | undefined;
  if (heartbeatSeconds > 0) {
    heartbeatTimer = setInterval(() => {
      const state = store.getState();
      if (endAnnounced) return;
      if (
        state.mode !== "running" ||
        (state.phase !== "scanning" && state.phase !== "triaging" && state.phase !== "verifying")
      ) {
        return;
      }
      const idleMs = Date.now() - lastWriteAt;
      if (idleMs < heartbeatSeconds * 1000) return;
      writeWithHeartbeatReset(line("heartbeat", formatHeartbeat(state, idleMs)));
    }, Math.min(heartbeatSeconds, 30) * 1000).unref();
  }

  // Shutdown drain — emit a single "shutting down" line on
  // SIGTERM / SIGINT / beforeExit so operators can tell graceful
  // teardown from a hard crash. Without this the heartbeat just
  // stops mid-cadence and there's no signal that anything happened.
  // Field-test issue #41.
  let drainEmitted = false;
  const emitDrain = (reason: string): void => {
    if (drainEmitted || endAnnounced) return;
    drainEmitted = true;
    const state = store.getState();
    const findingsPart =
      state.totalFindings > 0 ? ` · ${state.totalFindings.toLocaleString()} raw findings` : "";
    const costPart = state.runningCostUsd > 0 ? ` · $${state.runningCostUsd.toFixed(2)}` : "";
    try {
      write(line("shutdown", `${reason} · phase=${state.phase}${findingsPart}${costPart}`));
    } catch {
      /* best-effort — the same EPIPE handler in claude.ts catches stdout-closed */
    }
  };
  const onSigterm = (): void => emitDrain("SIGTERM received");
  const onSigint = (): void => emitDrain("SIGINT received");
  const onBeforeExit = (): void => emitDrain("process exiting");
  process.on("SIGTERM", onSigterm);
  process.on("SIGINT", onSigint);
  process.on("beforeExit", onBeforeExit);

  return () => {
    unsubscribe();
    if (heartbeatTimer) clearInterval(heartbeatTimer);
    process.off("SIGTERM", onSigterm);
    process.off("SIGINT", onSigint);
    process.off("beforeExit", onBeforeExit);
  };
}

/**
 * Build a heartbeat line that surfaces all the numbers an operator
 * needs to decide whether to keep waiting: phase, raw-finding count,
 * cost so far, idle time, and active stage ids. Cost is only included
 * when non-zero (avoids a noisy `$0.00` on scanner-only stages).
 *
 * In triage / verify phases, replaces the raw count with a
 * `triage: M/N · ETA Xm` progress block so operators can decide
 * kill-vs-wait against a concrete remaining-time estimate.
 * Field-test issues #26 and #46.
 */
function formatHeartbeat(state: UIState, idleMs: number): string {
  const idleSec = Math.round(idleMs / 1000);
  const costPart = state.runningCostUsd > 0 ? ` · $${state.runningCostUsd.toFixed(2)}` : "";
  const activeStages = state.stages.filter((s) => s.status === "active").map((s) => s.id);
  const stageDetail = activeStages.length ? ` (${activeStages.join(", ")})` : "";

  // Triage progress: count completed `triage`-kind results; pair
  // with `selectedForTriage` for a clean M/N. ETA is a moving
  // estimate based on processed/(elapsed since triage start).
  if (state.phase === "triaging" && state.selectedForTriage > 0) {
    const processed = state.results.filter((r) => r.kind === "triage" && r.verdict).length;
    const total = state.selectedForTriage;
    const triageStage = state.stages.find((s) => s.id === "triage");
    const triageStart = triageStage?.startedAt;
    let etaPart = "";
    if (triageStart && processed > 0) {
      const elapsedMs = Date.now() - triageStart;
      const rate = processed / elapsedMs; // findings per ms
      const remaining = total - processed;
      const etaMs = remaining > 0 && rate > 0 ? remaining / rate : 0;
      if (etaMs > 0) etaPart = ` · ETA ${formatDuration(etaMs)}`;
    }
    return `${state.phase} alive · ${processed}/${total} triaged${etaPart}${costPart} · idle ${idleSec}s${stageDetail}`;
  }

  const findingsPart =
    state.totalFindings > 0 ? ` · ${state.totalFindings.toLocaleString()} raw` : "";
  return `${state.phase} alive${findingsPart}${costPart} · idle ${idleSec}s${stageDetail}`;
}

/** Compact human duration: "47m", "2h 13m", "5h", "38h". */
function formatDuration(ms: number): string {
  const sec = Math.round(ms / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m`;
  const hours = Math.floor(min / 60);
  const remMin = min % 60;
  return remMin > 0 && hours < 10 ? `${hours}h ${remMin}m` : `${hours}h`;
}

function line(kind: string, body: string, atIsoTimestamp?: string): string {
  const ts = atIsoTimestamp ?? new Date().toISOString();
  return `[${ts}] ${kind}: ${body}`;
}

/**
 * Format the run-context stamp for the opening `scan:` line. Empty when no
 * fields are populated. We deliberately keep this `key=value` so a CI parser
 * can grep `kuzushi=` without a regex.
 */
function formatRunContext(
  ctx: CiStreamOptions["runContext"] | undefined,
  state: UIState,
): string {
  const fields: string[] = [];
  if (ctx?.runId) fields.push(`run=${ctx.runId.slice(0, 8)}`);
  if (ctx?.kuzushiVersion) fields.push(`kuzushi=${ctx.kuzushiVersion}`);
  const model = ctx?.model ?? state.model;
  if (model) fields.push(`model=${model}`);
  if (ctx?.gitSha) fields.push(`git=${ctx.gitSha.slice(0, 7)}`);
  return fields.join(" ");
}

/**
 * Final `result:` line — verdict + exit hint, designed for grep'ing in CI:
 *
 *   grep '^\[.*\] result:' build.log
 *
 * Exit hint is `1` when there's any tp finding or any failed task, else `0`.
 */
function formatResultVerdict(state: UIState): string {
  const summary = state.summary;
  if (!summary) return "unknown";
  const counts = countBySeverity(summary.actionableFindings ?? []);
  const failed = summary.failedTasks ?? [];
  const tpTotal = (summary.verdictCounts?.tp ?? 0) + (summary.verdictCounts?.needs_review ?? 0);
  const verdict = tpTotal > 0 || failed.length > 0 ? "fail" : "pass";
  const sevParts = (["critical", "high", "medium", "low"] as const)
    .filter((s) => counts[s] > 0)
    .map((s) => `${counts[s]} ${s}`);
  const failedPart = failed.length > 0 ? `, ${failed.length} failed-task${failed.length === 1 ? "" : "s"}` : "";
  const exitHint = verdict === "pass" ? 0 : 1;
  return `${verdict} (${sevParts.join(", ") || "no findings"}${failedPart}) exit_hint=${exitHint}`;
}

function countBySeverity(
  findings: ReadonlyArray<ActionableFinding>,
): { critical: number; high: number; medium: number; low: number } {
  const out = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (f.verdict !== "tp" || f.suppressed) continue;
    const sev = (f.displaySeverity ?? f.severity ?? "").toLowerCase();
    if (sev.includes("crit")) out.critical += 1;
    else if (sev.includes("high")) out.high += 1;
    else if (sev.includes("med")) out.medium += 1;
    else out.low += 1;
  }
  return out;
}

function formatStage(stage: PipelineStage): string {
  const detail = stage.detail ? ` (${stage.detail})` : "";
  const elapsed = stage.elapsedMs != null ? ` [${(stage.elapsedMs / 1000).toFixed(1)}s]` : "";
  return `${stage.id} → ${stage.status}${detail}${elapsed}`;
}

function formatResult(r: ResultLine): string {
  const verdict = r.verdict ?? "?";
  const conf = r.confidence != null ? ` ${(r.confidence * 100).toFixed(0)}%` : "";
  const cost = r.costUsd != null ? ` $${r.costUsd.toFixed(4)}` : "";
  return `${r.fingerprint.slice(0, 12)} ${verdict}${conf}${cost}`;
}

/**
 * Detail line for an actionable finding. Designed for grep:
 *
 *   grep -E '^\[.*\] finding:.*(critical|high)' build.log
 */
export function formatActionableFindingLine(f: ActionableFinding, alias: string): string {
  const sev = (f.displaySeverity ?? f.severity ?? "low").toLowerCase();
  const cwe = (f.cwe ?? [])[0] ?? "—";
  const loc = `${f.filePath ?? "?"}:${f.startLine ?? "?"}`;
  const title = (f.title ?? f.ruleId ?? "(untitled)").replace(/\n/g, " ");
  return `${alias} ${f.verdict} ${sev} ${cwe} ${loc} ${title}`;
}

function formatSummary(state: UIState): string {
  const s = state.summary;
  if (!s) return "no summary";
  const elapsedMs = state.pipelineStartedAt ? Date.now() - state.pipelineStartedAt : undefined;
  const parts: string[] = [];
  for (const [verdict, count] of Object.entries(s.verdictCounts ?? {})) {
    if (count > 0) parts.push(`${count} ${verdict}`);
  }
  parts.push(`$${state.runningCostUsd.toFixed(2)}`);
  if (elapsedMs != null) parts.push(`${(elapsedMs / 1000).toFixed(1)}s`);
  return parts.join(" · ");
}

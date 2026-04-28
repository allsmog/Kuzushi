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

import type { PipelineStage, ResultLine, UIState, UIStore } from "./state.js";

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
      writeWithHeartbeatReset(line("scan", `${state.repoName} started`));
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

    if ((state.mode === "summary" || state.phase === "done") && !endAnnounced) {
      if (state.summary) {
        writeWithHeartbeatReset(line("summary", formatSummary(state)));
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
 */
function formatHeartbeat(state: UIState, idleMs: number): string {
  const idleSec = Math.round(idleMs / 1000);
  const findingsPart =
    state.totalFindings > 0 ? ` · ${state.totalFindings.toLocaleString()} raw` : "";
  const costPart = state.runningCostUsd > 0 ? ` · $${state.runningCostUsd.toFixed(2)}` : "";
  const activeStages = state.stages.filter((s) => s.status === "active").map((s) => s.id);
  const stageDetail = activeStages.length ? ` (${activeStages.join(", ")})` : "";
  return `${state.phase} alive${findingsPart}${costPart} · idle ${idleSec}s${stageDetail}`;
}

function line(kind: string, body: string): string {
  return `[${new Date().toISOString()}] ${kind}: ${body}`;
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

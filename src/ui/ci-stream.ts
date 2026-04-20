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

  let lastPhase: UIState["phase"] | null = null;
  const lastStageStatus = new Map<string, string>();
  const seenResults = new Set<string>();
  let startAnnounced = false;
  let endAnnounced = false;

  const unsubscribe = store.subscribe(() => {
    const state = store.getState();
    if (state.mode !== "running" && !startAnnounced) return;

    if (!startAnnounced && state.repoName) {
      write(line("scan", `${state.repoName} started`));
      startAnnounced = true;
    }

    if (state.phase !== lastPhase) {
      write(line("phase", `${lastPhase ?? "(init)"} → ${state.phase}`));
      lastPhase = state.phase;
    }

    for (const stage of state.stages) {
      const prev = lastStageStatus.get(stage.id);
      if (prev !== stage.status) {
        write(line("stage", formatStage(stage)));
        lastStageStatus.set(stage.id, stage.status);
      }
    }

    if (emitFindings) {
      for (const r of state.results) {
        if (r.kind !== "triage" || !r.verdict) continue;
        if (seenResults.has(r.fingerprint)) continue;
        seenResults.add(r.fingerprint);
        write(line("finding", formatResult(r)));
      }
    }

    if ((state.mode === "summary" || state.phase === "done") && !endAnnounced) {
      if (state.summary) {
        write(line("summary", formatSummary(state)));
      }
      endAnnounced = true;
    }
  });

  return unsubscribe;
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

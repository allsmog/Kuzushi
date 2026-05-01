/**
 * Replay / trace helpers for the copilot shell.
 *
 * Three read-only surfaces over `.kuzushi/runs/<runId>/` + the `pipeline_runs`
 * sqlite table:
 *
 *   - `/show runs`          — list recent runs with id / repo / status / cost
 *   - `/replay <runId>`     — rebuild a summary from the stored `findings_json`
 *                             (no re-execution) so operators can re-read the
 *                             outcome of a past run without re-running it
 *   - `/trace <runId>`      — pretty-print the per-event JSONL audit stream
 *                             (`triage.jsonl` + `verify.jsonl`) in chronological
 *                             order, down to tool-call granularity
 *
 * This file never touches the Ink UI. The shell wraps the formatted output
 * as a history entry.
 */

import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import type { listRuns as listRunsFn, PipelineRunRecord } from "../store.js";

// Types

// Canonical `PipelineRunRecord` lives in `src/store.ts`. Re-exported here so
// `replay`-module consumers don't have to chase the persistence layer.
export type { PipelineRunRecord };
export type PipelineRunList = ReturnType<typeof listRunsFn>;

/** One line of a triage.jsonl / verify.jsonl audit log. */
export interface TraceEvent {
  type: string;
  timestamp: string;
  fingerprint?: string;
  payload?: Record<string, unknown>;
  /** Which file the event came from (e.g. "triage.jsonl"). */
  source: string;
}

// Runs table

export function formatRunsTable(runs: PipelineRunList, limit = 25): string {
  if (runs.length === 0) return "No runs recorded yet. Kick off a scan first.";
  const header = ["run", "repo", "status", "started", "cost", "findings"];
  const rows = runs.slice(0, limit).map((r) => {
    const findings = countFindings(r.findingsJson);
    return [
      shortRunId(r.runId),
      truncate(basenameOrRepo(r.repo), 26),
      r.status,
      relativeTime(r.startedAt),
      `$${(r.totalCostUsd ?? 0).toFixed(2)}`,
      findings != null ? String(findings) : "-",
    ];
  });
  const widths = header.map((h, i) =>
    Math.max(h.length, ...rows.map((row) => (row[i] ?? "").length)),
  );
  const pad = (row: string[]) =>
    row.map((cell, i) => cell.padEnd(widths[i] ?? cell.length)).join("  ");
  const hrule = header.map((h) => "\u2500".repeat(h.length));
  const footer =
    runs.length > limit ? `\n(showing ${limit} of ${runs.length}; pass --limit for more)` : "";
  return [pad(header), pad(hrule), ...rows.map(pad)].join("\n") + footer;
}

// Replay

export function formatRunReplay(run: PipelineRunRecord): string {
  const lines: string[] = [];
  lines.push(`run ${shortRunId(run.runId)}   ${run.status}   ${run.repo}`);
  lines.push(`started   ${run.startedAt}`);
  if (run.completedAt) lines.push(`completed ${run.completedAt}`);
  lines.push(`cost      $${(run.totalCostUsd ?? 0).toFixed(4)}`);
  if (run.promptHash) lines.push(`prompt    ${run.promptHash.slice(0, 12)}`);

  // Severity + verdict counts come from the persisted findings_json blob.
  const findings = parseFindings(run.findingsJson);
  if (findings.length === 0) {
    lines.push("", "(no findings persisted for this run)");
    return lines.join("\n");
  }
  const bySeverity = bucket(findings, (f) => displaySeverity(f));
  const byVerdict = bucket(findings, (f) => String(f.verdict ?? "\u2014"));

  lines.push("");
  lines.push("severity");
  for (const [k, n] of entriesSortedDesc(bySeverity)) {
    lines.push(`  ${k.padEnd(10)} ${n}`);
  }
  lines.push("verdict");
  for (const [k, n] of entriesSortedDesc(byVerdict)) {
    lines.push(`  ${k.padEnd(10)} ${n}`);
  }

  const top = findings
    .filter((f) => f.verdict === "tp" || f.verdict === "true_positive")
    .slice(0, 5);
  if (top.length > 0) {
    lines.push("", "top true-positives");
    for (const f of top) {
      const title = stringOrUndef(f.title) ?? stringOrUndef(f.ruleId) ?? "(untitled)";
      const loc = `${stringOrUndef(f.filePath) ?? "?"}:${numberOrUndef(f.startLine) ?? "?"}`;
      lines.push(`  ${shortFpId(stringOrUndef(f.fingerprint))}  ${truncate(title, 48)}  ${loc}`);
    }
  }

  // Metrics are stored as JSON; surface the handful the SummaryData uses.
  if (run.metricsJson) {
    try {
      const m = JSON.parse(run.metricsJson) as Record<string, unknown>;
      if (typeof m === "object" && m !== null) {
        lines.push("", "metrics");
        for (const key of ["triageCostUsd", "verificationCostUsd", "exploitable"]) {
          if (key in m) lines.push(`  ${key.padEnd(20)} ${formatAny(m[key])}`);
        }
      }
    } catch {
      // malformed metrics JSON — ignore silently, summary is still useful
    }
  }

  return lines.join("\n");
}

// Trace

export function readTraceEvents(dataDir: string, runId: string): TraceEvent[] {
  const runDir = path.join(dataDir, "runs", runId);
  if (!existsSync(runDir)) return [];

  const events: TraceEvent[] = [];
  for (const name of ["triage.jsonl", "verify.jsonl"]) {
    const file = path.join(runDir, name);
    if (!existsSync(file)) continue;
    const body = readFileSync(file, "utf-8");
    for (const line of body.split(/\n+/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const parsed = JSON.parse(trimmed) as Record<string, unknown>;
        events.push({
          type: String(parsed["type"] ?? "?"),
          timestamp: String(parsed["timestamp"] ?? ""),
          fingerprint: stringOrUndef(parsed["fingerprint"]),
          payload: parsed["payload"] as Record<string, unknown> | undefined,
          source: name,
        });
      } catch {
        // Skip malformed lines — better to render partial trace than nothing.
      }
    }
  }
  events.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  return events;
}

export function formatRunTrace(runId: string, events: TraceEvent[], limit = 80): string {
  if (events.length === 0) {
    return `No trace events found for run ${shortRunId(runId)}. Audit logging may have been disabled.`;
  }
  const kept = events.slice(-limit);
  const lines = kept.map((e) => formatTraceLine(e));
  const footer =
    events.length > limit
      ? `\n(showing last ${limit} of ${events.length}; trace logs are append-only)`
      : "";
  return lines.join("\n") + footer;
}

function formatTraceLine(e: TraceEvent): string {
  const when = e.timestamp ? e.timestamp.replace("T", " ").replace(/\.\d+Z?$/, "") : "?";
  const fp = e.fingerprint ? shortFpId(e.fingerprint) : "-";
  const kind = e.type.padEnd(26);
  const detail = summariseTracePayload(e);
  return `${when}  ${kind}  ${fp}  ${detail}`;
}

function summariseTracePayload(e: TraceEvent): string {
  const p = e.payload;
  if (!p) return "";
  const parts: string[] = [];
  const cost = numberOrUndef(p["costUsd"]);
  if (cost != null) parts.push(`$${cost.toFixed(4)}`);
  const idx = numberOrUndef(p["index"]);
  const total = numberOrUndef(p["total"]);
  if (idx != null && total != null) parts.push(`${idx}/${total}`);
  const result = p["result"] as Record<string, unknown> | undefined;
  if (result && typeof result === "object") {
    const verdict = stringOrUndef(result["verdict"]);
    if (verdict) parts.push(verdict);
    const confidence = numberOrUndef(result["confidence"]);
    if (confidence != null) parts.push(`conf=${confidence.toFixed(2)}`);
  }
  const finding = p["finding"] as Record<string, unknown> | undefined;
  if (finding && typeof finding === "object") {
    const rule = stringOrUndef(finding["ruleId"]);
    if (rule) parts.push(rule);
  }
  return parts.join("  ");
}

// Small helpers

function parseFindings(json: string | null | undefined): Array<Record<string, unknown>> {
  if (!json) return [];
  try {
    const parsed = JSON.parse(json);
    if (Array.isArray(parsed)) return parsed as Array<Record<string, unknown>>;
    return [];
  } catch {
    return [];
  }
}

function countFindings(json: string | null | undefined): number | undefined {
  if (!json) return undefined;
  try {
    const parsed = JSON.parse(json);
    return Array.isArray(parsed) ? parsed.length : undefined;
  } catch {
    return undefined;
  }
}

function bucket<T>(items: T[], keyOf: (t: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const item of items) {
    const k = keyOf(item);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

function entriesSortedDesc(rec: Record<string, number>): Array<[string, number]> {
  return Object.entries(rec).sort((a, b) => b[1] - a[1]);
}

function displaySeverity(f: Record<string, unknown>): string {
  const ds = stringOrUndef(f["displaySeverity"]);
  if (ds) return ds;
  const raw = stringOrUndef(f["severity"]);
  return raw ? raw.toLowerCase() : "\u2014";
}

function stringOrUndef(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function numberOrUndef(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

function formatAny(v: unknown): string {
  if (typeof v === "number") return Number.isInteger(v) ? String(v) : v.toFixed(4);
  if (typeof v === "string") return v;
  try {
    const s = JSON.stringify(v);
    return s.length > 80 ? `${s.slice(0, 79)}\u2026` : s;
  } catch {
    return String(v);
  }
}

function shortRunId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

function shortFpId(id?: string): string {
  if (!id) return "-";
  return id.length > 8 ? `F-${id.slice(0, 4)}` : id;
}

function basenameOrRepo(repo: string): string {
  if (!repo) return "(repo?)";
  const base = path.basename(repo);
  return base || repo;
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}\u2026`;
}

function relativeTime(iso: string): string {
  if (!iso) return "?";
  const d = new Date(iso).getTime();
  if (!Number.isFinite(d)) return iso;
  const deltaSec = Math.max(0, Math.floor((Date.now() - d) / 1000));
  if (deltaSec < 60) return `${deltaSec}s ago`;
  if (deltaSec < 3600) return `${Math.floor(deltaSec / 60)}m ago`;
  if (deltaSec < 86400) return `${Math.floor(deltaSec / 3600)}h ago`;
  return `${Math.floor(deltaSec / 86400)}d ago`;
}

/**
 * `kuzushi runs diff <a> <b>` — finding-set diff between two runs.
 *
 * Reads `pipeline_runs.findings_json` for both runs, fingerprint-keys
 * them, and emits four sets:
 *
 *   - new      — fingerprint present in B, absent from A
 *   - fixed    — fingerprint present in A, absent from B
 *   - drifted  — same fingerprint, differing verdict / displaySeverity / confidence
 *   - stable   — same fingerprint, no relevant change (count only)
 *
 * Output:
 *   default    — readable plain-text table
 *   --json     — structured object suitable for `jq`
 */

import { existsSync } from "node:fs";
import { resolveRepo } from "../shared.js";
import { CliUsageError } from "../errors.js";
import { defaultDbPath, getRun, initDb, listRuns } from "../../store.js";
import type { PipelineRunRecord } from "../../store.js";

export interface RunsDiffOpts {
  repo: string;
  json?: boolean;
}

interface FindingShape {
  fingerprint: string;
  verdict?: string;
  displaySeverity?: string;
  severity?: string;
  confidence?: number;
  ruleId?: string;
  filePath?: string;
  startLine?: number;
  title?: string;
}

export interface RunsDiffEntry {
  fingerprint: string;
  ruleId?: string;
  filePath?: string;
  startLine?: number;
  title?: string;
  verdict?: string;
  severity?: string;
}

export interface RunsDiffDriftEntry extends RunsDiffEntry {
  changes: Array<{ field: "verdict" | "severity" | "confidence"; from?: unknown; to?: unknown }>;
}

export interface RunsDiffResult {
  runA: { runId: string; startedAt: string; status: string };
  runB: { runId: string; startedAt: string; status: string };
  added: RunsDiffEntry[];
  removed: RunsDiffEntry[];
  drifted: RunsDiffDriftEntry[];
  stableCount: number;
}

function parseFindings(json: string | null | undefined): Map<string, FindingShape> {
  const out = new Map<string, FindingShape>();
  if (!json) return out;
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return out;
  }
  if (!Array.isArray(parsed)) return out;
  for (const item of parsed) {
    if (!item || typeof item !== "object") continue;
    const obj = item as Record<string, unknown>;
    const fp = obj["fingerprint"];
    if (typeof fp !== "string" || fp.length === 0) continue;
    const shape: FindingShape = {
      fingerprint: fp,
      verdict: typeof obj["verdict"] === "string" ? (obj["verdict"] as string) : undefined,
      displaySeverity:
        typeof obj["displaySeverity"] === "string"
          ? (obj["displaySeverity"] as string)
          : undefined,
      severity: typeof obj["severity"] === "string" ? (obj["severity"] as string) : undefined,
      confidence: typeof obj["confidence"] === "number" ? (obj["confidence"] as number) : undefined,
      ruleId: typeof obj["ruleId"] === "string" ? (obj["ruleId"] as string) : undefined,
      filePath: typeof obj["filePath"] === "string" ? (obj["filePath"] as string) : undefined,
      startLine:
        typeof obj["startLine"] === "number" ? (obj["startLine"] as number) : undefined,
      title: typeof obj["title"] === "string" ? (obj["title"] as string) : undefined,
    };
    out.set(fp, shape);
  }
  return out;
}

function severityOf(f: FindingShape): string | undefined {
  return f.displaySeverity ?? f.severity;
}

function toEntry(f: FindingShape): RunsDiffEntry {
  return {
    fingerprint: f.fingerprint,
    ...(f.ruleId ? { ruleId: f.ruleId } : {}),
    ...(f.filePath ? { filePath: f.filePath } : {}),
    ...(f.startLine != null ? { startLine: f.startLine } : {}),
    ...(f.title ? { title: f.title } : {}),
    ...(f.verdict ? { verdict: f.verdict } : {}),
    ...(severityOf(f) ? { severity: severityOf(f) } : {}),
  };
}

/** Pure diff function — exported for tests. */
export function diffRuns(
  runA: PipelineRunRecord,
  runB: PipelineRunRecord,
): RunsDiffResult {
  const a = parseFindings(runA.findingsJson);
  const b = parseFindings(runB.findingsJson);
  const added: RunsDiffEntry[] = [];
  const removed: RunsDiffEntry[] = [];
  const drifted: RunsDiffDriftEntry[] = [];
  let stableCount = 0;

  for (const [fp, fA] of a) {
    const fB = b.get(fp);
    if (!fB) {
      removed.push(toEntry(fA));
      continue;
    }
    const changes: RunsDiffDriftEntry["changes"] = [];
    if ((fA.verdict ?? null) !== (fB.verdict ?? null)) {
      changes.push({ field: "verdict", from: fA.verdict, to: fB.verdict });
    }
    if ((severityOf(fA) ?? null) !== (severityOf(fB) ?? null)) {
      changes.push({ field: "severity", from: severityOf(fA), to: severityOf(fB) });
    }
    if ((fA.confidence ?? null) !== (fB.confidence ?? null)) {
      changes.push({ field: "confidence", from: fA.confidence, to: fB.confidence });
    }
    if (changes.length === 0) {
      stableCount += 1;
    } else {
      drifted.push({ ...toEntry(fB), changes });
    }
  }
  for (const [fp, fB] of b) {
    if (!a.has(fp)) added.push(toEntry(fB));
  }

  return {
    runA: { runId: runA.runId, startedAt: runA.startedAt, status: runA.status },
    runB: { runId: runB.runId, startedAt: runB.startedAt, status: runB.status },
    added,
    removed,
    drifted,
    stableCount,
  };
}

export function formatDiff(result: RunsDiffResult): string {
  const lines: string[] = [];
  lines.push(
    `diff ${shortId(result.runA.runId)} -> ${shortId(result.runB.runId)}    (${result.runA.status} -> ${result.runB.status})`,
  );
  lines.push(
    `  +${result.added.length} new   -${result.removed.length} fixed   ~${result.drifted.length} drifted   =${result.stableCount} stable`,
  );

  if (result.added.length > 0) {
    lines.push("\nNew (introduced in B):");
    for (const f of result.added.slice(0, 50)) lines.push(`  + ${formatEntry(f)}`);
    if (result.added.length > 50) lines.push(`  ...and ${result.added.length - 50} more`);
  }

  if (result.removed.length > 0) {
    lines.push("\nFixed (gone from B):");
    for (const f of result.removed.slice(0, 50)) lines.push(`  - ${formatEntry(f)}`);
    if (result.removed.length > 50) lines.push(`  ...and ${result.removed.length - 50} more`);
  }

  if (result.drifted.length > 0) {
    lines.push("\nDrifted (verdict / severity / confidence changed):");
    for (const f of result.drifted.slice(0, 50)) {
      const changes = f.changes
        .map((c) => `${c.field}: ${formatVal(c.from)} -> ${formatVal(c.to)}`)
        .join(", ");
      lines.push(`  ~ ${formatEntry(f)} [${changes}]`);
    }
    if (result.drifted.length > 50) lines.push(`  ...and ${result.drifted.length - 50} more`);
  }

  return lines.join("\n");
}

function formatEntry(f: RunsDiffEntry): string {
  const fp = `F-${f.fingerprint.slice(0, 6)}`;
  const sev = f.severity ?? "?";
  const loc = `${f.filePath ?? "?"}:${f.startLine ?? "?"}`;
  const title = f.title ?? f.ruleId ?? "(untitled)";
  return `${fp}  ${sev.padEnd(8)}  ${truncate(title, 48).padEnd(48)}  ${loc}`;
}

function formatVal(v: unknown): string {
  if (v == null) return "-";
  if (typeof v === "number") return v.toFixed(2);
  return String(v);
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

function resolveRunId(
  db: ReturnType<typeof initDb>,
  partial: string,
): PipelineRunRecord | undefined {
  const exact = getRun(db, partial);
  if (exact) return exact;
  const matches = listRuns(db, { limit: 250 }).filter((r) => r.runId.startsWith(partial));
  if (matches.length === 1) return matches[0]!;
  if (matches.length > 1) {
    throw new CliUsageError(
      `Ambiguous runId prefix "${partial}" — matches: ${matches.map((m) => m.runId).join(", ")}`,
    );
  }
  return undefined;
}

export function runRunsDiff(idA: string, idB: string, opts: RunsDiffOpts): void {
  const { root } = resolveRepo(opts.repo);
  const dbPath = defaultDbPath(root);
  if (!existsSync(dbPath)) {
    throw new CliUsageError(`No runs database at ${dbPath}.`);
  }
  const db = initDb(dbPath);
  try {
    const runA = resolveRunId(db, idA);
    const runB = resolveRunId(db, idB);
    if (!runA) throw new CliUsageError(`Run not found: ${idA}`);
    if (!runB) throw new CliUsageError(`Run not found: ${idB}`);
    const result = diffRuns(runA, runB);
    if (opts.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(formatDiff(result));
    }
  } finally {
    db.close();
  }
}

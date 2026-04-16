import { writeFileSync } from "node:fs";
import type Database from "better-sqlite3";
import type { PipelineStats } from "./bus/events.js";
import { summarizeTaintPath } from "./findings/taint-path.js";
import { getActionableFindings } from "./store.js";
import type { ExploitChain } from "./types.js";

interface JsonReportMeta {
  version: string;
  repo: string;
  timestamp: string;
  scanMode: string;
}

interface JsonReportSummary {
  total: number;
  byVerdict: Record<string, number>;
  bySeverity: Record<string, number>;
}

interface JsonReportData {
  meta: JsonReportMeta;
  summary: JsonReportSummary;
  findings: Array<Record<string, unknown>>;
  exploitChains: ExploitChain[];
  stats: Partial<PipelineStats>;
}

/**
 * Serialize a value to JSON, handling BigInt and circular references.
 */
function safeJsonStringify(value: unknown, indent: number): string {
  const seen = new WeakSet<object>();

  return JSON.stringify(
    value,
    (_key: string, val: unknown): unknown => {
      if (typeof val === "bigint") {
        return val.toString();
      }

      if (val !== null && typeof val === "object") {
        if (seen.has(val)) {
          return "[Circular]";
        }
        seen.add(val);
      }

      return val;
    },
    indent,
  );
}

/**
 * Write a JSON report containing metadata, summary, findings, exploit chains,
 * and pipeline statistics.
 */
export function writeJsonReport(
  outputPath: string,
  db: Database.Database,
  repo: string,
  stats: Partial<PipelineStats>,
  exploitChains: ExploitChain[],
  scanMode: string,
  fingerprints?: string[],
): void {
  const allFindings = getActionableFindings(db, repo, {
    includeFalsePositives: true,
    fingerprints,
  });

  const byVerdict: Record<string, number> = { tp: 0, fp: 0, needs_review: 0, by_design: 0 };
  const bySeverity: Record<string, number> = {};

  for (const f of allFindings) {
    byVerdict[f.verdict] = (byVerdict[f.verdict] ?? 0) + 1;
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  }

  const findings: Array<Record<string, unknown>> = allFindings.map((f) => ({
    fingerprint: f.fingerprint,
    taskId: f.taskId,
    ruleId: f.ruleId,
    filePath: f.filePath,
    startLine: f.startLine,
    severity: f.severity,
    message: f.message,
    verdict: f.verdict,
    confidence: f.confidence,
    rationale: f.rationale,
    fixPatch: f.fixPatch,
    taintPath: f.taintPath,
    taintPathSummary: summarizeTaintPath(f.taintPath),
    proofState: f.proofState,
    engineProvenance: f.engineProvenance,
    verifyExploitable: f.verifyExploitable,
    verifyPocPayload: f.verifyPocPayload,
    verifyPocDescription: f.verifyPocDescription,
    verifyAttackVector: f.verifyAttackVector,
    verifyPreconditions: f.verifyPreconditions,
    verifyConfidence: f.verifyConfidence,
    verifyCostUsd: f.verifyCostUsd,
    pocHarnessPath: f.pocHarnessPath,
    pocHarnessLanguage: f.pocHarnessLanguage,
    pocHarnessParsed: f.pocHarnessParsed,
    pocHarnessParseError: f.pocHarnessParseError,
    pocHarnessSkipped: f.pocHarnessSkipped,
    pocHarnessSkipReason: f.pocHarnessSkipReason,
    pocHarnessCostUsd: f.pocHarnessCostUsd,
    pocRunExitCode: f.pocRunExitCode,
    pocRunStdout: f.pocRunStdout,
    pocRunStderr: f.pocRunStderr,
    pocRunVerdict: f.pocRunVerdict,
    pocRunDurationMs: f.pocRunDurationMs,
  }));

  const data: JsonReportData = {
    meta: {
      version: "0.1.0",
      repo,
      timestamp: new Date().toISOString(),
      scanMode,
    },
    summary: {
      total: allFindings.length,
      byVerdict,
      bySeverity,
    },
    findings,
    exploitChains,
    stats,
  };

  writeFileSync(outputPath, `${safeJsonStringify(data, 2)}\n`, "utf-8");
}

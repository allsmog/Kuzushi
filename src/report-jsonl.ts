import { writeFileSync } from "node:fs";
import type Database from "better-sqlite3";
import { getActionableFindings } from "./store.js";

/**
 * Serialize a single value to a compact JSON line, handling BigInt values.
 */
function toJsonLine(value: unknown): string {
  return JSON.stringify(value, (_key: string, val: unknown): unknown => {
    if (typeof val === "bigint") {
      return val.toString();
    }
    return val;
  });
}

/**
 * Write a JSONL (JSON Lines) report to the specified output path.
 *
 * The first line is a metadata object containing version, repo, timestamp,
 * and total finding count. Each subsequent line is a single finding serialized
 * as an independent JSON object.
 */
export function writeJsonlReport(
  outputPath: string,
  db: Database.Database,
  repo: string,
  fingerprints?: string[],
): void {
  const allFindings = getActionableFindings(db, repo, {
    includeFalsePositives: true,
    fingerprints,
  });

  const meta = {
    version: "0.1.0",
    repo,
    timestamp: new Date().toISOString(),
    total: allFindings.length,
  };

  const lines: string[] = [toJsonLine(meta)];

  for (const f of allFindings) {
    lines.push(toJsonLine({
      fingerprint: f.fingerprint,
      scanner: f.scanner,
      ruleId: f.ruleId,
      filePath: f.filePath,
      startLine: f.startLine,
      severity: f.severity,
      message: f.message,
      verdict: f.verdict,
      confidence: f.confidence,
      rationale: f.rationale,
      fixPatch: f.fixPatch,
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
    }));
  }

  writeFileSync(outputPath, lines.join("\n") + "\n", "utf-8");
}

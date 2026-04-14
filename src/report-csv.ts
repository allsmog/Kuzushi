import { writeFileSync } from "node:fs";
import type Database from "better-sqlite3";
import { summarizeTaintPath } from "./findings/taint-path.js";
import { getActionableFindings } from "./store.js";

const CSV_COLUMNS = [
  "fingerprint",
  "taskId",
  "filePath",
  "startLine",
  "severity",
  "verdict",
  "confidence",
  "ruleId",
  "message",
  "verifyCostUsd",
  "proofState",
  "taintPathSteps",
  "taintPathSummary",
  "engineKinds",
  "pocRunVerdict",
  "pocRunDurationMs",
] as const;

const CSV_HEADER = CSV_COLUMNS.join(",");

/**
 * RFC 4180 compliant CSV field escaping.
 * Wraps a field in double quotes when it contains commas, double quotes,
 * or newlines. Internal double quotes are escaped by doubling them.
 */
function escapeCsvField(value: unknown): string {
  const str = value == null ? "" : String(value);

  if (str.includes(",") || str.includes('"') || str.includes("\n") || str.includes("\r")) {
    return `"${str.replace(/"/g, '""')}"`;
  }

  return str;
}

/**
 * Write a CSV report of findings to the specified output path.
 * Columns: fingerprint, taskId, filePath, startLine, severity, verdict,
 * confidence, ruleId, message, verifyCostUsd.
 *
 * The output is RFC 4180 compliant with a header row.
 */
export function writeCsvReport(
  outputPath: string,
  db: Database.Database,
  repo: string,
  fingerprints?: string[],
): void {
  const allFindings = getActionableFindings(db, repo, {
    includeFalsePositives: true,
    fingerprints,
  });

  const lines: string[] = [CSV_HEADER];

  for (const f of allFindings) {
    const row = CSV_COLUMNS.map((col) => {
      const value = getCsvValue(f, col);
      return escapeCsvField(value);
    });
    lines.push(row.join(","));
  }

  writeFileSync(outputPath, lines.join("\r\n") + "\r\n", "utf-8");
}

function getCsvValue(
  finding: Awaited<ReturnType<typeof getActionableFindings>>[number],
  column: (typeof CSV_COLUMNS)[number],
): unknown {
  switch (column) {
    case "taintPathSteps":
      return finding.taintPath?.length ?? 0;
    case "taintPathSummary":
      return summarizeTaintPath(finding.taintPath) ?? "";
    case "engineKinds":
      return [...new Set((finding.engineProvenance ?? []).map((entry) => entry.kind))].join("|");
    default:
      return finding[column as keyof typeof finding];
  }
}

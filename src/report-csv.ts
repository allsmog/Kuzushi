import { writeFileSync } from "node:fs";
import type Database from "better-sqlite3";
import { getActionableFindings } from "./store.js";

const CSV_COLUMNS = [
  "fingerprint",
  "scanner",
  "filePath",
  "startLine",
  "severity",
  "verdict",
  "confidence",
  "ruleId",
  "message",
  "verifyCostUsd",
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
 * Columns: fingerprint, scanner, filePath, startLine, severity, verdict,
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
      const value = f[col as keyof typeof f];
      return escapeCsvField(value);
    });
    lines.push(row.join(","));
  }

  writeFileSync(outputPath, lines.join("\r\n") + "\r\n", "utf-8");
}

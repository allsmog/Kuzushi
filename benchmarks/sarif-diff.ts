#!/usr/bin/env tsx
/**
 * Compare two SARIF files and report differences.
 *
 * Usage:
 *   tsx benchmarks/sarif-diff.ts <before.sarif> <after.sarif> [--json <output.json>]
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import chalk from "chalk";
import type { SarifDiffEntry, SarifLog, SarifResult } from "./types.js";

const { values: opts, positionals } = parseArgs({
  options: {
    json: { type: "string" },
    help: { type: "boolean", short: "h", default: false },
  },
  allowPositionals: true,
  strict: true,
});

if (opts.help || positionals.length < 2) {
  console.log(`
${chalk.bold("Kuzushi SARIF Diff")}

${chalk.yellow("Usage:")}
  tsx benchmarks/sarif-diff.ts <before.sarif> <after.sarif> [--json <output.json>]

${chalk.yellow("Options:")}
  --json <path>   Write diff as JSON to this path
  -h, --help      Show this help
`);
  process.exit(opts.help ? 0 : 1);
}

// ── SARIF loading ──

function loadSarif(filePath: string): SarifLog {
  const resolved = resolve(filePath);
  if (!existsSync(resolved)) {
    console.error(chalk.red(`SARIF file not found: ${resolved}`));
    process.exit(1);
  }
  return JSON.parse(readFileSync(resolved, "utf-8")) as SarifLog;
}

// ── Fingerprinting ──

function fingerprintResult(result: SarifResult): string {
  const loc = result.locations?.[0]?.physicalLocation;
  const file = loc?.artifactLocation?.uri ?? "unknown";
  const line = loc?.region?.startLine ?? 0;
  return `${file}:${line}:${result.ruleId}`;
}

interface IndexedResult {
  fingerprint: string;
  result: SarifResult;
  verdict?: string;
  confidence?: number;
}

function indexResults(results: SarifResult[]): Map<string, IndexedResult> {
  const map = new Map<string, IndexedResult>();
  for (const result of results) {
    const fp = fingerprintResult(result);
    map.set(fp, {
      fingerprint: fp,
      result,
      verdict: result.properties?.verdict as string | undefined,
      confidence: result.properties?.confidence as number | undefined,
    });
  }
  return map;
}

// ── Diff computation ──

function computeDiff(before: SarifLog, after: SarifLog): SarifDiffEntry[] {
  const beforeRun = before.runs?.[0];
  const afterRun = after.runs?.[0];
  if (!beforeRun || !afterRun) {
    console.error(chalk.red("Both SARIF files must have at least one run."));
    process.exit(1);
  }

  const beforeIdx = indexResults(beforeRun.results);
  const afterIdx = indexResults(afterRun.results);
  const entries: SarifDiffEntry[] = [];

  // Find removed and changed
  for (const [fp, beforeEntry] of beforeIdx) {
    const afterEntry = afterIdx.get(fp);
    if (!afterEntry) {
      const loc = beforeEntry.result.locations?.[0]?.physicalLocation;
      entries.push({
        kind: "removed",
        fingerprint: fp,
        ruleId: beforeEntry.result.ruleId,
        file: loc?.artifactLocation?.uri ?? "unknown",
        line: loc?.region?.startLine ?? 0,
      });
    } else if (
      beforeEntry.verdict !== afterEntry.verdict ||
      beforeEntry.confidence !== afterEntry.confidence
    ) {
      const loc = afterEntry.result.locations?.[0]?.physicalLocation;
      entries.push({
        kind: "changed",
        fingerprint: fp,
        ruleId: afterEntry.result.ruleId,
        file: loc?.artifactLocation?.uri ?? "unknown",
        line: loc?.region?.startLine ?? 0,
        details: {
          before: { verdict: beforeEntry.verdict, confidence: beforeEntry.confidence },
          after: { verdict: afterEntry.verdict, confidence: afterEntry.confidence },
        },
      });
    }
  }

  // Find added
  for (const [fp, afterEntry] of afterIdx) {
    if (!beforeIdx.has(fp)) {
      const loc = afterEntry.result.locations?.[0]?.physicalLocation;
      entries.push({
        kind: "added",
        fingerprint: fp,
        ruleId: afterEntry.result.ruleId,
        file: loc?.artifactLocation?.uri ?? "unknown",
        line: loc?.region?.startLine ?? 0,
      });
    }
  }

  return entries.sort((a, b) => {
    const kindOrder = { removed: 0, changed: 1, added: 2 };
    return kindOrder[a.kind] - kindOrder[b.kind] || a.fingerprint.localeCompare(b.fingerprint);
  });
}

// ── Output ──

function printDiff(entries: SarifDiffEntry[], beforePath: string, afterPath: string): void {
  const added = entries.filter((e) => e.kind === "added");
  const removed = entries.filter((e) => e.kind === "removed");
  const changed = entries.filter((e) => e.kind === "changed");

  console.log();
  console.log(chalk.bold.underline("SARIF Diff"));
  console.log(`  Before: ${beforePath}`);
  console.log(`  After:  ${afterPath}`);
  console.log();
  console.log(
    `  ${chalk.green(`+${added.length} added`)}  ${chalk.red(`-${removed.length} removed`)}  ${chalk.yellow(`~${changed.length} changed`)}`,
  );

  if (removed.length > 0) {
    console.log();
    console.log(chalk.red.bold("Removed findings:"));
    for (const entry of removed) {
      console.log(chalk.red(`  - ${entry.ruleId} @ ${entry.file}:${entry.line}`));
    }
  }

  if (added.length > 0) {
    console.log();
    console.log(chalk.green.bold("Added findings:"));
    for (const entry of added) {
      console.log(chalk.green(`  + ${entry.ruleId} @ ${entry.file}:${entry.line}`));
    }
  }

  if (changed.length > 0) {
    console.log();
    console.log(chalk.yellow.bold("Changed findings:"));
    for (const entry of changed) {
      const b = entry.details?.before;
      const a = entry.details?.after;
      console.log(
        chalk.yellow(`  ~ ${entry.ruleId} @ ${entry.file}:${entry.line}`) +
          `  verdict: ${b?.verdict ?? "?"} -> ${a?.verdict ?? "?"}` +
          `  confidence: ${b?.confidence?.toFixed(2) ?? "?"} -> ${a?.confidence?.toFixed(2) ?? "?"}`,
      );
    }
  }

  if (entries.length === 0) {
    console.log(chalk.green("  No differences found."));
  }

  console.log();
}

// ── Main ──

const beforeSarif = loadSarif(positionals[0]);
const afterSarif = loadSarif(positionals[1]);
const diff = computeDiff(beforeSarif, afterSarif);

printDiff(diff, positionals[0], positionals[1]);

if (opts.json) {
  writeFileSync(resolve(opts.json), JSON.stringify(diff, null, 2) + "\n");
  console.log(chalk.green(`Diff JSON written to: ${opts.json}`));
}

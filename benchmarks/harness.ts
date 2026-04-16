#!/usr/bin/env tsx

/**
 * Benchmark evaluation harness for Kuzushi.
 *
 * Usage:
 *   tsx benchmarks/harness.ts --dataset benchmarks/owasp-benchmark --sarif results.sarif
 *   tsx benchmarks/harness.ts --dataset benchmarks/owasp-benchmark --run
 *   tsx benchmarks/harness.ts --dataset benchmarks/owasp-benchmark --run --config '{"model":"anthropic:claude-sonnet-4-6"}'
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

import chalk from "chalk";
import type {
  BenchmarkMetrics,
  CweMetrics,
  GroundTruthDataset,
  GroundTruthEntry,
  MatchResult,
  SarifLog,
  SarifResult,
} from "./types.js";

// ── CLI argument parsing ──

const { values: args } = parseArgs({
  options: {
    dataset: { type: "string", short: "d" },
    sarif: { type: "string", short: "s" },
    run: { type: "boolean", default: false },
    config: { type: "string", short: "c" },
    output: { type: "string", short: "o" },
    "line-tolerance": { type: "string", default: "10" },
    help: { type: "boolean", short: "h", default: false },
  },
  strict: true,
});

if (args.help || !args.dataset) {
  console.log(`
${chalk.bold("Kuzushi Benchmark Harness")}

${chalk.yellow("Usage:")}
  tsx benchmarks/harness.ts --dataset <path> [--sarif <path>] [--run] [--config <json>]

${chalk.yellow("Options:")}
  -d, --dataset <path>       Path to benchmark dataset directory (must contain ground-truth.json)
  -s, --sarif <path>         Path to existing SARIF file to evaluate
  --run                      Run kuzushi scan first, then evaluate
  -c, --config <json>        JSON config overrides for kuzushi scan
  -o, --output <path>        Write JSON metrics to this path
  --line-tolerance <n>       Line proximity tolerance for matching (default: 10)
  -h, --help                 Show this help
`);
  process.exit(args.help ? 0 : 1);
}

const LINE_TOLERANCE = parseInt(args["line-tolerance"] ?? "10", 10);

// ── Load ground truth ──

function loadGroundTruth(datasetDir: string): GroundTruthDataset {
  const gtPath = join(datasetDir, "ground-truth.json");
  if (!existsSync(gtPath)) {
    console.error(chalk.red(`Ground truth not found: ${gtPath}`));
    console.error(
      "Run the dataset's convert script first (e.g. tsx benchmarks/owasp-benchmark/convert-ground-truth.ts)",
    );
    process.exit(1);
  }
  return JSON.parse(readFileSync(gtPath, "utf-8")) as GroundTruthDataset;
}

// ── Load / generate SARIF ──

function loadSarif(sarifPath: string): SarifLog {
  const raw = readFileSync(sarifPath, "utf-8");
  return JSON.parse(raw) as SarifLog;
}

function runKuzushiScan(
  repoDir: string,
  sarifOutputPath: string,
  configOverrides?: string,
): { durationMs: number } {
  const cliPath = resolve(__dirname, "../src/cli.ts");
  const cmdArgs = [cliPath, "scan", repoDir, "--sarif", sarifOutputPath, "--fresh"];

  if (configOverrides) {
    try {
      const overrides = JSON.parse(configOverrides) as Record<string, unknown>;
      if (overrides["scanners"]) {
        cmdArgs.push("--scanners", String(overrides["scanners"]));
      }
      if (overrides["model"]) {
        cmdArgs.push("--model", String(overrides["model"]));
      }
      if (overrides["severity"]) {
        cmdArgs.push("--severity", String(overrides["severity"]));
      }
      if (overrides["baseUrl"]) {
        cmdArgs.push("--base-url", String(overrides["baseUrl"]));
      }
      if (overrides["max"]) {
        cmdArgs.push("--max", String(overrides["max"]));
      }
      if (overrides["apiKey"]) {
        cmdArgs.push("--api-key", String(overrides["apiKey"]));
      }
    } catch {
      console.error(chalk.red("Invalid --config JSON"));
      process.exit(1);
    }
  }

  console.log(chalk.blue(`Running: npx tsx ${redactCommandArgs(cmdArgs).join(" ")}`));
  const start = performance.now();

  execFileSync("npx", ["tsx", ...cmdArgs], {
    stdio: "inherit",
    encoding: "utf-8",
    timeout: 600_000,
  });

  return { durationMs: performance.now() - start };
}

function redactCommandArgs(args: string[]): string[] {
  const redacted = [...args];
  for (let i = 0; i < redacted.length; i += 1) {
    if (redacted[i] === "--api-key" && i + 1 < redacted.length) {
      redacted[i + 1] = "<redacted>";
    }
  }
  return redacted;
}

// ── Finding matching ──

function extractCwe(result: SarifResult, rules: Map<string, string[]>): string[] {
  const cwes: string[] = [];

  // Check rule tags
  const ruleTags = rules.get(result.ruleId);
  if (ruleTags) {
    for (const tag of ruleTags) {
      const match = tag.match(/cwe-(\d+)/i);
      if (match) {
        cwes.push(`CWE-${match[1]}`);
      }
    }
  }

  // Check ruleId for CWE pattern
  const ruleIdMatch = result.ruleId.match(/CWE[_-]?(\d+)/i);
  if (ruleIdMatch) {
    cwes.push(`CWE-${ruleIdMatch[1]}`);
  }

  // Check message text
  const msgMatch = result.message?.text?.match(/CWE[_-]?(\d+)/gi);
  if (msgMatch) {
    for (const m of msgMatch) {
      const numMatch = m.match(/(\d+)/);
      if (numMatch) {
        cwes.push(`CWE-${numMatch[1]}`);
      }
    }
  }

  return [...new Set(cwes)];
}

function normalizePath(filePath: string): string {
  return filePath
    .replace(/\\/g, "/")
    .replace(/^file:\/\/\//i, "/")
    .replace(/^\/+/, "")
    .replace(/^[A-Za-z]:\//, "")
    .replace(/^\.\//, "")
    .toLowerCase();
}

function normalizeCweId(cwe: string): number {
  const match = cwe.match(/(\d+)/);
  return match ? parseInt(match[1], 10) : -1;
}

function fingerprintResult(result: SarifResult): string {
  const loc = result.locations?.[0]?.physicalLocation;
  const file = loc?.artifactLocation?.uri ?? "unknown";
  const line = loc?.region?.startLine ?? 0;
  return `${normalizePath(file)}:${line}:${result.ruleId}`;
}

function matchFindings(
  groundTruth: GroundTruthEntry[],
  sarifResults: SarifResult[],
  ruleTagMap: Map<string, string[]>,
): MatchResult[] {
  // Deduplicate SARIF results by (file, line, ruleId) to prevent
  // structurally identical findings from inflating TP counts.
  const seenFingerprints = new Set<string>();
  const dedupedResults: SarifResult[] = [];
  for (const result of sarifResults) {
    const fp = fingerprintResult(result);
    if (!seenFingerprints.has(fp)) {
      seenFingerprints.add(fp);
      dedupedResults.push(result);
    }
  }

  // Index findings by normalized file path for fast lookup
  const findingsByFile = new Map<string, SarifResult[]>();
  for (const result of dedupedResults) {
    const loc = result.locations?.[0]?.physicalLocation;
    if (!loc?.artifactLocation?.uri) continue;
    const normFile = normalizePath(loc.artifactLocation.uri);
    const existing = findingsByFile.get(normFile) ?? [];
    existing.push(result);
    findingsByFile.set(normFile, existing);
  }

  const usedFindings = new Set<SarifResult>();

  return groundTruth.map((gt) => {
    const normGtFile = normalizePath(gt.file);
    const gtCweNum = normalizeCweId(gt.cwe);
    const candidates = findingsByFile.get(normGtFile) ?? [];

    let bestMatch: SarifResult | null = null;
    let bestDistance = Infinity;

    for (const candidate of candidates) {
      if (usedFindings.has(candidate)) continue;

      const loc = candidate.locations?.[0]?.physicalLocation;
      const candidateLine = loc?.region?.startLine ?? 0;
      const lineDistance = Math.abs(candidateLine - gt.line);

      if (lineDistance > LINE_TOLERANCE) continue;

      // Check CWE overlap
      const candidateCwes = extractCwe(candidate, ruleTagMap);
      const cweMatch =
        candidateCwes.length === 0 || candidateCwes.some((c) => normalizeCweId(c) === gtCweNum);
      if (!cweMatch && candidateCwes.length > 0) continue;

      if (lineDistance < bestDistance) {
        bestDistance = lineDistance;
        bestMatch = candidate;
      }
    }

    if (bestMatch) {
      usedFindings.add(bestMatch);
    }

    return {
      groundTruth: gt,
      finding: bestMatch,
      matched: bestMatch !== null,
    };
  });
}

// ── Metrics computation ──

function computeMetrics(
  datasetName: string,
  matchResults: MatchResult[],
  costUsd: number,
  durationMs: number,
): BenchmarkMetrics {
  let tp = 0;
  let fp = 0;
  let fn = 0;
  let tn = 0;

  const cweBuckets = new Map<string, { tp: number; fp: number; fn: number; tn: number }>();

  for (const result of matchResults) {
    const cwe = result.groundTruth.cwe;
    const bucket = cweBuckets.get(cwe) ?? { tp: 0, fp: 0, fn: 0, tn: 0 };

    if (result.groundTruth.isVulnerable) {
      if (result.matched) {
        tp++;
        bucket.tp++;
      } else {
        fn++;
        bucket.fn++;
      }
    } else {
      if (result.matched) {
        fp++;
        bucket.fp++;
      } else {
        tn++;
        bucket.tn++;
      }
    }

    cweBuckets.set(cwe, bucket);
  }

  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  const perCwe: Record<string, CweMetrics> = {};
  for (const [cwe, b] of cweBuckets) {
    const p = b.tp + b.fp > 0 ? b.tp / (b.tp + b.fp) : 0;
    const r = b.tp + b.fn > 0 ? b.tp / (b.tp + b.fn) : 0;
    const f = p + r > 0 ? (2 * p * r) / (p + r) : 0;
    perCwe[cwe] = { tp: b.tp, fp: b.fp, fn: b.fn, tn: b.tn, precision: p, recall: r, f1: f };
  }

  return {
    dataset: datasetName,
    tp,
    fp,
    fn,
    tn,
    precision,
    recall,
    f1,
    perCwe,
    costUsd,
    durationMs,
  };
}

// ── Terminal output ──

function printMetrics(metrics: BenchmarkMetrics): void {
  console.log();
  console.log(chalk.bold.underline(`Benchmark Results: ${metrics.dataset}`));
  console.log();

  // Summary table
  const headers = ["Metric", "Value"];
  const rows = [
    ["True Positives", String(metrics.tp)],
    ["False Positives", String(metrics.fp)],
    ["False Negatives", String(metrics.fn)],
    ["True Negatives", String(metrics.tn)],
    ["Precision", `${(metrics.precision * 100).toFixed(1)}%`],
    ["Recall", `${(metrics.recall * 100).toFixed(1)}%`],
    ["F1 Score", `${(metrics.f1 * 100).toFixed(1)}%`],
    ["Cost (USD)", `$${metrics.costUsd.toFixed(4)}`],
    ["Duration", `${(metrics.durationMs / 1000).toFixed(1)}s`],
  ];

  printTable(headers, rows);

  // Per-CWE breakdown
  const cweEntries = Object.entries(metrics.perCwe).sort(([a], [b]) => a.localeCompare(b));
  if (cweEntries.length > 0) {
    console.log();
    console.log(chalk.bold("Per-CWE Breakdown:"));

    const cweHeaders = ["CWE", "TP", "FP", "FN", "TN", "Precision", "Recall", "F1"];
    const cweRows = cweEntries.map(([cwe, m]) => [
      cwe,
      String(m.tp),
      String(m.fp),
      String(m.fn),
      String(m.tn),
      `${(m.precision * 100).toFixed(1)}%`,
      `${(m.recall * 100).toFixed(1)}%`,
      `${(m.f1 * 100).toFixed(1)}%`,
    ]);

    printTable(cweHeaders, cweRows);
  }
}

function printTable(headers: string[], rows: string[][]): void {
  const colWidths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i] ?? "").length)),
  );

  const sep = colWidths.map((w) => "-".repeat(w + 2)).join("+");
  const formatRow = (row: string[]) =>
    row.map((cell, i) => ` ${cell.padEnd(colWidths[i])} `).join("|");

  console.log(chalk.dim(sep));
  console.log(chalk.bold(formatRow(headers)));
  console.log(chalk.dim(sep));
  for (const row of rows) {
    console.log(formatRow(row));
  }
  console.log(chalk.dim(sep));
}

// ── Main ──

async function main(): Promise<void> {
  const datasetDir = resolve(args.dataset!);
  const dataset = loadGroundTruth(datasetDir);

  console.log(chalk.bold(`Dataset: ${dataset.name}`));
  console.log(`  Language: ${dataset.language}`);
  console.log(`  Entries: ${dataset.entries.length}`);
  console.log(`  Vulnerable: ${dataset.entries.filter((e) => e.isVulnerable).length}`);
  console.log(`  Non-vulnerable: ${dataset.entries.filter((e) => !e.isVulnerable).length}`);

  let sarifPath: string;
  let durationMs = 0;

  if (args.run) {
    // Run kuzushi scan first
    const repoDir = join(datasetDir, "repo");
    if (!existsSync(repoDir)) {
      console.error(chalk.red(`Repo not found at ${repoDir}. Run the dataset's setup.sh first.`));
      process.exit(1);
    }

    const resultsDir = join(datasetDir, "results");
    if (!existsSync(resultsDir)) {
      mkdirSync(resultsDir, { recursive: true });
    }

    sarifPath = join(resultsDir, `kuzushi-${Date.now()}.sarif`);
    const timing = runKuzushiScan(repoDir, sarifPath, args.config);
    durationMs = timing.durationMs;
  } else if (args.sarif) {
    sarifPath = resolve(args.sarif);
    if (!existsSync(sarifPath)) {
      console.error(chalk.red(`SARIF file not found: ${sarifPath}`));
      process.exit(1);
    }
  } else {
    console.error(chalk.red("Provide either --sarif <path> or --run"));
    process.exit(1);
  }

  console.log(chalk.blue(`Loading SARIF: ${sarifPath}`));
  const sarif = loadSarif(sarifPath);
  const run = sarif.runs?.[0];
  if (!run) {
    console.error(chalk.red("No runs found in SARIF file"));
    process.exit(1);
  }

  // Build rule -> tags map
  const ruleTagMap = new Map<string, string[]>();
  for (const rule of run.tool.driver.rules ?? []) {
    if (rule.properties?.tags) {
      ruleTagMap.set(rule.id, rule.properties.tags);
    }
  }

  // Extract cost from SARIF properties
  const summaryProps = run.properties?.["summary"] as Record<string, unknown> | undefined;
  const costUsd =
    typeof summaryProps?.["totalCostUsd"] === "number"
      ? (summaryProps["totalCostUsd"] as number)
      : 0;

  console.log(`  SARIF results: ${run.results.length}`);

  // Match findings against ground truth
  const matchResults = matchFindings(dataset.entries, run.results, ruleTagMap);
  const metrics = computeMetrics(dataset.name, matchResults, costUsd, durationMs);

  printMetrics(metrics);

  // Write JSON output
  const outputPath = args.output ?? join(datasetDir, "results", `metrics-${Date.now()}.json`);
  const outputDir = resolve(outputPath, "..");
  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }
  writeFileSync(outputPath, JSON.stringify(metrics, null, 2) + "\n");
  console.log(chalk.green(`\nMetrics written to: ${outputPath}`));
}

main().catch((err) => {
  console.error(chalk.red(err instanceof Error ? err.message : String(err)));
  process.exit(1);
});

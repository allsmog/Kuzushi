#!/usr/bin/env tsx

/** Evaluate complete Kuzushi SARIF output against a ground-truth dataset. */

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import chalk from "chalk";
import { assertDatasetCheckout } from "./benchmark-dataset-checkout.js";
import { assertExecutionMatchesDeclaration } from "./benchmark-execution-evidence.js";
import { withMaterializedCorpus } from "./benchmark-materialized-corpus.js";
import {
  assertConfigMatchesDeclaration,
  buildResultProvenance,
  loadProvenanceInput,
} from "./benchmark-provenance.js";
import { loadBenchmarkSarif } from "./benchmark-sarif.js";
import { parseScanConfigArgument, scanConfigArgs } from "./benchmark-scan-config.js";
import { recordedBenchmarkSpend } from "./benchmark-spend.js";
import { loadGroundTruth } from "./ground-truth.js";
import {
  DEFAULT_LINE_TOLERANCE,
  evaluateBenchmark,
  MAX_LINE_TOLERANCE,
  parseLineTolerance,
} from "./scoring.js";
import type {
  BenchmarkMetrics,
  BenchmarkProvenanceInput,
  BenchmarkScanConfig,
  GroundTruthDataset,
} from "./types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliArgs = process.argv.slice(2);
if (cliArgs[0] === "--") cliArgs.shift();
const { values: args } = parseArgs({
  args: cliArgs,
  options: {
    dataset: { type: "string", short: "d" },
    sarif: { type: "string", short: "s" },
    run: { type: "boolean", default: false },
    config: { type: "string", short: "c" },
    output: { type: "string", short: "o" },
    provenance: { type: "string", short: "p" },
    "line-tolerance": { type: "string", default: String(DEFAULT_LINE_TOLERANCE) },
    help: { type: "boolean", short: "h", default: false },
  },
  strict: true,
});

if (args.help || !args.dataset || !args.provenance) {
  printHelp();
  process.exit(args.help ? 0 : 1);
}

function printHelp(): void {
  console.log(`
${chalk.bold("Kuzushi Benchmark Harness")}

${chalk.yellow("Usage:")}
  tsx benchmarks/harness.ts --dataset <path> --provenance <path> [--sarif <path> | --run]

${chalk.yellow("Options:")}
  -d, --dataset <path>       Dataset directory containing ground-truth.json
  -s, --sarif <path>         Existing deterministic-fixture SARIF to evaluate
  --run                      Run kuzushi scan first (required for real-model mode)
  -c, --config <json>        Exact harness scan config (required with --run)
  -o, --output <path>        Write JSON metrics to this path
  -p, --provenance <path>    Explicit execution/model/config provenance declaration
  --line-tolerance <n>       Match tolerance, 0..${MAX_LINE_TOLERANCE} (default: ${DEFAULT_LINE_TOLERANCE})
  -h, --help                 Show this help
`);
}

async function main(): Promise<void> {
  const declaration = loadProvenanceInput(args.provenance!);
  assertExclusiveInput();
  assertExecutionInputPolicy(declaration);
  const datasetDir = resolve(args.dataset!);
  const dataset = loadGroundTruth(join(datasetDir, "ground-truth.json"));
  assertConfigMatchesDeclaration(args.config, declaration);
  const runConfig = args.run ? parseScanConfigArgument(args.config) : declaration.scanConfig;
  const tolerance = parseLineTolerance(args["line-tolerance"] ?? String(DEFAULT_LINE_TOLERANCE));
  printDataset(dataset, tolerance);
  const input = benchmarkInput(datasetDir, dataset, runConfig);
  const sarif = loadBenchmarkSarif(input.sarifPath);
  const spend = recordedBenchmarkSpend(sarif);
  assertExecutionMatchesDeclaration(declaration, spend.receipt);
  const provenance = buildResultProvenance({
    declaration,
    dataset,
    durationMs: input.durationMs,
    spend: spend.receipt,
  });
  const evaluation = evaluateBenchmark(
    dataset,
    sarif,
    tolerance,
    spend.costUsd,
    spend.receipt,
    input.durationMs,
    provenance,
  );
  console.log(`  SARIF runs: ${sarif.runs.length}`);
  console.log(`  Scored findings: ${evaluation.scoredFindingCount}`);
  printMetrics(evaluation.metrics);
  writeMetrics(datasetDir, evaluation.metrics);
}

function benchmarkInput(
  datasetDir: string,
  dataset: GroundTruthDataset,
  config: BenchmarkScanConfig,
): { sarifPath: string; durationMs: number } {
  return args.run ? executeBenchmarkScan(datasetDir, dataset, config) : existingSarifInput();
}

function assertExclusiveInput(): void {
  if (args.run && args.sarif) throw new Error("Provide only one of --sarif or --run");
}

function assertExecutionInputPolicy(declaration: BenchmarkProvenanceInput): void {
  if (declaration.executionMode === "real-model" && !args.run) {
    throw new Error(
      "real-model provenance requires --run so the harness can verify the declared dataset checkout; --sarif is deterministic-fixture-only",
    );
  }
}

function existingSarifInput(): { sarifPath: string; durationMs: number } {
  if (!args.sarif) throw new Error("Provide either --sarif <path> or --run");
  const sarifPath = resolve(args.sarif);
  if (!existsSync(sarifPath)) throw new Error(`SARIF file not found: ${sarifPath}`);
  console.log(chalk.blue(`Loading SARIF: ${sarifPath}`));
  return { sarifPath, durationMs: 0 };
}

function executeBenchmarkScan(
  datasetDir: string,
  dataset: GroundTruthDataset,
  config: BenchmarkScanConfig,
): { sarifPath: string; durationMs: number } {
  const repoDir = join(datasetDir, "repo");
  if (!existsSync(repoDir)) throw new Error(`Repo not found at ${repoDir}. Run setup.sh first.`);
  const revision = assertDatasetCheckout(datasetDir, dataset);
  const resultsDir = join(datasetDir, "results");
  mkdirSync(resultsDir, { recursive: true });
  const sarifPath = join(resultsDir, `kuzushi-${Date.now()}.sarif`);
  const durationMs = withMaterializedCorpus(repoDir, revision, (corpusRoot) =>
    runKuzushiScan(corpusRoot, sarifPath, config),
  );
  return { sarifPath, durationMs };
}

function runKuzushiScan(repoDir: string, sarifPath: string, config: BenchmarkScanConfig): number {
  const cliPath = resolve(__dirname, "../bin/kuzushi-rs.mjs");
  const command = ["scan", repoDir, "--sarif", sarifPath, ...scanConfigArgs(config)];
  console.log(chalk.blue(`Running: ${[process.execPath, cliPath, ...command].join(" ")}`));
  const started = performance.now();
  execFileSync(process.execPath, [cliPath, ...command], {
    stdio: "inherit",
    encoding: "utf8",
    timeout: 600_000,
  });
  return performance.now() - started;
}

function printDataset(dataset: GroundTruthDataset, tolerance: number): void {
  console.log(chalk.bold(`Dataset: ${dataset.name}`));
  console.log(`  Language: ${dataset.language}`);
  console.log(`  Entries: ${dataset.entries.length}`);
  console.log(`  Vulnerable: ${dataset.entries.filter((entry) => entry.isVulnerable).length}`);
  console.log(`  Non-vulnerable: ${dataset.entries.filter((entry) => !entry.isVulnerable).length}`);
  console.log(`  Line tolerance: ${tolerance}`);
}

function printMetrics(metrics: BenchmarkMetrics): void {
  console.log();
  console.log(chalk.bold.underline(`Benchmark Results: ${metrics.dataset}`));
  printTable(["Metric", "Value"], aggregateRows(metrics));
  printCweMetrics(metrics);
}

function aggregateRows(metrics: BenchmarkMetrics): string[][] {
  return [
    ["True Positives", String(metrics.tp)],
    ["False Positives", String(metrics.fp)],
    ["False Negatives", String(metrics.fn)],
    ["True Negatives", String(metrics.tn)],
    ["Precision", formatPercent(metrics.precision)],
    ["Recall", formatPercent(metrics.recall)],
    ["F1 Score", formatPercent(metrics.f1)],
    ["Cost (USD)", `$${metrics.costUsd.toFixed(4)}`],
    ["Spend receipt", `${metrics.spend.source}:${metrics.spend.runId}`],
    ["Duration", `${(metrics.durationMs / 1000).toFixed(1)}s`],
  ];
}

function printCweMetrics(metrics: BenchmarkMetrics): void {
  const entries = Object.entries(metrics.perCwe).sort(([left], [right]) =>
    left.localeCompare(right),
  );
  if (entries.length === 0) return;
  console.log();
  console.log(chalk.bold("Per-CWE Breakdown:"));
  const rows = entries.map(([cwe, value]) => [
    cwe,
    String(value.tp),
    String(value.fp),
    String(value.fn),
    String(value.tn),
    formatPercent(value.precision),
    formatPercent(value.recall),
    formatPercent(value.f1),
  ]);
  printTable(["CWE", "TP", "FP", "FN", "TN", "Precision", "Recall", "F1"], rows);
}

function printTable(headers: string[], rows: string[][]): void {
  const widths = headers.map((header, index) =>
    Math.max(header.length, ...rows.map((row) => (row[index] ?? "").length)),
  );
  const separator = widths.map((width) => "-".repeat(width + 2)).join("+");
  const rowText = (row: string[]) =>
    row.map((cell, index) => ` ${cell.padEnd(widths[index])} `).join("|");
  console.log(chalk.dim(separator));
  console.log(chalk.bold(rowText(headers)));
  console.log(chalk.dim(separator));
  for (const row of rows) console.log(rowText(row));
  console.log(chalk.dim(separator));
}

function formatPercent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function writeMetrics(datasetDir: string, metrics: BenchmarkMetrics): void {
  const path = resolve(args.output ?? join(datasetDir, "results", `metrics-${Date.now()}.json`));
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(metrics, null, 2)}\n`);
  console.log(chalk.green(`\nMetrics written to: ${path}`));
}

main().catch((error) => {
  console.error(chalk.red(error instanceof Error ? error.message : String(error)));
  process.exit(1);
});

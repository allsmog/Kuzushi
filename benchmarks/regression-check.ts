#!/usr/bin/env tsx
/**
 * Regression gate for Kuzushi benchmark metrics.
 *
 * Compares one or more benchmark result files against a stored baseline and
 * fails (exit 1) when precision or recall drops beyond configurable thresholds.
 *
 * Usage:
 *   tsx benchmarks/regression-check.ts --results metrics-a.json,metrics-b.json
 *   tsx benchmarks/regression-check.ts --results metrics.json --update-baseline
 *   tsx benchmarks/regression-check.ts --results metrics.json --precision-threshold 0.02
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { parseArgs } from "node:util";
import chalk from "chalk";
import {
  assertBaseline,
  assertCompatibleResultSet,
  assertCompatibleResults,
  assertMetrics,
} from "./benchmark-provenance.js";
import type { BaselineMetrics, BenchmarkMetrics, CweMetrics } from "./types.js";

// ── CLI argument parsing ──

const cliArgs = process.argv.slice(2);
if (cliArgs[0] === "--") cliArgs.shift();
const { values: args } = parseArgs({
  args: cliArgs,
  options: {
    baseline: { type: "string", default: "benchmarks/baseline.json" },
    results: { type: "string" },
    "update-baseline": { type: "boolean", default: false },
    "bootstrap-baseline": { type: "boolean", default: false },
    "precision-threshold": { type: "string", default: "0.03" },
    "recall-threshold": { type: "string", default: "0.03" },
    "cost-threshold": { type: "string", default: "0.25" },
    help: { type: "boolean", short: "h", default: false },
  },
  strict: true,
});

if (args.help) {
  console.log(`
${chalk.bold("Kuzushi Regression Check")}

${chalk.yellow("Usage:")}
  tsx benchmarks/regression-check.ts --results <path,...> [options]

${chalk.yellow("Options:")}
  --baseline <path>              Path to baseline JSON (default: benchmarks/baseline.json)
  --results <path,...>           Comma-separated paths to metrics JSON files (from harness.ts)
  --update-baseline              Update the baseline file on success
  --bootstrap-baseline           Create a missing baseline from these results
  --precision-threshold <n>      Max precision drop, 0..1 (default: 0.03 = 3%)
  --recall-threshold <n>         Max recall drop, 0..1 (default: 0.03 = 3%)
  --cost-threshold <n>           Max cost ratio increase, 0..10 (default: 0.25 = 25%)
  -h, --help                     Show this help
`);
  process.exit(0);
}

if (!args.results) {
  console.error(
    chalk.red(
      "Error: --results is required. Provide one or more comma-separated metric file paths.",
    ),
  );
  process.exit(1);
}

const PRECISION_THRESHOLD = parseThreshold(args["precision-threshold"] ?? "0.03", "precision", 1);
const RECALL_THRESHOLD = parseThreshold(args["recall-threshold"] ?? "0.03", "recall", 1);
const COST_THRESHOLD = parseThreshold(args["cost-threshold"] ?? "0.25", "cost", 10);
const baselinePath = resolve(args.baseline ?? "benchmarks/baseline.json");
const resultPaths = args.results.split(",").map((p) => resolve(p.trim()));

// ── Load files ──

function loadBaseline(filePath: string, allowMissing: boolean): BaselineMetrics {
  if (!existsSync(filePath)) return createMissingBaseline(filePath, allowMissing);
  const parsed: unknown = JSON.parse(readFileSync(filePath, "utf-8"));
  assertBaseline(parsed, filePath);
  return parsed;
}

function createMissingBaseline(filePath: string, allowMissing: boolean): BaselineMetrics {
  if (!allowMissing) {
    throw new Error(
      `Baseline not found: ${filePath}. Use --bootstrap-baseline or --update-baseline only for an intentional baseline write.`,
    );
  }
  return emptyBaseline();
}

function loadMetrics(filePath: string): BenchmarkMetrics {
  if (!existsSync(filePath)) {
    console.error(chalk.red(`Metrics file not found: ${filePath}`));
    process.exit(1);
  }
  const parsed: unknown = JSON.parse(readFileSync(filePath, "utf-8"));
  assertMetrics(parsed, filePath);
  return parsed;
}

function emptyBaseline(): BaselineMetrics {
  return {
    schemaVersion: 2,
    updatedAt: new Date().toISOString(),
    datasets: {},
  };
}

function parseThreshold(raw: string, name: string, maximum: number): number {
  const parsed = raw.trim() === "" ? Number.NaN : Number(raw);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > maximum) {
    console.error(
      chalk.red(`Invalid ${name} threshold ${JSON.stringify(raw)}; expected 0..${maximum}.`),
    );
    process.exit(1);
  }
  return parsed;
}

// ── Comparison logic ──

interface RegressionResult {
  dataset: string;
  passed: boolean;
  precisionDelta: number;
  recallDelta: number;
  f1Delta: number;
  costDeltaRatio: number;
  precisionFail: boolean;
  recallFail: boolean;
  costFail: boolean;
  cweWarnings: string[];
  before: BenchmarkMetrics | null;
  after: BenchmarkMetrics;
}

function compareDataset(
  baseline: BenchmarkMetrics | null,
  current: BenchmarkMetrics,
): RegressionResult {
  if (!baseline) return unbaselinedResult(current);
  const deltas = regressionDeltas(baseline, current);
  const failures = regressionFailures(baseline, current, deltas);
  return {
    dataset: current.dataset,
    passed: !failures.precisionFail && !failures.recallFail && !failures.costFail,
    ...deltas,
    ...failures,
    cweWarnings: cweRegressionWarnings(baseline, current),
    before: baseline,
    after: current,
  };
}

function unbaselinedResult(current: BenchmarkMetrics): RegressionResult {
  return {
    dataset: current.dataset,
    passed: true,
    precisionDelta: 0,
    recallDelta: 0,
    f1Delta: 0,
    costDeltaRatio: 0,
    precisionFail: false,
    recallFail: false,
    costFail: false,
    cweWarnings: [],
    before: null,
    after: current,
  };
}

function regressionDeltas(baseline: BenchmarkMetrics, current: BenchmarkMetrics) {
  return {
    precisionDelta: roundDelta(current.precision - baseline.precision),
    recallDelta: roundDelta(current.recall - baseline.recall),
    f1Delta: roundDelta(current.f1 - baseline.f1),
    costDeltaRatio: benchmarkCostDeltaRatio(baseline.costUsd, current.costUsd),
  };
}

function regressionFailures(
  baseline: BenchmarkMetrics,
  current: BenchmarkMetrics,
  deltas: ReturnType<typeof regressionDeltas>,
) {
  return {
    precisionFail: deltas.precisionDelta < -PRECISION_THRESHOLD,
    recallFail: deltas.recallDelta < -RECALL_THRESHOLD,
    costFail: costRegressed(baseline, current, deltas.costDeltaRatio),
  };
}

function cweRegressionWarnings(baseline: BenchmarkMetrics, current: BenchmarkMetrics): string[] {
  return Object.entries(current.perCwe).flatMap(([cwe, currentCwe]) =>
    cweWarningsAt(cwe, baseline.perCwe[cwe], currentCwe),
  );
}

function cweWarningsAt(
  cwe: string,
  baseline: CweMetrics | undefined,
  current: CweMetrics,
): string[] {
  if (!baseline) return [];
  return [
    cweMetricWarning(cwe, "precision", baseline.precision, current.precision, PRECISION_THRESHOLD),
    cweMetricWarning(cwe, "recall", baseline.recall, current.recall, RECALL_THRESHOLD),
  ].filter((warning): warning is string => warning !== null);
}

function cweMetricWarning(
  cwe: string,
  metric: string,
  baseline: number,
  current: number,
  threshold: number,
): string | null {
  const delta = roundDelta(current - baseline);
  if (delta >= -(threshold * 2)) return null;
  return `${cwe}: ${metric} dropped ${formatDelta(delta)} (${formatPct(baseline)} -> ${formatPct(current)})`;
}

// ── Numeric helpers ──

function roundDelta(value: number): number {
  return Math.round(value * 1e6) / 1e6;
}

function benchmarkCostDeltaRatio(baseline: number, current: number): number {
  if (baseline > 0) return roundDelta((current - baseline) / baseline);
  return current > 0 ? Number.POSITIVE_INFINITY : 0;
}

function costRegressed(
  baseline: BenchmarkMetrics,
  current: BenchmarkMetrics,
  deltaRatio: number,
): boolean {
  if (current.tp > baseline.tp || current.costUsd <= baseline.costUsd) return false;
  return baseline.costUsd === 0 || deltaRatio > COST_THRESHOLD;
}

// ── Formatting helpers ──

function formatPct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function formatDelta(delta: number): string {
  const sign = delta >= 0 ? "+" : "";
  return `${sign}${(delta * 100).toFixed(1)}pp`;
}

function colorDelta(delta: number, threshold: number): string {
  const text = formatDelta(delta);
  if (delta < -threshold) return chalk.red(text);
  if (delta < 0) return chalk.yellow(text);
  if (delta > 0) return chalk.green(text);
  return chalk.dim(text);
}

function formatCostDelta(deltaRatio: number): string {
  if (deltaRatio === Number.POSITIVE_INFINITY) return "+infinite (baseline was $0)";
  const sign = deltaRatio >= 0 ? "+" : "";
  return `${sign}${(deltaRatio * 100).toFixed(1)}%`;
}

function colorCostDelta(deltaRatio: number, threshold: number, failed: boolean): string {
  const text = formatCostDelta(deltaRatio);
  if (failed) return chalk.red(text);
  if (deltaRatio > threshold) return chalk.yellow(text);
  if (deltaRatio > 0) return chalk.green(text);
  return chalk.dim(text);
}

// ── Table rendering ──

function printComparisonTable(results: RegressionResult[]): void {
  console.log();
  console.log(chalk.bold.underline("Regression Check Results"));
  console.log();
  const headers = [
    "Dataset",
    "Precision (before)",
    "Precision (after)",
    "Prec Delta",
    "Recall (before)",
    "Recall (after)",
    "Rec Delta",
    "Cost Delta",
    "F1 Delta",
    "Status",
  ];
  printTable(headers, results.map(comparisonRow));
  printObservationRevisions(results);
  printCweWarnings(results);
}

function comparisonRow(result: RegressionResult): string[] {
  return [
    result.dataset,
    beforePercent(result, "precision"),
    formatPct(result.after.precision),
    deltaCell(result, result.precisionDelta, PRECISION_THRESHOLD),
    beforePercent(result, "recall"),
    formatPct(result.after.recall),
    deltaCell(result, result.recallDelta, RECALL_THRESHOLD),
    costDeltaCell(result),
    deltaCell(result, result.f1Delta, 0),
    regressionStatus(result),
  ];
}

function beforePercent(result: RegressionResult, metric: "precision" | "recall"): string {
  return result.before ? formatPct(result.before[metric]) : chalk.dim("n/a");
}

function deltaCell(result: RegressionResult, delta: number, threshold: number): string {
  return result.before ? colorDelta(delta, threshold) : chalk.dim("new");
}

function costDeltaCell(result: RegressionResult): string {
  return result.before
    ? colorCostDelta(result.costDeltaRatio, COST_THRESHOLD, result.costFail)
    : chalk.dim("new");
}

function regressionStatus(result: RegressionResult): string {
  if (!result.before) return chalk.blue("NEW");
  if (result.passed) return chalk.green("PASS");
  return chalk.red(`FAIL (${failureReasons(result).join(", ")})`);
}

function failureReasons(result: RegressionResult): string[] {
  const reasons: string[] = [];
  if (result.precisionFail) reasons.push("precision");
  if (result.recallFail) reasons.push("recall");
  if (result.costFail) reasons.push("cost");
  return reasons;
}

function printCweWarnings(results: RegressionResult[]): void {
  for (const result of results) {
    if (result.cweWarnings.length > 0) {
      console.log();
      console.log(chalk.yellow.bold(`Per-CWE warnings for ${result.dataset}:`));
      for (const warning of result.cweWarnings) {
        console.log(chalk.yellow(`  ! ${warning}`));
      }
    }
  }
}

function printObservationRevisions(results: RegressionResult[]): void {
  console.log();
  for (const result of results) {
    const before = result.before?.provenance.observed.kuzushiRevision ?? "new baseline";
    const after = result.after.provenance.observed.kuzushiRevision;
    console.log(`  ${result.dataset} code revision: ${before} -> ${after}`);
  }
}

function stripAnsi(str: string): number {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: ESC (\x1b) is required to strip ANSI color codes
  return str.replace(/\x1b\[[0-9;]*m/g, "").length;
}

function printTable(headers: string[], rows: string[][]): void {
  const colWidths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => stripAnsi(r[i] ?? ""))),
  );

  const sep = colWidths.map((w) => "-".repeat(w + 2)).join("+");

  const formatRow = (row: string[]) =>
    row
      .map((cell, i) => {
        const visible = stripAnsi(cell);
        const padding = Math.max(0, colWidths[i] - visible);
        return ` ${cell}${" ".repeat(padding)} `;
      })
      .join("|");

  console.log(chalk.dim(sep));
  console.log(chalk.bold(formatRow(headers)));
  console.log(chalk.dim(sep));
  for (const row of rows) {
    console.log(formatRow(row));
  }
  console.log(chalk.dim(sep));
}

// ── Main ──

function main(): void {
  printRunConfiguration();
  const input = loadRegressionInput();
  assertDatasetsAreBaselined(input);
  const results = compareMetrics(input);
  printComparisonTable(results);
  reportRegressionOutcome(results);
  updateBaseline(input);
  console.log();
}

interface RegressionInput {
  writesBaseline: boolean;
  baseline: BaselineMetrics;
  metricsFiles: BenchmarkMetrics[];
}

function printRunConfiguration(): void {
  console.log(chalk.bold("Kuzushi Regression Check"));
  console.log(`  Baseline: ${baselinePath}`);
  console.log(`  Results: ${resultPaths.join(", ")}`);
  console.log(`  Precision threshold: ${formatPct(PRECISION_THRESHOLD)} drop`);
  console.log(`  Recall threshold: ${formatPct(RECALL_THRESHOLD)} drop`);
  console.log(
    `  Cost threshold: ${(COST_THRESHOLD * 100).toFixed(1)}% increase unless TP count improves`,
  );
}

function loadRegressionInput(): RegressionInput {
  const writesBaseline = Boolean(args["update-baseline"] || args["bootstrap-baseline"]);
  return {
    writesBaseline,
    baseline: loadBaseline(baselinePath, writesBaseline),
    metricsFiles: resultPaths.map(loadMetrics),
  };
}

function assertDatasetsAreBaselined(input: RegressionInput): void {
  assertInputProvenance(input);
  const unknownDatasets = input.metricsFiles
    .map((metrics) => metrics.dataset)
    .filter((dataset) => input.baseline.datasets[dataset] === undefined);
  if (unknownDatasets.length > 0 && !input.writesBaseline) {
    throw new Error(
      `No baseline entry for dataset(s): ${unknownDatasets.join(", ")}. ` +
        "Use --update-baseline only after reviewing the deterministic results and provenance.",
    );
  }
}

function assertInputProvenance(input: RegressionInput): void {
  assertCompatibleResultSet(input.metricsFiles, "regression results");
  for (const metrics of input.metricsFiles) {
    const baseline = input.baseline.datasets[metrics.dataset];
    if (baseline) assertCompatibleResults(baseline, metrics);
  }
  const combined = { ...input.baseline.datasets };
  for (const metrics of input.metricsFiles) combined[metrics.dataset] = metrics;
  assertCompatibleResultSet(Object.values(combined), "regression baseline and results");
}

function compareMetrics(input: RegressionInput): RegressionResult[] {
  return input.metricsFiles.map((metrics) =>
    compareDataset(input.baseline.datasets[metrics.dataset] ?? null, metrics),
  );
}

function reportRegressionOutcome(results: RegressionResult[]): void {
  const failures = results.filter((r) => !r.passed);
  const totalWarnings = results.reduce((sum, r) => sum + r.cweWarnings.length, 0);
  console.log();
  if (failures.length > 0) failRegression(failures);
  printWarningSummary(totalWarnings);
  console.log(chalk.green.bold("All datasets passed the regression gate."));
}

function failRegression(failures: RegressionResult[]): never {
  console.log(
    chalk.red.bold(
      `REGRESSION DETECTED: ${failures.length} dataset(s) failed the regression gate.`,
    ),
  );
  console.log();
  for (const failure of failures) {
    for (const message of failureMessages(failure)) console.log(chalk.red(message));
  }
  console.log();
  process.exit(1);
}

function failureMessages(failure: RegressionResult): string[] {
  const messages: string[] = [];
  if (failure.precisionFail) {
    messages.push(
      `  ${failure.dataset}: precision dropped ${formatDelta(failure.precisionDelta)} ` +
        `(threshold: ${formatPct(PRECISION_THRESHOLD)})`,
    );
  }
  if (failure.recallFail) {
    messages.push(
      `  ${failure.dataset}: recall dropped ${formatDelta(failure.recallDelta)} ` +
        `(threshold: ${formatPct(RECALL_THRESHOLD)})`,
    );
  }
  if (failure.costFail) {
    messages.push(
      `  ${failure.dataset}: cost increased ${formatCostDelta(failure.costDeltaRatio)} ` +
        `without TP improvement (threshold: ${(COST_THRESHOLD * 100).toFixed(1)}%)`,
    );
  }
  return messages;
}

function printWarningSummary(totalWarnings: number): void {
  if (totalWarnings === 0) return;
  console.log(
    chalk.yellow(`${totalWarnings} per-CWE warning(s) detected, but aggregate thresholds passed.`),
  );
}

function updateBaseline(input: RegressionInput): void {
  if (!input.writesBaseline) return;
  const newBaseline: BaselineMetrics = {
    schemaVersion: 2,
    updatedAt: baselineObservationTime(input),
    datasets: { ...input.baseline.datasets },
  };

  for (const metrics of input.metricsFiles) newBaseline.datasets[metrics.dataset] = metrics;

  const baselineDir = dirname(baselinePath);
  if (!existsSync(baselineDir)) mkdirSync(baselineDir, { recursive: true });

  writeFileSync(baselinePath, `${JSON.stringify(newBaseline, null, 2)}\n`);
  console.log(chalk.green(`Baseline updated: ${baselinePath}`));
}

function baselineObservationTime(input: RegressionInput): string {
  const observations = [...Object.values(input.baseline.datasets), ...input.metricsFiles].map(
    (metrics) => metrics.provenance.observed.generatedAt,
  );
  return observations.sort().at(-1) ?? new Date(0).toISOString();
}

try {
  main();
} catch (error) {
  console.error(chalk.red(error instanceof Error ? error.message : String(error)));
  process.exit(1);
}

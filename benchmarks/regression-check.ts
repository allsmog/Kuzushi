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
import type { BaselineMetrics, BenchmarkMetrics, CweMetrics } from "./types.js";

// ── CLI argument parsing ──

const { values: args } = parseArgs({
  options: {
    baseline: { type: "string", default: "benchmarks/baseline.json" },
    results: { type: "string" },
    "update-baseline": { type: "boolean", default: false },
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
  --precision-threshold <n>      Max precision drop allowed (default: 0.03 = 3%)
  --recall-threshold <n>         Max recall drop allowed (default: 0.03 = 3%)
  --cost-threshold <n>           Max cost increase allowed unless TP count improves (default: 0.25 = 25%)
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

const PRECISION_THRESHOLD = parseFloat(args["precision-threshold"] ?? "0.03");
const RECALL_THRESHOLD = parseFloat(args["recall-threshold"] ?? "0.03");
const COST_THRESHOLD = parseFloat(args["cost-threshold"] ?? "0.25");
const baselinePath = resolve(args.baseline ?? "benchmarks/baseline.json");
const resultPaths = args.results.split(",").map((p) => resolve(p.trim()));

// ── Load files ──

function loadBaseline(filePath: string): BaselineMetrics {
  if (!existsSync(filePath)) {
    console.log(chalk.yellow(`Baseline not found at ${filePath}, starting with empty baseline.`));
    return { updatedAt: new Date().toISOString(), datasets: {} };
  }
  return JSON.parse(readFileSync(filePath, "utf-8")) as BaselineMetrics;
}

function loadMetrics(filePath: string): BenchmarkMetrics {
  if (!existsSync(filePath)) {
    console.error(chalk.red(`Metrics file not found: ${filePath}`));
    process.exit(1);
  }
  return JSON.parse(readFileSync(filePath, "utf-8")) as BenchmarkMetrics;
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
  // No baseline for this dataset — always passes
  if (!baseline) {
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

  // Round deltas to 6 decimal places to avoid IEEE 754 floating-point
  // boundary instability (e.g. 0.750 - 0.800 producing -0.050000000000000044).
  const precisionDelta = roundDelta(current.precision - baseline.precision);
  const recallDelta = roundDelta(current.recall - baseline.recall);
  const f1Delta = roundDelta(current.f1 - baseline.f1);
  const costDeltaRatio =
    baseline.costUsd > 0 ? roundDelta((current.costUsd - baseline.costUsd) / baseline.costUsd) : 0;

  const precisionFail = precisionDelta < -PRECISION_THRESHOLD;
  const recallFail = recallDelta < -RECALL_THRESHOLD;
  const costFail =
    baseline.costUsd > 0 && costDeltaRatio > COST_THRESHOLD && current.tp <= baseline.tp;

  // Per-CWE warnings: flag any CWE where precision or recall dropped by more
  // than double the aggregate thresholds (significant per-CWE regression).
  const cweWarnings: string[] = [];
  const cweThresholdMultiplier = 2;

  for (const [cwe, currentCwe] of Object.entries(current.perCwe)) {
    const baselineCwe: CweMetrics | undefined = baseline.perCwe[cwe];
    if (!baselineCwe) continue;

    const cwePrecDelta = roundDelta(currentCwe.precision - baselineCwe.precision);
    const cweRecDelta = roundDelta(currentCwe.recall - baselineCwe.recall);

    if (cwePrecDelta < -(PRECISION_THRESHOLD * cweThresholdMultiplier)) {
      cweWarnings.push(
        `${cwe}: precision dropped ${formatDelta(cwePrecDelta)} ` +
          `(${formatPct(baselineCwe.precision)} -> ${formatPct(currentCwe.precision)})`,
      );
    }
    if (cweRecDelta < -(RECALL_THRESHOLD * cweThresholdMultiplier)) {
      cweWarnings.push(
        `${cwe}: recall dropped ${formatDelta(cweRecDelta)} ` +
          `(${formatPct(baselineCwe.recall)} -> ${formatPct(currentCwe.recall)})`,
      );
    }
  }

  return {
    dataset: current.dataset,
    passed: !precisionFail && !recallFail && !costFail,
    precisionDelta,
    recallDelta,
    f1Delta,
    costDeltaRatio,
    precisionFail,
    recallFail,
    costFail,
    cweWarnings,
    before: baseline,
    after: current,
  };
}

// ── Numeric helpers ──

function roundDelta(value: number): number {
  return Math.round(value * 1e6) / 1e6;
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
  const rows: string[][] = [];

  for (const r of results) {
    const precBefore = r.before ? formatPct(r.before.precision) : chalk.dim("n/a");
    const precAfter = formatPct(r.after.precision);
    const precDelta = r.before
      ? colorDelta(r.precisionDelta, PRECISION_THRESHOLD)
      : chalk.dim("new");

    const recBefore = r.before ? formatPct(r.before.recall) : chalk.dim("n/a");
    const recAfter = formatPct(r.after.recall);
    const recDelta = r.before ? colorDelta(r.recallDelta, RECALL_THRESHOLD) : chalk.dim("new");
    const costDelta = r.before
      ? colorCostDelta(r.costDeltaRatio, COST_THRESHOLD, r.costFail)
      : chalk.dim("new");

    const f1Delta = r.before ? colorDelta(r.f1Delta, 0) : chalk.dim("new");

    let status: string;
    if (!r.before) {
      status = chalk.blue("NEW");
    } else if (r.passed) {
      status = chalk.green("PASS");
    } else {
      const reasons: string[] = [];
      if (r.precisionFail) reasons.push("precision");
      if (r.recallFail) reasons.push("recall");
      if (r.costFail) reasons.push("cost");
      status = chalk.red(`FAIL (${reasons.join(", ")})`);
    }

    rows.push([
      r.dataset,
      precBefore,
      precAfter,
      precDelta,
      recBefore,
      recAfter,
      recDelta,
      costDelta,
      f1Delta,
      status,
    ]);
  }

  printTable(headers, rows);

  // Print CWE warnings
  for (const r of results) {
    if (r.cweWarnings.length > 0) {
      console.log();
      console.log(chalk.yellow.bold(`Per-CWE warnings for ${r.dataset}:`));
      for (const w of r.cweWarnings) {
        console.log(chalk.yellow(`  ! ${w}`));
      }
    }
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
  console.log(chalk.bold("Kuzushi Regression Check"));
  console.log(`  Baseline: ${baselinePath}`);
  console.log(`  Results: ${resultPaths.join(", ")}`);
  console.log(`  Precision threshold: ${formatPct(PRECISION_THRESHOLD)} drop`);
  console.log(`  Recall threshold: ${formatPct(RECALL_THRESHOLD)} drop`);
  console.log(
    `  Cost threshold: ${(COST_THRESHOLD * 100).toFixed(1)}% increase unless TP count improves`,
  );

  const baseline = loadBaseline(baselinePath);
  const metricsFiles = resultPaths.map(loadMetrics);

  const results: RegressionResult[] = metricsFiles.map((metrics) =>
    compareDataset(baseline.datasets[metrics.dataset] ?? null, metrics),
  );

  printComparisonTable(results);

  const failures = results.filter((r) => !r.passed);
  const totalWarnings = results.reduce((sum, r) => sum + r.cweWarnings.length, 0);

  console.log();
  if (failures.length > 0) {
    console.log(
      chalk.red.bold(
        `REGRESSION DETECTED: ${failures.length} dataset(s) failed the regression gate.`,
      ),
    );
    console.log();

    for (const f of failures) {
      if (f.precisionFail) {
        console.log(
          chalk.red(
            `  ${f.dataset}: precision dropped ${formatDelta(f.precisionDelta)} ` +
              `(threshold: ${formatPct(PRECISION_THRESHOLD)})`,
          ),
        );
      }
      if (f.recallFail) {
        console.log(
          chalk.red(
            `  ${f.dataset}: recall dropped ${formatDelta(f.recallDelta)} ` +
              `(threshold: ${formatPct(RECALL_THRESHOLD)})`,
          ),
        );
      }
      if (f.costFail) {
        console.log(
          chalk.red(
            `  ${f.dataset}: cost increased ${formatCostDelta(f.costDeltaRatio)} ` +
              `without TP improvement (threshold: ${(COST_THRESHOLD * 100).toFixed(1)}%)`,
          ),
        );
      }
    }

    console.log();
    process.exit(1);
  }

  if (totalWarnings > 0) {
    console.log(
      chalk.yellow(
        `${totalWarnings} per-CWE warning(s) detected, but aggregate thresholds passed.`,
      ),
    );
  }

  console.log(chalk.green.bold("All datasets passed the regression gate."));

  // Update baseline if requested
  if (args["update-baseline"]) {
    const newBaseline: BaselineMetrics = {
      updatedAt: new Date().toISOString(),
      datasets: { ...baseline.datasets },
    };

    for (const metrics of metricsFiles) {
      newBaseline.datasets[metrics.dataset] = metrics;
    }

    const baselineDir = dirname(baselinePath);
    if (!existsSync(baselineDir)) {
      mkdirSync(baselineDir, { recursive: true });
    }

    writeFileSync(baselinePath, `${JSON.stringify(newBaseline, null, 2)}\n`);
    console.log(chalk.green(`Baseline updated: ${baselinePath}`));
  }

  console.log();
  process.exit(0);
}

main();

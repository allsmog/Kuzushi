#!/usr/bin/env tsx

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import type { BaselineMetrics, BenchmarkMetrics } from "./types.js";

const DEFAULT_DATASETS = ["govwa", "juice-shop"] as const;

const { values: args } = parseArgs({
  options: {
    datasets: { type: "string" },
    output: { type: "string", default: "benchmarks/baseline.json" },
    "results-dir": { type: "string", default: "benchmarks/results" },
  },
  strict: true,
});

const datasets = (args.datasets ?? DEFAULT_DATASETS.join(","))
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);
const outputPath = resolve(args.output ?? "benchmarks/baseline.json");
const resultsDir = resolve(args["results-dir"] ?? "benchmarks/results");

if (!existsSync(resultsDir)) {
  mkdirSync(resultsDir, { recursive: true });
}

const metricsByDataset: Record<string, BenchmarkMetrics> = {};

for (const dataset of datasets) {
  const datasetDir = resolve("benchmarks", dataset);
  const repoDir = join(datasetDir, "repo");
  if (!existsSync(repoDir)) {
    throw new Error(
      `Dataset repo missing for ${dataset}: ${repoDir}. Run ${datasetDir}/setup.sh first.`,
    );
  }

  const sarifPath = join(resultsDir, `${dataset}.sarif`);
  const metricsPath = join(resultsDir, `${dataset}.json`);

  execFileSync(
    "npx",
    [
      "tsx",
      "src/cli.ts",
      "scan",
      repoDir,
      "--sarif",
      sarifPath,
      "--fresh",
      "--scanners",
      "semgrep,agentic",
    ],
    {
      stdio: "inherit",
      encoding: "utf-8",
      env: process.env,
    },
  );

  execFileSync(
    "npx",
    [
      "tsx",
      "benchmarks/harness.ts",
      "--dataset",
      datasetDir,
      "--sarif",
      sarifPath,
      "--output",
      metricsPath,
    ],
    {
      stdio: "inherit",
      encoding: "utf-8",
      env: process.env,
    },
  );

  const metrics = JSON.parse(readFileSync(metricsPath, "utf-8")) as BenchmarkMetrics;
  metricsByDataset[metrics.dataset] = metrics;
}

const baseline: BaselineMetrics = {
  updatedAt: new Date().toISOString(),
  datasets: metricsByDataset,
};

const outputDir = dirname(outputPath);
if (!existsSync(outputDir)) {
  mkdirSync(outputDir, { recursive: true });
}

writeFileSync(outputPath, `${JSON.stringify(baseline, null, 2)}\n`);

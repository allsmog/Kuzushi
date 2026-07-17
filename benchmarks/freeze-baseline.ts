#!/usr/bin/env tsx

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { loadProvenanceInput } from "./benchmark-provenance.js";
import { canonicalScanConfig } from "./benchmark-scan-config.js";
import type { BaselineMetrics, BenchmarkMetrics } from "./types.js";

const DEFAULT_DATASETS = ["govwa", "juice-shop"] as const;

const { values: args } = parseArgs({
  options: {
    datasets: { type: "string" },
    output: { type: "string", default: "benchmarks/baseline.json" },
    "results-dir": { type: "string", default: "benchmarks/results" },
    provenance: { type: "string", default: "benchmarks/baseline-provenance.json" },
  },
  strict: true,
});

const datasets = (args.datasets ?? DEFAULT_DATASETS.join(","))
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);
const outputPath = resolve(args.output ?? "benchmarks/baseline.json");
const resultsDir = resolve(args["results-dir"] ?? "benchmarks/results");
const provenancePath = resolve(args.provenance ?? "benchmarks/baseline-provenance.json");
if (!existsSync(provenancePath)) throw new Error(`Provenance input missing: ${provenancePath}`);
const provenance = loadProvenanceInput(provenancePath);
const scanConfig = canonicalScanConfig(provenance.scanConfig);

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

  const metricsPath = join(resultsDir, `${dataset}.json`);

  execFileSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "benchmarks/harness.ts",
      "--dataset",
      datasetDir,
      "--run",
      "--config",
      scanConfig,
      "--output",
      metricsPath,
      "--provenance",
      provenancePath,
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
  schemaVersion: 2,
  updatedAt: Object.values(metricsByDataset)
    .map((metrics) => metrics.provenance.observed.generatedAt)
    .sort()
    .at(-1)!,
  datasets: metricsByDataset,
};

const outputDir = dirname(outputPath);
if (!existsSync(outputDir)) {
  mkdirSync(outputDir, { recursive: true });
}

writeFileSync(outputPath, `${JSON.stringify(baseline, null, 2)}\n`);

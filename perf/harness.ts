#!/usr/bin/env tsx
/**
 * Micro-benchmark harness for Kuzushi performance work.
 *
 * NOT to be confused with `benchmarks/` (scan-accuracy F1/precision on real
 * vulnerability corpora). This harness only measures CPU, allocation, and
 * SQLite throughput of hot-path code.
 *
 * Usage:
 *   pnpm perf              # run all benches, median of 5, print table
 *   pnpm perf --json       # also write perf/results.json
 *   pnpm perf --cases registry
 */

import { writeFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { parseArgs } from "node:util";

import { benchRegistry } from "./bench-registry.js";

export interface BenchCase {
  name: string;
  /** Called once per iteration. Should produce work proportional to the N in the name. */
  run: () => void | Promise<void>;
  /** Optional setup run once before timing (fixtures etc). */
  setup?: () => void | Promise<void>;
  /** Optional teardown after all iterations. */
  teardown?: () => void | Promise<void>;
  /** Iteration count; defaults to 5. */
  iterations?: number;
}

export interface BenchResult {
  name: string;
  medianMs: number;
  minMs: number;
  maxMs: number;
  meanMs: number;
  rssDeltaMb: number;
  heapDeltaMb: number;
  iterations: number;
}

const MB = 1024 * 1024;

function median(nums: number[]): number {
  const sorted = [...nums].sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

export async function runBench(bench: BenchCase): Promise<BenchResult> {
  const iters = bench.iterations ?? 5;
  await runOptionalHook(bench.setup);

  // Warm-up — let V8 compile and JIT the hot path before measuring.
  await bench.run();

  const before = memorySnapshot();
  const samples = await measureSamples(bench, iters);
  const after = memorySnapshot();
  await runOptionalHook(bench.teardown);

  return {
    name: bench.name,
    medianMs: median(samples),
    minMs: Math.min(...samples),
    maxMs: Math.max(...samples),
    meanMs: samples.reduce((a, b) => a + b, 0) / samples.length,
    rssDeltaMb: (after.rss - before.rss) / MB,
    heapDeltaMb: (after.heap - before.heap) / MB,
    iterations: iters,
  };
}

async function runOptionalHook(hook: BenchCase["setup"]): Promise<void> {
  if (hook) await hook();
}

async function measureSamples(bench: BenchCase, iters: number): Promise<number[]> {
  const samples: number[] = [];
  for (let i = 0; i < iters; i++) {
    global.gc?.();
    const start = performance.now();
    await bench.run();
    samples.push(performance.now() - start);
  }
  return samples;
}

function memorySnapshot(): { heap: number; rss: number } {
  const usage = process.memoryUsage();
  return { heap: usage.heapUsed, rss: usage.rss };
}

function printTable(results: BenchResult[]): void {
  const cols = [
    { header: "benchmark", get: (r: BenchResult) => r.name },
    { header: "median ms", get: (r: BenchResult) => r.medianMs.toFixed(2) },
    { header: "min ms", get: (r: BenchResult) => r.minMs.toFixed(2) },
    { header: "max ms", get: (r: BenchResult) => r.maxMs.toFixed(2) },
    { header: "mean ms", get: (r: BenchResult) => r.meanMs.toFixed(2) },
    { header: "Δheap MB", get: (r: BenchResult) => r.heapDeltaMb.toFixed(2) },
    { header: "Δrss MB", get: (r: BenchResult) => r.rssDeltaMb.toFixed(2) },
    { header: "iters", get: (r: BenchResult) => String(r.iterations) },
  ];

  const widths = cols.map((c) => Math.max(c.header.length, ...results.map((r) => c.get(r).length)));

  const sep = widths.map((w) => "-".repeat(w + 2)).join("+");
  const fmt = (cells: string[]) => cells.map((cell, i) => ` ${cell.padEnd(widths[i])} `).join("|");

  console.log(sep);
  console.log(fmt(cols.map((c) => c.header)));
  console.log(sep);
  for (const r of results) {
    console.log(fmt(cols.map((c) => c.get(r))));
  }
  console.log(sep);
}

async function main(): Promise<void> {
  const values = parseCliArgs();
  if (values.help) return printHelp();

  const benches = selectedBenches(values.cases);
  console.log(`node ${process.version} | cpus=${process.platform}`);
  console.log(`running ${benches.length} bench(es)...`);
  console.log();

  const results = await runBenches(benches);
  printTable(results);
  writeJsonResults(Boolean(values.json), results);
}

function parseCliArgs(): { json?: boolean; cases?: string; help?: boolean } {
  return parseArgs({
    options: {
      json: { type: "boolean", default: false },
      cases: { type: "string" },
      help: { type: "boolean", short: "h", default: false },
    },
    strict: true,
  }).values;
}

function printHelp(): void {
  console.log(`Usage: pnpm perf [--json] [--cases <csv>]
Available cases: registry`);
}

function selectedBenches(cases?: string): BenchCase[] {
  const enabled = new Set(
    (cases ?? "registry")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  );

  const benches: BenchCase[] = [];
  if (enabled.has("registry")) benches.push(...benchRegistry());
  return benches;
}

async function runBenches(benches: BenchCase[]): Promise<BenchResult[]> {
  const results: BenchResult[] = [];
  for (const b of benches) {
    const r = await runBench(b);
    results.push(r);
  }
  return results;
}

function writeJsonResults(enabled: boolean, results: BenchResult[]): void {
  if (!enabled) return;
  writeFileSync(
    new URL("./results.json", import.meta.url),
    JSON.stringify({ node: process.version, at: new Date().toISOString(), results }, null, 2),
  );
  console.log("\nresults written to perf/results.json");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

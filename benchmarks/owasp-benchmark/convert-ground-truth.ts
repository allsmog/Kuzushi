#!/usr/bin/env tsx

/**
 * Convert OWASP BenchmarkJava's `expectedresults-*.csv` to our `ground-truth.json` format.
 *
 * Usage:
 *   tsx benchmarks/owasp-benchmark/convert-ground-truth.ts
 *
 * Expects the BenchmarkJava repo to be cloned at benchmarks/owasp-benchmark/repo/
 * (run setup.sh first).
 */

import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { GroundTruthDataset, GroundTruthEntry } from "../types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const REPO_DIR = join(__dirname, "repo");

// ── Category mapping ──

const CATEGORY_NAMES: Record<string, string> = {
  pathtravel: "Path Traversal",
  cmdi: "Command Injection",
  xss: "XSS",
  sqli: "SQL Injection",
  ldapi: "LDAP Injection",
  securecookie: "Insecure Cookie",
  hash: "Weak Hash",
  crypto: "Weak Crypto",
  trustbound: "Trust Boundary",
  xpathi: "XPath Injection",
  weakrand: "Weak Random",
};

// ── Find the expectedresults CSV ──

function findExpectedResultsCsv(): string {
  const files = readdirSync(REPO_DIR);
  const match = files.find((f) => f.startsWith("expectedresults-") && f.endsWith(".csv"));
  if (!match) {
    console.error("Could not find expectedresults-*.csv in", REPO_DIR);
    process.exit(1);
  }
  return join(REPO_DIR, match);
}

// ── Parse CSV ──

function parseCsv(csvPath: string): GroundTruthEntry[] {
  const raw = readFileSync(csvPath, "utf-8");
  const lines = raw.split("\n");
  const entries: GroundTruthEntry[] = [];

  for (const line of lines) {
    const trimmed = line.trim();
    // Skip empty lines and the header (starts with #)
    if (!trimmed || trimmed.startsWith("#")) continue;

    const parts = trimmed.split(",");
    if (parts.length < 4) continue;

    const testName = parts[0].trim();
    const category = parts[1].trim();
    const realVuln = parts[2].trim().toLowerCase() === "true";
    const cweNum = parts[3].trim();

    const paddedCwe = cweNum.padStart(3, "0");
    const filePath = `src/main/java/org/owasp/benchmark/testcode/${testName}.java`;

    entries.push({
      id: testName,
      file: filePath,
      line: 1,
      cwe: `CWE-${paddedCwe}`,
      isVulnerable: realVuln,
      category: CATEGORY_NAMES[category] ?? category,
    });
  }

  return entries;
}

// ── Main ──

const csvPath = findExpectedResultsCsv();
console.log(`Reading: ${csvPath}`);

const entries = parseCsv(csvPath);
console.log(`Parsed ${entries.length} test cases`);
console.log(`  Vulnerable: ${entries.filter((e) => e.isVulnerable).length}`);
console.log(`  Non-vulnerable: ${entries.filter((e) => !e.isVulnerable).length}`);

const dataset: GroundTruthDataset = {
  name: "OWASP BenchmarkJava",
  language: "java",
  repoUrl: "https://github.com/OWASP-Benchmark/BenchmarkJava",
  repoRef: execFileSync("git", ["-C", REPO_DIR, "rev-parse", "HEAD"], {
    encoding: "utf8",
  }).trim(),
  entries,
};

const outputPath = join(__dirname, "ground-truth.json");
writeFileSync(outputPath, `${JSON.stringify(dataset, null, 2)}\n`);
console.log(`Written: ${outputPath}`);

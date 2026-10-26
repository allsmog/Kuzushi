#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";

const DEFAULT_THRESHOLD = 80;
const MAX_GIT_OUTPUT_BYTES = 64 * 1024 * 1024;
// These sources compile only under a feature set that is checked separately
// from the default workspace build used to generate the LCOV report.
const ALTERNATE_FEATURE_SOURCES = new Set(["crates/kuzushi-cpg/src/disabled.rs"]);

export function parseLcov(text, root = process.cwd()) {
  const files = new Map();
  let current;
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith("SF:")) {
      current = normalizedSourcePath(line.slice(3), root);
      files.set(current, new Map());
    } else if (current && line.startsWith("DA:")) {
      const [lineNumber, count] = line.slice(3).split(",").map(Number);
      if (Number.isSafeInteger(lineNumber) && Number.isFinite(count)) {
        files.get(current).set(lineNumber, count);
      }
    } else if (line === "end_of_record") {
      current = undefined;
    }
  }
  return files;
}

export function parseChangedRustLines(diff) {
  const changed = new Map();
  let current;
  for (const line of diff.split(/\r?\n/)) {
    if (line.startsWith("+++ ")) {
      current = changedFilePath(line);
      if (current && isProductionRust(current)) changed.set(current, new Set());
    } else if (current && changed.has(current) && line.startsWith("@@ ")) {
      addHunkLines(changed.get(current), line);
    }
  }
  return changed;
}

export function evaluateDiffCoverage(coverage, changed, threshold = DEFAULT_THRESHOLD) {
  let measured = 0;
  let covered = 0;
  const uncovered = [];
  for (const [file, changedLines] of changed) {
    const result = evaluateFileCoverage(file, coverage.get(file), changedLines);
    measured += result.measured;
    covered += result.covered;
    uncovered.push(...result.uncovered);
  }
  const percent = measured === 0 ? 100 : (covered / measured) * 100;
  return { covered, measured, percent, threshold, uncovered };
}

export function omitUninstrumentedDeclarationSources(coverage, changed, sourceForFile) {
  return new Map(
    [...changed].filter(([file]) => {
      if (coverage.has(file)) return true;
      if (hasSeparateCoverageConfiguration(file)) return false;
      return hasExecutableFunction(sourceForFile(file));
    }),
  );
}

function hasSeparateCoverageConfiguration(file) {
  if (ALTERNATE_FEATURE_SOURCES.has(file)) return true;
  return /\/(?:windows|linux|macos)(?:\/|\.rs$)/.test(file);
}

function hasExecutableFunction(source) {
  return /\bfn\s+(?:r#)?[A-Za-z_][A-Za-z0-9_]*/.test(source);
}

function evaluateFileCoverage(file, coverage, changedLines) {
  if (!coverage && changedLines.size > 0) {
    throw new Error(`missing coverage instrumentation for changed source: ${file}`);
  }
  if (!coverage) return { covered: 0, measured: 0, uncovered: [] };
  const executable = [...changedLines].filter((line) => coverage.has(line));
  const uncovered = executable
    .filter((line) => coverage.get(line) === 0)
    .map((line) => `${file}:${line}`);
  return {
    covered: executable.length - uncovered.length,
    measured: executable.length,
    uncovered,
  };
}

function normalizedSourcePath(file, root) {
  const normalized = file.replaceAll("\\", "/");
  const relative = path.isAbsolute(normalized) ? path.relative(root, normalized) : normalized;
  return relative.replaceAll("\\", "/").replace(/^\.\//, "");
}

function changedFilePath(line) {
  const value = decodeGitPath(line.slice(4));
  if (value === "/dev/null") return undefined;
  return value.replace(/^b\//, "");
}

function decodeGitPath(value) {
  if (!value.startsWith('"')) return value;
  if (!value.endsWith('"')) throw new Error("unterminated quoted Git path");
  return Buffer.concat(
    [...value.slice(1, -1).matchAll(/\\([0-7]{1,3}|[abfnrtv"\\])|([^\\]+)|(\\.)/g)].map(
      gitPathChunk,
    ),
  ).toString("utf8");
}

function gitPathChunk(match) {
  const escapes = { a: 7, b: 8, f: 12, n: 10, r: 13, t: 9, v: 11, '"': 34, "\\": 92 };
  if (match[3]) throw new Error(`invalid Git path escape: ${match[3]}`);
  if (match[2]) return Buffer.from(match[2], "utf8");
  return Buffer.from([escapes[match[1]] ?? Number.parseInt(match[1], 8)]);
}

function addHunkLines(lines, header) {
  const match = header.match(/\+(\d+)(?:,(\d+))?/);
  if (!match) return;
  const start = Number(match[1]);
  const count = Number(match[2] ?? "1");
  for (let line = start; line < start + count; line += 1) lines.add(line);
}

function isProductionRust(file) {
  return (
    file.startsWith("crates/") &&
    file.includes("/src/") &&
    file.endsWith(".rs") &&
    !file.endsWith("/tests.rs") &&
    !file.endsWith("_tests.rs") &&
    !file.includes("/tests/") &&
    !file.startsWith("crates/kuzushi-bdd-tui/")
  );
}

function resolveBase(root) {
  const requested = process.env.KUZUSHI_QUALITY_BASE_REF;
  if (requested) return requireCommit(root, requested);
  if (commitExists(root, "origin/main") && !isSameCommit(root, "origin/main", "HEAD")) {
    return git(root, ["merge-base", "origin/main", "HEAD"]).trim();
  }
  return requireCommit(root, "HEAD^");
}

function requireCommit(root, reference) {
  if (commitExists(root, reference)) return reference;
  throw new Error(`diff coverage cannot resolve base commit ${reference}`);
}

function commitExists(root, reference) {
  try {
    execFileSync("git", ["rev-parse", "--verify", "--quiet", `${reference}^{commit}`], {
      cwd: root,
      stdio: "ignore",
    });
    return true;
  } catch {
    return false;
  }
}

function isSameCommit(root, left, right) {
  return git(root, ["rev-parse", left]).trim() === git(root, ["rev-parse", right]).trim();
}

function git(root, args) {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    maxBuffer: MAX_GIT_OUTPUT_BYTES,
  });
}

function thresholdFromEnvironment() {
  const threshold = Number(process.env.KUZUSHI_DIFF_COVERAGE_THRESHOLD ?? DEFAULT_THRESHOLD);
  if (!Number.isFinite(threshold) || threshold < 0 || threshold > 100) {
    throw new Error("KUZUSHI_DIFF_COVERAGE_THRESHOLD must be between 0 and 100");
  }
  return threshold;
}

function readCoverageReport(root, reportPath) {
  const coverage = parseLcov(readFileSync(path.resolve(root, reportPath), "utf8"), root);
  if (coverage.size === 0) throw new Error(`coverage report ${reportPath} contains no files`);
  return coverage;
}

function main() {
  const root = git(process.cwd(), ["rev-parse", "--show-toplevel"]).trim();
  const reportPath = process.argv[2] ?? "target/llvm-cov/lcov.info";
  const base = resolveBase(root);
  const diff = git(root, ["diff", "--unified=0", "--no-color", base, "--", "crates"]);
  const coverage = readCoverageReport(root, reportPath);
  const result = evaluateDiffCoverage(
    coverage,
    omitUninstrumentedDeclarationSources(coverage, parseChangedRustLines(diff), (file) =>
      readFileSync(path.resolve(root, file), "utf8"),
    ),
    thresholdFromEnvironment(),
  );
  process.stdout.write(
    `Changed executable Rust lines: ${result.covered}/${result.measured} covered (${result.percent.toFixed(2)}%, required ${result.threshold}%).\n`,
  );
  if (result.percent < result.threshold) {
    for (const location of result.uncovered.slice(0, 50)) process.stderr.write(`- ${location}\n`);
    if (result.uncovered.length > 50) {
      process.stderr.write(`- ... ${result.uncovered.length - 50} more uncovered lines\n`);
    }
    process.exitCode = 1;
  }
}

if (process.argv[1]?.endsWith("check-diff-coverage.mjs")) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`diff coverage failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

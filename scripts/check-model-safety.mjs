#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const root = repoRoot();
const MODEL_LITERAL =
  "(?:(?:anthropic|openai|openai-codex):[^\"'`]+|(?:gpt|claude)-[A-Za-z0-9._:-]+)";
const FORBIDDEN_MODEL_DEFAULTS = [
  [
    "hardcoded model fallback expression",
    new RegExp(String.raw`(?:\?\?|unwrap_or(?:_else)?|or_else)\s*\([^)]*["']${MODEL_LITERAL}["']`),
  ],
  [
    "hardcoded model field literal",
    new RegExp(String.raw`\bmodel\s*[:=]\s*["']${MODEL_LITERAL}["']`),
  ],
];
const failures = modelFallbackFailures();

if (failures.length > 0) {
  console.error("Kuzushi model safety check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("Model safety check passed.");

function modelFallbackFailures() {
  return trackedFiles()
    .filter(isProductionSource)
    .flatMap((file) => scanFile(file));
}

function scanFile(file) {
  return readFileSync(path.join(root, file), "utf8")
    .split(/\r?\n/)
    .flatMap((line, index) => lineFailures(file, line, index + 1));
}

function lineFailures(file, line, lineNumber) {
  return FORBIDDEN_MODEL_DEFAULTS.filter(([, pattern]) => pattern.test(line)).map(
    ([label]) => `${file}:${lineNumber} ${label}`,
  );
}

function trackedFiles() {
  return [
    ...new Set([
      ...gitLines(["ls-files"]),
      ...gitLines(["ls-files", "--others", "--exclude-standard"]),
    ]),
  ]
    .filter((file) => existsSync(path.join(root, file)))
    .sort();
}

function isProductionSource(file) {
  return (
    /\.(rs|ts|js|mjs)$/.test(file) &&
    !isIgnored(file) &&
    !isTestFile(file) &&
    !file.startsWith("src/testing/")
  );
}

function isIgnored(file) {
  return (
    file.startsWith("target/") ||
    file.startsWith("dist/") ||
    file.startsWith("coverage/") ||
    file.startsWith("node_modules/") ||
    file === "scripts/check-model-safety.mjs"
  );
}

function isTestFile(file) {
  return (
    file.includes("/tests/") ||
    file.endsWith("/tests.rs") ||
    file.endsWith("_tests.rs") ||
    file.includes(".test.") ||
    file.includes("_test.")
  );
}

function repoRoot() {
  try {
    return execFileSync("git", ["rev-parse", "--show-toplevel"], {
      encoding: "utf8",
    }).trim();
  } catch {
    return process.cwd();
  }
}

function gitLines(args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8" })
    .split(/\r?\n/)
    .map((file) => file.trim())
    .filter(Boolean);
}

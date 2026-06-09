#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();

const allowedFiles = new Set([
  "scripts/check-ddd-boundaries.mjs",
  "scripts/check-validated-wording.mjs",
]);

const allowedPrefixes = [
  "crates/kuzushi-core/src/proof/",
  "crates/kuzushi-core/src/verification/",
  "crates/kuzushi-core/src/remediation/patch/",
  "crates/kuzushi-core/src/capabilities/threat_intel/",
  "crates/kuzushi-eval/src/",
  "crates/kuzushi-core/src/modules/options/",
  "src/modules/",
  "src/testing/",
];

const failures = trackedFiles()
  .filter(scannableFile)
  .flatMap((file) => validatedWordFailures(file));

if (failures.length > 0) {
  console.error("Kuzushi validated-wording check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("validated wording check passed");

function validatedWordFailures(file) {
  if (isAllowed(file)) return [];
  return readFileSync(path.join(root, file), "utf8")
    .split(/\r?\n/)
    .flatMap((line, index) =>
      /\bvalidated\b/i.test(line) && !isAllowedValidatedLine(line)
        ? [
            `${file}:${index + 1} uses "validated" outside proof/verification/input-validation contexts`,
          ]
        : [],
    );
}

function isAllowed(file) {
  return allowedFiles.has(file) || allowedPrefixes.some((prefix) => file.startsWith(prefix));
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

function scannableFile(file) {
  return (
    /\.(rs|ts|tsx|js|mjs|md)$/.test(file) &&
    isProductionOrPublicPolicySurface(file) &&
    !isTestFile(file) &&
    !file.startsWith("target/") &&
    !file.startsWith("dist/") &&
    !file.startsWith("coverage/") &&
    !file.startsWith("node_modules/")
  );
}

function isProductionOrPublicPolicySurface(file) {
  return (
    file.startsWith("src/") ||
    (file.startsWith("crates/") && file.includes("/src/")) ||
    file === "README.md" ||
    file === "PORT_PLAN.md" ||
    file.startsWith("docs/") ||
    file.startsWith("scripts/")
  );
}

function isAllowedValidatedLine(line) {
  return isInputValidationContext(line) || isValidatedPolicyContext(line);
}

function isInputValidationContext(line) {
  const normalized = line.toLowerCase();
  return [
    "validated against",
    "validated at runtime",
    "validated/sanitized",
    "validated input",
    "configschema",
    "input validation",
  ].some((allowed) => normalized.includes(allowed));
}

function isValidatedPolicyContext(line) {
  const normalized = line.toLowerCase();
  return [
    "validated-wording check",
    "`validated` claims",
    '"validated" unless',
    'using "validated" wording',
    "check-validated-wording.mjs",
  ].some((allowed) => normalized.includes(allowed));
}

function isTestFile(file) {
  return file.includes("/tests/") || file.endsWith("/tests.rs") || file.endsWith("_tests.rs");
}

function gitLines(args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8" })
    .split(/\r?\n/)
    .map((file) => file.trim())
    .filter(Boolean);
}

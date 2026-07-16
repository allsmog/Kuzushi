#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";

const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();

const requiredContexts = [
  "context",
  "attack_surface",
  "threat_model",
  "modules",
  "recommender",
  "scanners",
  "findings",
  "proof",
  "triage",
  "verify",
  "patch",
  "report",
  "run_trace",
  "run_lifecycle",
  "failure",
  "ui_*",
];

const checks = [
  {
    file: "docs/architecture/kuzushi-boundaries.md",
    markerFor: (context) => `| \`${context}\``,
  },
  {
    file: "docs/PORT_PLAN.md",
    markerFor: (context) => `- \`${context}\``,
  },
];

const failures = checks.flatMap(missingContextMarkers);

if (failures.length > 0) {
  console.error("Kuzushi DDD context documentation check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`DDD context documentation check passed for ${requiredContexts.length} contexts.`);

function missingContextMarkers({ file, markerFor }) {
  const source = readFileSync(path.join(root, file), "utf8");
  return requiredContexts
    .filter((context) => !source.includes(markerFor(context)))
    .map((context) => `${file} does not list required DDD context ${context}`);
}

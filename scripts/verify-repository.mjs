#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";

const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const cargo = process.platform === "win32" ? "cargo.exe" : "cargo";

const quickPlan = Object.freeze([
  step("secrets", pnpm, ["quality:secrets"]),
  step("tests", pnpm, ["test"]),
  step("format", cargo, ["fmt", "--all", "--", "--check"]),
  step("cargo-check", cargo, ["check", "--workspace", "--all-targets", "--locked"]),
  step("architecture", pnpm, ["quality:architecture"]),
  step("model-safety", pnpm, ["quality:model-safety"]),
  step("docs", pnpm, ["check:docs"]),
  step("crap-risk", pnpm, ["quality:crap-risk"]),
  step("biome", pnpm, ["check"]),
]);

const ciPlan = Object.freeze([
  ...quickPlan,
  step("coverage", pnpm, ["test:coverage"]),
  step("clippy", cargo, [
    "clippy",
    "--workspace",
    "--all-targets",
    "--locked",
    "--",
    "-D",
    "warnings",
  ]),
  step("cargo-deny", cargo, ["deny", "check", "advisories", "licenses", "bans", "sources"]),
  step("rust-tests", cargo, ["test", "--workspace", "--locked"]),
  step("performance", pnpm, ["test:performance"]),
  step("mutations", pnpm, ["test:mutations"]),
  step("rust-build", cargo, ["build", "--workspace", "--locked"]),
  step("build-native", pnpm, ["build:native"]),
  step("pack-contract", pnpm, ["verify:pack"]),
  step("e2e", pnpm, ["test:e2e"]),
]);

const ciMatrixExceptions = Object.freeze([
  "Node 22 minimum-version compatibility runs in CI's dedicated Node 22 job.",
  "Linux bubblewrap/AppArmor setup and artifact upload/download run only on GitHub-hosted CI.",
]);

export function verificationPlan(mode) {
  if (mode === "quick") return quickPlan;
  if (mode === "ci") return ciPlan;
  throw new Error("verification mode must be quick or ci");
}

export function validatePnpmPlanScripts(plan, packageScripts) {
  const missing = plan
    .filter(isPnpmStep)
    .map(({ args }) => args[0])
    .filter((script) => !Object.hasOwn(packageScripts, script));
  if (missing.length > 0) {
    throw new Error(
      `verification plan references unknown package scripts: ${[...new Set(missing)].join(", ")}`,
    );
  }
}

function step(name, command, args) {
  return Object.freeze({ name, command, args: Object.freeze(args) });
}

function isPnpmStep(item) {
  return path.basename(item.command).replace(/\.cmd$/, "") === "pnpm";
}

function packageScripts() {
  const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  return packageJson.scripts ?? {};
}

function validatePlans() {
  const scripts = packageScripts();
  validatePnpmPlanScripts(quickPlan, scripts);
  validatePnpmPlanScripts(ciPlan, scripts);
}

export function parseArguments(args) {
  let mode;
  let summary = false;
  for (const arg of args) {
    if (arg === "--summary") {
      summary = true;
    } else if (arg.startsWith("-")) {
      throw new Error(`unknown verification option: ${arg}`);
    } else if (mode) {
      throw new Error(`unexpected verification argument: ${arg}`);
    } else {
      mode = arg;
    }
  }
  return { mode: mode ?? "quick", summary };
}

function runStep(item, summary) {
  process.stderr.write(`verify: ${item.name} (${[item.command, ...item.args].join(" ")})\n`);
  const started = Date.now();
  const result = spawnSync(item.command, item.args, {
    cwd: process.cwd(),
    stdio: summary ? ["inherit", "ignore", "ignore"] : ["inherit", 2, 2],
  });
  return {
    name: item.name,
    command: [item.command, ...item.args],
    durationMs: Date.now() - started,
    status: result.status,
    signal: result.signal,
    error: result.error?.message,
  };
}

function main() {
  const { mode, summary } = parseArguments(process.argv.slice(2));
  validatePlans();
  const plan = verificationPlan(mode);
  const receipt = {
    mode,
    startedAt: new Date().toISOString(),
    matrixExceptions: mode === "ci" ? ciMatrixExceptions : [],
    steps: [],
  };
  let exitCode = 0;
  for (const item of plan) {
    const result = runStep(item, summary);
    receipt.steps.push(result);
    if (result.status !== 0 || result.signal) {
      exitCode = result.status ?? 1;
      break;
    }
  }
  receipt.ok = exitCode === 0;
  receipt.finishedAt = new Date().toISOString();
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
  process.exitCode = exitCode;
}

if (process.argv[1]?.endsWith("verify-repository.mjs")) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`repository verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

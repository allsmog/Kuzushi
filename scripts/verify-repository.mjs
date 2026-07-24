#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import process from "node:process";

const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const cargo = process.platform === "win32" ? "cargo.exe" : "cargo";

const quickPlan = Object.freeze([
  step("types", pnpm, ["check:types"]),
  step("tests", pnpm, ["test"]),
  step("format", cargo, ["fmt", "--all", "--", "--check"]),
  step("architecture", pnpm, ["quality:architecture"]),
  step("model-safety", pnpm, ["quality:model-safety"]),
  step("docs", pnpm, ["check:docs"]),
  step("crap-risk", pnpm, ["quality:crap-risk"]),
  step("biome", pnpm, ["check"]),
]);

const ciPlan = Object.freeze([
  step("types", pnpm, ["check:types"]),
  step("coverage", pnpm, ["test:coverage"]),
  step("format", cargo, ["fmt", "--all", "--", "--check"]),
  step("architecture", pnpm, ["quality:architecture"]),
  step("model-safety", pnpm, ["quality:model-safety"]),
  step("docs", pnpm, ["check:docs"]),
  step("crap-risk", pnpm, ["quality:crap-risk"]),
  step("biome", pnpm, ["check"]),
  step("codegen", pnpm, ["codegen:check"]),
  step("clippy", cargo, ["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"]),
  step("cargo-deny", cargo, ["deny", "check", "advisories", "licenses", "bans", "sources"]),
  step("rust-tests", cargo, ["test", "--workspace"]),
  step("rust-build", cargo, ["build", "--workspace"]),
  step("build-typescript", pnpm, ["build:clean"]),
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

function step(name, command, args) {
  return Object.freeze({ name, command, args: Object.freeze(args) });
}

function runStep(item) {
  const started = Date.now();
  const result = spawnSync(item.command, item.args, {
    cwd: process.cwd(),
    stdio: ["inherit", 2, 2],
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
  const mode = process.argv[2] ?? "quick";
  const plan = verificationPlan(mode);
  const receipt = {
    mode,
    startedAt: new Date().toISOString(),
    matrixExceptions: mode === "ci" ? ciMatrixExceptions : [],
    steps: [],
  };
  let exitCode = 0;
  for (const item of plan) {
    const result = runStep(item);
    receipt.steps.push(result);
    if (result.status !== 0 || result.signal) {
      exitCode = result.status ?? 1;
      break;
    }
  }
  receipt.ok = exitCode === 0;
  receipt.finishedAt = new Date().toISOString();
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
  if (exitCode !== 0) process.exit(exitCode);
}

if (process.argv[1]?.endsWith("verify-repository.mjs")) main();

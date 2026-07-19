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
  ...quickPlan,
  step("rust-tests", cargo, ["test", "--workspace"]),
  step("build-typescript", pnpm, ["build:clean"]),
  step("build-native", pnpm, ["build:native"]),
  step("pack-contract", pnpm, ["verify:pack"]),
  step("e2e", pnpm, ["test:e2e"]),
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
  const result = spawnSync(item.command, item.args, { cwd: process.cwd(), stdio: "inherit" });
  return {
    name: item.name,
    command: [item.command, ...item.args],
    durationMs: Date.now() - started,
    status: result.status ?? 1,
    error: result.error?.message,
  };
}

function main() {
  const mode = process.argv[2] ?? "quick";
  const plan = verificationPlan(mode);
  const receipt = { mode, startedAt: new Date().toISOString(), steps: [] };
  for (const item of plan) {
    const result = runStep(item);
    receipt.steps.push(result);
    if (result.status !== 0) {
      receipt.ok = false;
      process.stderr.write(`${JSON.stringify(receipt, null, 2)}\n`);
      process.exit(result.status);
    }
  }
  receipt.ok = true;
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

if (process.argv[1]?.endsWith("verify-repository.mjs")) main();

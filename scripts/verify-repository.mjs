#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";

const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const cargo = process.platform === "win32" ? "cargo.exe" : "cargo";

const quickPlan = Object.freeze([
  step("private-context", pnpm, ["quality:private-context"]),
  step("secrets", pnpm, ["quality:secrets"]),
  step("tests", pnpm, ["test"]),
  step("format", cargo, ["fmt", "--all", "--", "--check"]),
  step("cargo-check", cargo, ["check", "--workspace", "--all-targets", "--locked"]),
  step("tui-tests", cargo, ["test", "-p", "kuzushi-tui", "--lib", "--locked"]),
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

// What no local run on one machine can attest, whatever mode it used. The
// receipt carries these so a reader never mistakes a local pass for full
// matrix coverage.
const hostMatrixExceptions = Object.freeze([
  "Node 22 minimum-version compatibility runs in CI's dedicated Node 22 job.",
  "Linux bubblewrap/AppArmor setup and artifact upload/download run only on GitHub-hosted CI.",
  "Cross-platform compilation (Windows, Linux, the native release matrix) is not exercised by a single-host run.",
]);

export function verificationExceptions(mode) {
  const covered = new Set(verificationPlan(mode).map(({ name }) => name));
  const omitted = ciPlan.map(({ name }) => name).filter((name) => !covered.has(name));
  if (omitted.length === 0) return [...hostMatrixExceptions];
  return [...hostMatrixExceptions, `Mode ${mode} did not run: ${omitted.join(", ")}.`];
}

export function planDigest(plan) {
  const pairs = plan.map(({ name, command, args }) => [name, [command, ...args].join(" ")]);
  return createHash("sha256").update(JSON.stringify(pairs)).digest("hex");
}

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
  let receipt = null;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--summary") {
      summary = true;
    } else if (arg === "--receipt") {
      index += 1;
      receipt = args[index];
      if (!receipt) throw new Error("--receipt requires a file path");
    } else if (arg.startsWith("-")) {
      throw new Error(`unknown verification option: ${arg}`);
    } else if (mode) {
      throw new Error(`unexpected verification argument: ${arg}`);
    } else {
      mode = arg;
    }
  }
  return { mode: mode ?? "quick", summary, receipt };
}

// Every fact below is captured from a real command. A fact we cannot read is
// recorded as null so a reader sees "unknown", never a comfortable default.
function captureOutput(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  if (result.error || result.status !== 0) return null;
  return result.stdout.trim();
}

export function rustcIdentity(versionOutput) {
  if (!versionOutput) return null;
  const lines = versionOutput.split(/\r?\n/);
  const host = lines.find((line) => line.startsWith("host: "))?.slice("host: ".length);
  return host ? `${lines[0]} (host ${host})` : lines[0];
}

export function workingTreeDirty(porcelain) {
  if (porcelain === null) return null;
  return porcelain.length > 0;
}

function repositoryFacts() {
  return {
    commit: captureOutput("git", ["rev-parse", "HEAD"]),
    tree: captureOutput("git", ["rev-parse", "HEAD^{tree}"]),
    dirty: workingTreeDirty(captureOutput("git", ["status", "--porcelain"])),
  };
}

// A run is only attributable to one snapshot if the tree was clean at both ends
// and never moved between them. Anything else — dirty at either end, a commit or
// tree that changed mid-run, or a fact we could not read — means the steps did
// not all see the same content, so the receipt says so instead of picking one
// snapshot to report.
export function foldRunSnapshots(before, after) {
  const dirty = eitherDirty(before.dirty, after.dirty);
  const moved = before.commit !== after.commit || before.tree !== after.tree;
  return {
    commit: after.commit,
    tree: after.tree,
    dirty,
    driftedDuringRun: dirty !== false || moved,
  };
}

function eitherDirty(before, after) {
  if (before === true || after === true) return true;
  if (before === null || after === null) return null;
  return false;
}

function toolchainFacts() {
  return {
    rustc: rustcIdentity(
      captureOutput(process.platform === "win32" ? "rustc.exe" : "rustc", ["-vV"]),
    ),
    node: process.version,
    pnpm: captureOutput(pnpm, ["-v"]),
  };
}

function defaultReceiptPath() {
  const gitDir = captureOutput("git", ["rev-parse", "--absolute-git-dir"]);
  if (!gitDir) {
    throw new Error(
      "cannot locate the git directory for the default receipt path; pass --receipt <path>",
    );
  }
  return path.join(gitDir, "kuzushi-verify-receipt.json");
}

function writeReceipt(file, receipt) {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(receipt, null, 2)}\n`);
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

function openReceipt(mode, plan) {
  const opened = repositoryFacts();
  return {
    mode,
    startedAt: new Date().toISOString(),
    ...foldRunSnapshots(opened, opened),
    toolchain: toolchainFacts(),
    host: `${process.platform}-${process.arch}`,
    plan: { mode, digest: planDigest(plan) },
    exceptions: verificationExceptions(mode),
    steps: [],
    opened,
  };
}

function closeReceipt(receipt, exitCode) {
  const { opened, ...rest } = receipt;
  return {
    ...rest,
    ...foldRunSnapshots(opened, repositoryFacts()),
    ok: exitCode === 0,
    finishedAt: new Date().toISOString(),
  };
}

function runPlan(plan, receipt, summary) {
  for (const item of plan) {
    const result = runStep(item, summary);
    receipt.steps.push(result);
    if (result.status !== 0 || result.signal) return result.status ?? 1;
  }
  return 0;
}

function main() {
  const { mode, summary, receipt: receiptOverride } = parseArguments(process.argv.slice(2));
  validatePlans();
  const plan = verificationPlan(mode);
  const receiptPath = receiptOverride ?? defaultReceiptPath();
  const opened = openReceipt(mode, plan);
  const exitCode = runPlan(plan, opened, summary);
  const receipt = closeReceipt(opened, exitCode);
  writeReceipt(receiptPath, receipt);
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
  process.stderr.write(`verify: receipt written to ${receiptPath}\n`);
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

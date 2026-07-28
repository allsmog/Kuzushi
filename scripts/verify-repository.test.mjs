import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { validatePnpmPlanScripts, verificationPlan } from "./verify-repository.mjs";

const verifier = path.join(path.dirname(fileURLToPath(import.meta.url)), "verify-repository.mjs");
const packageJson = JSON.parse(
  readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "package.json"),
    "utf8",
  ),
);

test("CI plan includes every host-independent hard gate", () => {
  const quickPlan = verificationPlan("quick");
  const ciPlan = verificationPlan("ci");
  const quick = quickPlan.map(({ name }) => name);
  const ci = ciPlan.map(({ name }) => name);

  assert.ok(quick.includes("tests"));
  assert.ok(quick.includes("cargo-check"));
  assert.ok(ci.includes("coverage"));
  assert.ok(ci.includes("clippy"));
  assert.ok(ci.includes("cargo-deny"));
  assert.ok(ci.includes("rust-tests"));
  assert.ok(ci.includes("performance"));
  assert.ok(ci.includes("mutations"));
  assert.ok(ci.includes("rust-build"));
  assert.ok(ci.includes("build-native"));
  assert.ok(ci.includes("pack-contract"));
  assert.ok(ci.includes("e2e"));
  assert.deepEqual(ci.slice(0, quick.length), quick);
  assert.equal(new Set(ciPlan.map(commandKey)).size, ciPlan.length);
  assert.deepEqual(stepArgs(quickPlan, "cargo-check"), [
    "check",
    "--workspace",
    "--all-targets",
    "--locked",
  ]);
  assert.deepEqual(stepArgs(ciPlan, "clippy"), [
    "clippy",
    "--workspace",
    "--all-targets",
    "--locked",
    "--",
    "-D",
    "warnings",
  ]);
  assert.deepEqual(stepArgs(ciPlan, "rust-tests"), ["test", "--workspace", "--locked"]);
  assert.deepEqual(stepArgs(ciPlan, "rust-build"), ["build", "--workspace", "--locked"]);
});

test("all verification plans reference package scripts that exist", () => {
  for (const mode of ["quick", "ci"]) {
    assert.doesNotThrow(() => validatePnpmPlanScripts(verificationPlan(mode), packageJson.scripts));
  }
});

test("package script validation rejects unknown plan scripts", () => {
  const pnpmStep = verificationPlan("quick").find(({ name }) => name === "tests");
  const invalidPlan = [{ ...pnpmStep, args: ["missing:script"] }];

  assert.throws(
    () => validatePnpmPlanScripts(invalidPlan, packageJson.scripts),
    /unknown package scripts: missing:script/,
  );
});

test("unknown verification modes fail closed", () => {
  assert.throws(() => verificationPlan("fast-ish"), /quick or ci/);
});

test("process receipt owns stdout and records successful completion", {
  skip: process.platform === "win32",
}, () => {
  withFakeTools("success", (environment) => {
    const result = runVerifier(environment);
    const receipt = JSON.parse(result.stdout);

    assert.equal(result.status, 0);
    assert.equal(receipt.ok, true);
    assert.match(receipt.startedAt, /^\d{4}-/);
    assert.match(receipt.finishedAt, /^\d{4}-/);
    assert.match(result.stderr, /fake child output/);
    assert.doesNotMatch(result.stdout, /fake child output/);
  });
});

test("process receipt preserves command failure status", {
  skip: process.platform === "win32",
}, () => {
  withFakeTools("failure", (environment) => {
    const result = runVerifier(environment);
    const receipt = JSON.parse(result.stdout);

    assert.equal(result.status, 7);
    assert.equal(receipt.ok, false);
    assert.equal(receipt.steps.at(-1).status, 7);
  });
});

test("process receipt preserves terminating signal", { skip: process.platform === "win32" }, () => {
  withFakeTools("signal", (environment) => {
    const result = runVerifier(environment);
    const receipt = JSON.parse(result.stdout);

    assert.equal(result.status, 1);
    assert.equal(receipt.ok, false);
    assert.equal(receipt.steps.at(-1).signal, "SIGTERM");
  });
});

function runVerifier(environment) {
  return spawnSync(process.execPath, [verifier, "quick"], {
    encoding: "utf8",
    env: environment,
  });
}

function commandKey({ command, args }) {
  return JSON.stringify([command, args]);
}

function stepArgs(plan, name) {
  return plan.find((item) => item.name === name)?.args;
}

function withFakeTools(mode, callback) {
  const directory = mkdtempSync(path.join(os.tmpdir(), "kuzushi-verify-receipt-"));
  try {
    const tool = `#!/bin/sh\necho fake child output\n${toolExit(mode)}\n`;
    for (const name of ["pnpm", "cargo"]) {
      const file = path.join(directory, name);
      writeFileSync(file, tool);
      chmodSync(file, 0o755);
    }
    callback({ ...process.env, PATH: directory });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function toolExit(mode) {
  if (mode === "failure") return '[ "$1" = "test" ] && exit 7\nexit 0';
  if (mode === "signal") return '[ "$1" = "test" ] && kill -TERM $$\nexit 0';
  return "exit 0";
}

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { verificationPlan } from "./verify-repository.mjs";

const verifier = path.join(path.dirname(fileURLToPath(import.meta.url)), "verify-repository.mjs");

test("CI plan includes every host-independent hard gate", () => {
  const quick = verificationPlan("quick").map(({ name }) => name);
  const ci = verificationPlan("ci").map(({ name }) => name);

  assert.ok(quick.includes("tests"));
  assert.ok(ci.includes("coverage"));
  assert.ok(ci.includes("codegen"));
  assert.ok(ci.includes("clippy"));
  assert.ok(ci.includes("cargo-deny"));
  assert.ok(ci.includes("rust-tests"));
  assert.ok(ci.includes("rust-build"));
  assert.ok(ci.includes("build-native"));
  assert.ok(ci.includes("pack-contract"));
  assert.ok(ci.includes("e2e"));
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

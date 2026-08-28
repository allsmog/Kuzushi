import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  foldRunSnapshots,
  parseArguments,
  planDigest,
  rustcIdentity,
  validatePnpmPlanScripts,
  verificationExceptions,
  verificationPlan,
  workingTreeDirty,
} from "./verify-repository.mjs";

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

  assert.ok(quick.includes("secrets"));
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
  assert.deepEqual(stepArgs(quickPlan, "secrets"), ["quality:secrets"]);
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

test("verification arguments enable summary output explicitly", () => {
  assert.deepEqual(parseArguments([]), { mode: "quick", summary: false, receipt: null });
  assert.deepEqual(parseArguments(["ci", "--summary"]), {
    mode: "ci",
    summary: true,
    receipt: null,
  });
  assert.deepEqual(parseArguments(["--receipt", "/tmp/r.json"]), {
    mode: "quick",
    summary: false,
    receipt: "/tmp/r.json",
  });
  assert.throws(() => parseArguments(["--verbose"]), /unknown verification option/);
  assert.throws(() => parseArguments(["--receipt"]), /--receipt requires a file path/);
});

test("plan digest changes when a plan step is weakened", () => {
  const quick = verificationPlan("quick");
  const weakened = quick.map((item) =>
    item.name === "cargo-check" ? { ...item, args: ["check"] } : item,
  );
  const renamed = quick.map((item) => (item.name === "biome" ? { ...item, name: "lint" } : item));

  assert.match(planDigest(quick), /^[0-9a-f]{64}$/);
  assert.equal(planDigest(quick), planDigest(verificationPlan("quick")));
  assert.notEqual(planDigest(quick), planDigest(weakened));
  assert.notEqual(planDigest(quick), planDigest(renamed));
  assert.notEqual(planDigest(quick), planDigest(verificationPlan("ci")));
});

test("exceptions name the CI-only gates a quick run did not cover", () => {
  const quick = verificationExceptions("quick");
  const ci = verificationExceptions("ci");
  const omitted = quick.find((entry) => entry.startsWith("Mode quick did not run:"));

  assert.ok(omitted, "quick exceptions must name the gates it skipped");
  for (const gate of ["clippy", "cargo-deny", "rust-tests", "mutations", "e2e"]) {
    assert.ok(omitted.includes(gate), `quick exceptions must disclose ${gate}`);
  }
  assert.ok(quick.some((entry) => entry.includes("Cross-platform compilation")));
  assert.ok(!ci.some((entry) => entry.startsWith("Mode ci did not run:")));
  assert.ok(ci.some((entry) => entry.includes("Node 22")));
});

test("toolchain and dirty facts stay honest when the fact is unreadable", () => {
  assert.equal(rustcIdentity(null), null);
  assert.equal(
    rustcIdentity("rustc 1.90.0 (abc 2026-01-01)\nbinary: rustc\nhost: aarch64-apple-darwin"),
    "rustc 1.90.0 (abc 2026-01-01) (host aarch64-apple-darwin)",
  );
  assert.equal(rustcIdentity("rustc 1.90.0"), "rustc 1.90.0");
  assert.equal(workingTreeDirty(null), null, "an unreadable git status must not read as clean");
  assert.equal(workingTreeDirty(""), false);
  assert.equal(workingTreeDirty(" M scripts/verify-repository.mjs"), true);
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

test("summary output suppresses successful child output", {
  skip: process.platform === "win32",
}, () => {
  withFakeTools("success", (environment) => {
    const result = runVerifier(environment, ["quick", "--summary"]);
    const receipt = JSON.parse(result.stdout);

    assert.equal(result.status, 0);
    assert.equal(receipt.ok, true);
    assert.doesNotMatch(result.stderr, /fake child output/);
    assert.match(result.stderr, /verify: secrets/);
  });
});

test("process receipt preserves command failure status", {
  skip: process.platform === "win32",
}, () => {
  withFakeTools("failure", (environment) => {
    const result = runVerifier(environment, ["quick", "--summary"]);
    const receipt = JSON.parse(result.stdout);

    assert.equal(result.status, 7);
    assert.equal(receipt.ok, false);
    assert.equal(receipt.steps.at(-1).status, 7);
  });
});

test("process receipt preserves terminating signal", { skip: process.platform === "win32" }, () => {
  withFakeTools("signal", (environment) => {
    const result = runVerifier(environment, ["quick", "--summary"]);
    const receipt = JSON.parse(result.stdout);

    assert.equal(result.status, 1);
    assert.equal(receipt.ok, false);
    assert.equal(receipt.steps.at(-1).signal, "SIGTERM");
  });
});

test("snapshot folding reports the close-time state and any drift between the ends", () => {
  const clean = { commit: "aaa", tree: "ttt", dirty: false };

  assert.deepEqual(foldRunSnapshots(clean, clean), {
    commit: "aaa",
    tree: "ttt",
    dirty: false,
    driftedDuringRun: false,
  });
  assert.deepEqual(foldRunSnapshots(clean, { ...clean, dirty: true }), {
    commit: "aaa",
    tree: "ttt",
    dirty: true,
    driftedDuringRun: true,
  });
  assert.deepEqual(foldRunSnapshots({ ...clean, dirty: true }, clean), {
    commit: "aaa",
    tree: "ttt",
    dirty: true,
    driftedDuringRun: true,
  });

  const moved = foldRunSnapshots(clean, { commit: "bbb", tree: "uuu", dirty: false });
  assert.equal(moved.commit, "bbb", "the receipt reports the close-time commit");
  assert.equal(moved.tree, "uuu");
  assert.equal(moved.driftedDuringRun, true, "a commit that moved mid-run is drift");

  const unknown = foldRunSnapshots(clean, { ...clean, dirty: null });
  assert.equal(unknown.dirty, null, "an unreadable git status must not read as clean");
  assert.equal(unknown.driftedDuringRun, true, "unknown cleanliness fails closed");
});

test("receipt binds the run to a commit, tree, toolchain, and plan digest", {
  skip: process.platform === "win32",
}, () => {
  withFakeTools("success", { keepPath: true }, (environment) => {
    const receiptPath = temporaryReceiptPath();
    const result = runVerifier(environment, ["quick", "--summary"], receiptPath);
    const receipt = JSON.parse(result.stdout);

    assert.equal(result.status, 0);
    assert.equal(receipt.commit, gitOutput(["rev-parse", "HEAD"]));
    assert.equal(receipt.tree, gitOutput(["rev-parse", "HEAD^{tree}"]));
    assert.equal(receipt.dirty, gitOutput(["status", "--porcelain"]).length > 0);
    assert.equal(receipt.driftedDuringRun, receipt.dirty);
    assert.ok(!("opened" in receipt), "the opening snapshot is internal, not receipt content");
    assert.equal(receipt.toolchain.node, process.version);
    assert.equal(receipt.host, `${process.platform}-${process.arch}`);
    assert.deepEqual(receipt.plan, {
      mode: "quick",
      digest: planDigest(verificationPlan("quick")),
    });
    assert.ok(receipt.exceptions.length > 0, "receipt must state what it does not cover");
    assert.deepEqual(JSON.parse(readFileSync(receiptPath, "utf8")), receipt);
    assert.match(result.stderr, new RegExp(`receipt written to ${escapeRegExp(receiptPath)}`));
  });
});

test("receipt records a dirty working tree honestly", {
  skip: process.platform === "win32",
}, () => {
  withFakeTools("success", { keepPath: true }, (environment) => {
    withTemporaryGitRepository((repository) => {
      const receiptPath = temporaryReceiptPath();
      const clean = JSON.parse(runVerifierIn(repository, environment, receiptPath).stdout);
      writeFileSync(path.join(repository, "scratch.txt"), "uncommitted\n");
      const dirty = JSON.parse(runVerifierIn(repository, environment, receiptPath).stdout);

      assert.equal(clean.dirty, false);
      assert.equal(clean.driftedDuringRun, false);
      assert.equal(dirty.dirty, true);
      assert.equal(dirty.driftedDuringRun, true);
      assert.equal(dirty.commit, clean.commit, "an uncommitted edit does not move HEAD");
      assert.equal(dirty.ok, true, "the receipt still passes; it just says the tree was dirty");
    });
  });
});

test("a tree edited between plan start and receipt close is recorded as drift", {
  skip: process.platform === "win32",
}, () => {
  withFakeTools("edit-midrun", { keepPath: true }, (environment) => {
    withTemporaryGitRepository((repository) => {
      const receipt = JSON.parse(
        runVerifierIn(repository, environment, temporaryReceiptPath()).stdout,
      );

      assert.equal(receipt.ok, true, "every step still passed");
      assert.equal(receipt.dirty, true, "the tree was clean at start but dirty at close");
      assert.equal(receipt.driftedDuringRun, true);
    });
  });
});

test("a commit made between plan start and receipt close is recorded as drift", {
  skip: process.platform === "win32",
}, () => {
  withFakeTools("commit-midrun", { keepPath: true }, (environment) => {
    withTemporaryGitRepository((repository) => {
      const opening = gitOutputIn(repository, ["rev-parse", "HEAD"]);
      const receipt = JSON.parse(
        runVerifierIn(repository, environment, temporaryReceiptPath()).stdout,
      );

      assert.equal(receipt.ok, true);
      assert.equal(receipt.dirty, false, "the tree itself stayed clean");
      assert.notEqual(receipt.commit, opening, "the receipt reports the close-time commit");
      assert.equal(receipt.driftedDuringRun, true, "HEAD moved mid-run");
    });
  });
});

function runVerifier(environment, args = ["quick"], receiptPath = temporaryReceiptPath()) {
  return spawnSync(process.execPath, [verifier, ...args, "--receipt", receiptPath], {
    encoding: "utf8",
    env: environment,
  });
}

function temporaryReceiptPath() {
  return path.join(
    mkdtempSync(path.join(os.tmpdir(), "kuzushi-verify-out-")),
    "kuzushi-verify-receipt.json",
  );
}

function commandKey({ command, args }) {
  return JSON.stringify([command, args]);
}

function stepArgs(plan, name) {
  return plan.find((item) => item.name === name)?.args;
}

// keepPath leaves the real PATH behind the fakes, so provenance commands
// (git, rustc) still resolve while pnpm/cargo stay stubbed.
function withFakeTools(mode, optionsOrCallback, maybeCallback) {
  const callback = maybeCallback ?? optionsOrCallback;
  const { keepPath = false } = maybeCallback ? optionsOrCallback : {};
  const directory = mkdtempSync(path.join(os.tmpdir(), "kuzushi-verify-receipt-"));
  try {
    // A version probe answers like the real tool would; only plan steps emit
    // the marker output the leak assertions look for.
    const tool = [
      "#!/bin/sh",
      'case "$1" in -v|--version) echo 9.9.9-fake; exit 0 ;; esac',
      "echo fake child output",
      toolExit(mode),
      "",
    ].join("\n");
    for (const name of ["pnpm", "cargo"]) {
      const file = path.join(directory, name);
      writeFileSync(file, tool);
      chmodSync(file, 0o755);
    }
    const PATH = keepPath ? `${directory}${path.delimiter}${process.env.PATH}` : directory;
    callback({ ...process.env, PATH });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function withTemporaryGitRepository(callback) {
  const repository = mkdtempSync(path.join(os.tmpdir(), "kuzushi-verify-repo-"));
  try {
    for (const args of [
      ["init", "--quiet", "--initial-branch=main"],
      ["config", "user.email", "receipt-test@example.invalid"],
      ["config", "user.name", "receipt test"],
      ["commit", "--quiet", "--allow-empty", "-m", "initial"],
    ]) {
      spawnSync("git", args, { cwd: repository, encoding: "utf8" });
    }
    callback(repository);
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
}

function runVerifierIn(cwd, environment, receiptPath) {
  return spawnSync(process.execPath, [verifier, "quick", "--summary", "--receipt", receiptPath], {
    cwd,
    encoding: "utf8",
    env: environment,
  });
}

function gitOutput(args) {
  return spawnSync("git", args, { encoding: "utf8" }).stdout.trim();
}

function gitOutputIn(cwd, args) {
  return spawnSync("git", args, { cwd, encoding: "utf8" }).stdout.trim();
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function toolExit(mode) {
  if (mode === "failure") return '[ "$1" = "test" ] && exit 7\nexit 0';
  if (mode === "signal") return '[ "$1" = "test" ] && kill -TERM $$\nexit 0';
  // Mutate the working tree from inside a plan step, so the opening and closing
  // snapshots genuinely disagree.
  if (mode === "edit-midrun") return '[ "$1" = "test" ] && : > mid-run-edit.txt\nexit 0';
  if (mode === "commit-midrun") {
    return '[ "$1" = "test" ] && git commit --quiet --allow-empty -m mid-run\nexit 0';
  }
  return "exit 0";
}

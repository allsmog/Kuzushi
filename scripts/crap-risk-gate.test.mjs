import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const gate = path.join(path.dirname(fileURLToPath(import.meta.url)), "crap-risk-gate.mjs");

test("explicit CI base covers every commit in a multi-commit change", () => {
  const repository = mkdtempSync(path.join(os.tmpdir(), "kuzushi-crap-base-"));
  try {
    initializeRepository(repository);
    const base = git(repository, ["rev-parse", "HEAD"]).trim();
    writeBranchyProductionChange(repository);
    commit(repository, "add risky code");
    writeFileSync(path.join(repository, "README.md"), "tip-only docs change\n");
    commit(repository, "docs only tip");

    const result = spawnSync(process.execPath, [gate], {
      cwd: repository,
      encoding: "utf8",
      env: { ...process.env, KUZUSHI_CRAP_RISK_BASE_REF: base },
    });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /src\/risky\.rs/);
    assert.match(result.stderr, /complexity/);
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});

test("zero-SHA event base covers a complete multi-commit new ref", () => {
  const repository = mkdtempSync(path.join(os.tmpdir(), "kuzushi-crap-zero-base-"));
  try {
    initializeRepository(repository);
    writeBranchyProductionChange(repository);
    commit(repository, "add risky code");
    writeFileSync(path.join(repository, "README.md"), "tip-only docs change\n");
    commit(repository, "docs only tip");

    const result = spawnSync(process.execPath, [gate], {
      cwd: repository,
      encoding: "utf8",
      env: { ...process.env, KUZUSHI_CRAP_RISK_BASE_REF: "0".repeat(40) },
    });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /src\/risky\.rs/);
    assert.match(result.stderr, /complexity/);
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});

test("non-commit diff bases fail closed", () => {
  const repository = mkdtempSync(path.join(os.tmpdir(), "kuzushi-crap-object-base-"));
  try {
    initializeRepository(repository);
    const blob = git(repository, ["rev-parse", "HEAD:README.md"]).trim();

    const result = spawnSync(process.execPath, [gate], {
      cwd: repository,
      encoding: "utf8",
      env: { ...process.env, KUZUSHI_CRAP_RISK_BASE_REF: blob },
    });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /cannot resolve diff base/);
    assert.doesNotMatch(result.stdout, /passed for 0 changed code file/);
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});

function initializeRepository(repository) {
  git(repository, ["init", "-q"]);
  git(repository, ["config", "user.name", "Kuzushi Test"]);
  git(repository, ["config", "user.email", "kuzushi@example.invalid"]);
  writeFileSync(path.join(repository, "README.md"), "base\n");
  commit(repository, "base");
}

function writeBranchyProductionChange(repository) {
  const source = `fn risky(a: bool, b: bool, c: bool, d: bool, e: bool) -> bool {
    if a { return true; }
    if b { return true; }
    if c { return true; }
    if d { return true; }
    e
}\n`;
  const src = path.join(repository, "src");
  mkdirSync(src);
  writeFileSync(path.join(src, "risky.rs"), source);
}

function commit(repository, message) {
  git(repository, ["add", "."]);
  git(repository, ["commit", "-q", "-m", message]);
}

function git(repository, args) {
  return execFileSync("git", args, { cwd: repository, encoding: "utf8" });
}

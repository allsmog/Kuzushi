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

test("dirty worktree files do not hide committed changes since the CI base", () => {
  const repository = mkdtempSync(path.join(os.tmpdir(), "kuzushi-crap-dirty-base-"));
  try {
    initializeRepository(repository);
    const base = git(repository, ["rev-parse", "HEAD"]).trim();
    writeBranchyProductionChange(repository);
    commit(repository, "add risky code");
    writeFileSync(path.join(repository, "README.md"), "uncommitted docs change\n");

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

test("inline Rust tests do not consume production complexity budgets", () => {
  const repository = mkdtempSync(path.join(os.tmpdir(), "kuzushi-crap-inline-tests-"));
  try {
    initializeRepository(repository);
    const src = path.join(repository, "src");
    mkdirSync(src);
    const testLines = Array.from(
      { length: 45 },
      (_, index) => `        if value == ${index} { return; }`,
    ).join("\n");
    writeFileSync(
      path.join(src, "small.rs"),
      `fn small() -> bool { true }

#[cfg(test)]
mod tests {
    #[test]
    fn exhaustive_fixture() {
        let value = 99;
${testLines}
    }
}
`,
    );

    const result = spawnSync(process.execPath, [gate], {
      cwd: repository,
      encoding: "utf8",
      env: { ...process.env, KUZUSHI_CRAP_RISK_BASE_REF: "HEAD" },
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /passed for 1 changed code file/);
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});

test("Rust test-support modules are excluded from production scoring", () => {
  const repository = mkdtempSync(path.join(os.tmpdir(), "kuzushi-crap-test-support-"));
  try {
    initializeRepository(repository);
    const src = path.join(repository, "src");
    mkdirSync(src);
    writeFileSync(
      path.join(src, "test_support.rs"),
      `fn branchy_fixture(value: usize) {
${Array.from({ length: 45 }, (_, index) => `    if value == ${index} { return; }`).join("\n")}
}
`,
    );

    const result = spawnSync(process.execPath, [gate], {
      cwd: repository,
      encoding: "utf8",
      env: { ...process.env, KUZUSHI_CRAP_RISK_BASE_REF: "HEAD" },
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /passed for 0 changed code file/);
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});

test("Rust test module naming conventions are excluded from production scoring", () => {
  const repository = mkdtempSync(path.join(os.tmpdir(), "kuzushi-crap-test-modules-"));
  try {
    initializeRepository(repository);
    const src = path.join(repository, "src");
    const nested = path.join(src, "bridge_process_tests");
    mkdirSync(nested, { recursive: true });
    const fixture = `fn branchy_fixture(value: usize) {
${Array.from({ length: 45 }, (_, index) => `    if value == ${index} { return; }`).join("\n")}
}
`;
    writeFileSync(path.join(src, "runtime_admission_tests.rs"), fixture);
    writeFileSync(path.join(nested, "admission.rs"), fixture);

    const result = spawnSync(process.execPath, [gate], {
      cwd: repository,
      encoding: "utf8",
      env: { ...process.env, KUZUSHI_CRAP_RISK_BASE_REF: "HEAD" },
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /passed for 0 changed code file/);
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

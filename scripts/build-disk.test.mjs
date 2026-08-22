import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { access, copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const buildDiskScript = fileURLToPath(new URL("./build-disk.sh", import.meta.url));

function run(command, args, options) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  assert.equal(
    result.status,
    0,
    `${command} ${args.join(" ")} failed:\n${result.stdout}${result.stderr}`,
  );
  return result.stdout;
}

async function createFixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), "kuzushi-build-disk-"));
  const repo = path.join(root, "repo");
  const home = path.join(root, "home");
  await mkdir(repo);
  await mkdir(home);
  run("git", ["init", "-q"], { cwd: repo });
  // Deterministic idle process table so machine-local Cargo/rustc activity can
  // never leak into fixture prune behavior. Liveness tests override this.
  const idleProcessTable = path.join(root, "idle-processes");
  await writeFile(idleProcessTable, "");
  return { root, repo, home, idleProcessTable };
}

function buildDisk(fixture, args = [], configuredEnvironment = {}) {
  const result = buildDiskResult(fixture, args, configuredEnvironment);
  assert.equal(result.status, 0, `build-disk failed:\n${result.stdout}${result.stderr}`);
  return result.stdout;
}

function buildDiskResult(fixture, args = [], configuredEnvironment = {}) {
  const environment = { ...process.env };
  delete environment.CARGO_TARGET_DIR;
  delete environment.KUZUSHI_EVIDENCE_LOOP_TARGET_DIR;
  delete environment.KUZUSHI_BUILD_DISK_PROCESS_TABLE;
  delete environment.KUZUSHI_BUILD_DISK_BUDGET_GIB;
  return spawnSync("bash", [buildDiskScript, ...args], {
    encoding: "utf8",
    cwd: fixture.repo,
    env: {
      ...environment,
      HOME: fixture.home,
      KUZUSHI_BUILD_DISK_PROCESS_TABLE: fixture.idleProcessTable,
      ...configuredEnvironment,
    },
  });
}

async function exists(candidate) {
  try {
    await access(candidate);
    return true;
  } catch {
    return false;
  }
}

async function writeProcessTable(fixture, rows) {
  const table = path.join(fixture.root, "process-table");
  const lines = rows.map(({ pid, cwd, exe }) => `${pid}\t${cwd}\t${exe}`);
  await writeFile(table, `${lines.join("\n")}\n`);
  return table;
}

test("reports absolute Cargo and relative evidence-loop targets", async () => {
  const fixture = await createFixture();
  try {
    const cargoTarget = path.join(fixture.root, "shared cargo target");
    const evidenceTarget = path.join(fixture.repo, "evidence-target");
    await mkdir(cargoTarget);
    await mkdir(evidenceTarget);

    const output = buildDisk(fixture, [], {
      CARGO_TARGET_DIR: cargoTarget,
      KUZUSHI_EVIDENCE_LOOP_TARGET_DIR: "evidence-target",
    });

    assert.ok(output.includes(cargoTarget));
    assert.ok(output.includes(evidenceTarget));
    assert.match(output, /total across 2 build root\(s\)/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("discovers agent worktree targets alongside the checkout target", async () => {
  const fixture = await createFixture();
  try {
    const checkoutTarget = path.join(fixture.repo, "target");
    const agentWorktree = path.join(fixture.repo, ".claude", "worktrees", "agent a");
    const agentTarget = path.join(agentWorktree, "target");
    const codexTarget = path.join(fixture.repo, ".codex", "worktrees", "agent-b", "target-dev");
    await mkdir(checkoutTarget, { recursive: true });
    await mkdir(agentTarget, { recursive: true });
    await mkdir(codexTarget, { recursive: true });

    const output = buildDisk(fixture);
    assert.ok(output.includes(checkoutTarget));
    assert.ok(output.includes(agentTarget));
    assert.ok(output.includes(codexTarget));
    assert.match(output, /total across 3 build root\(s\)/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("report distinguishes incremental, deps, release, coverage, and scratch", async () => {
  const fixture = await createFixture();
  try {
    const target = path.join(fixture.repo, "target");
    await mkdir(path.join(target, "debug", "incremental"), { recursive: true });
    await mkdir(path.join(target, "debug", "deps"), { recursive: true });
    await mkdir(path.join(target, "release"), { recursive: true });
    await mkdir(path.join(target, "llvm-cov-target"), { recursive: true });
    await mkdir(path.join(target, ".ephemeral"), { recursive: true });
    await writeFile(path.join(target, "debug", "incremental", "cache"), "x".repeat(4096));
    await writeFile(path.join(target, "debug", "deps", "libdep.rlib"), "y".repeat(4096));

    const output = buildDisk(fixture);
    assert.match(output, /incremental\n/);
    assert.match(output, /deps \(compiled dependencies \+ test executables\)/);
    assert.match(output, /release artifacts/);
    assert.match(output, /coverage/);
    assert.match(output, /scratch \(\.ephemeral, mutation\)/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("budget check passes under budget and fails over it", async () => {
  const fixture = await createFixture();
  try {
    const target = path.join(fixture.repo, "target");
    await mkdir(path.join(target, "debug"), { recursive: true });
    await writeFile(path.join(target, "debug", "big"), "z".repeat(2 * 1024 * 1024));

    const under = buildDiskResult(fixture, ["--check-budget", "--budget-gib", "40"]);
    assert.equal(under.status, 0, under.stdout + under.stderr);
    assert.match(under.stdout, /of a 40 GiB budget/);

    const over = buildDiskResult(fixture, ["--check-budget", "--budget-gib", "0.001"]);
    assert.equal(over.status, 1, over.stdout + over.stderr);
    assert.match(over.stdout, /over budget/);

    const invalid = buildDiskResult(fixture, ["--check-budget", "--budget-gib", "zero"]);
    assert.equal(invalid.status, 2);
    assert.match(invalid.stderr, /budget must be a positive number/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("prunes auxiliary and incremental data from configured targets", async () => {
  const fixture = await createFixture();
  try {
    const cargoTarget = path.join(fixture.root, "cargo-build");
    const evidenceTarget = path.join(fixture.root, "evidence-build");
    const cargoAux = path.join(cargoTarget, "llvm-cov-target");
    const evidenceAux = path.join(evidenceTarget, ".ephemeral");
    const cargoIncremental = path.join(cargoTarget, "debug", "incremental");
    const evidenceIncremental = path.join(evidenceTarget, "debug", "incremental");
    await Promise.all(
      [cargoAux, evidenceAux, cargoIncremental, evidenceIncremental].map((directory) =>
        mkdir(directory, { recursive: true }),
      ),
    );
    await writeFile(path.join(cargoTarget, "keep"), "compiled dependency");
    await writeFile(path.join(cargoTarget, "debug", "deps.rlib"), "compiled dependency");

    const environment = {
      CARGO_TARGET_DIR: cargoTarget,
      KUZUSHI_EVIDENCE_LOOP_TARGET_DIR: evidenceTarget,
    };
    buildDisk(fixture, ["--prune-aux", "--apply"], environment);
    assert.equal(await exists(cargoAux), false);
    assert.equal(await exists(evidenceAux), false);
    assert.equal(await exists(path.join(cargoTarget, "keep")), true);

    buildDisk(fixture, ["--prune-incremental", "--apply"], environment);
    assert.equal(await exists(cargoIncremental), false);
    assert.equal(await exists(evidenceIncremental), false);
    assert.equal(await exists(cargoTarget), true);
    assert.equal(await exists(evidenceTarget), true);
    assert.equal(await exists(path.join(cargoTarget, "debug", "deps.rlib")), true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("keeps configured targets on prune-all dry-run and removes them on apply", async () => {
  const fixture = await createFixture();
  try {
    const cargoTarget = path.join(fixture.root, "cargo-target");
    const evidenceTarget = path.join(fixture.root, "evidence-target");
    await mkdir(cargoTarget);
    await mkdir(evidenceTarget);
    const environment = {
      CARGO_TARGET_DIR: cargoTarget,
      KUZUSHI_EVIDENCE_LOOP_TARGET_DIR: evidenceTarget,
    };

    const dryRun = buildDisk(fixture, ["--prune-all"], environment);
    assert.match(dryRun, /Dry run:/);
    assert.equal(await exists(cargoTarget), true);
    assert.equal(await exists(evidenceTarget), true);

    buildDisk(fixture, ["--prune-all", "--apply"], environment);
    assert.equal(await exists(cargoTarget), false);
    assert.equal(await exists(evidenceTarget), false);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("prune apply preserves repository sources and handles paths with spaces", async () => {
  const fixture = await createFixture();
  try {
    const source = path.join(fixture.repo, "src", "main.rs");
    await mkdir(path.dirname(source), { recursive: true });
    await writeFile(source, "fn main() {}\n");
    const target = path.join(fixture.repo, "target");
    await mkdir(path.join(target, "debug", "incremental", "crate a-hash"), {
      recursive: true,
    });
    await writeFile(
      path.join(target, "debug", "incremental", "crate a-hash", "session file"),
      "incremental cache",
    );
    await writeFile(path.join(target, "debug", "kuzushi"), "final binary");

    buildDisk(fixture, ["--prune-incremental", "--apply"]);
    assert.equal(await exists(path.join(target, "debug", "incremental")), false);
    assert.equal(await exists(path.join(target, "debug", "kuzushi")), true);
    assert.equal(await exists(source), true);

    buildDisk(fixture, ["--prune-all", "--apply"]);
    assert.equal(await exists(target), false);
    assert.equal(await exists(source), true);
    assert.equal(await exists(fixture.repo), true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("refuses every prune mode for a configured unsafe root", async () => {
  const fixture = await createFixture();
  try {
    const sentinel = path.join(fixture.home, "keep");
    await writeFile(sentinel, "operator data");

    for (const mode of ["--prune-aux", "--prune-incremental", "--prune-all"]) {
      const result = buildDiskResult(fixture, [mode, "--apply"], {
        CARGO_TARGET_DIR: fixture.home,
        HOME: `${fixture.home}/`,
      });
      assert.equal(result.status, 2, mode);
      assert.match(result.stderr, /refusing unsafe prune path/);
    }
    assert.equal(await exists(sentinel), true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("refuses to prune when an executable runs from the target", async () => {
  const fixture = await createFixture();
  try {
    const target = path.join(fixture.repo, "target");
    const binary = path.join(target, "debug", "kuzushi binary");
    await mkdir(path.join(target, "debug", "incremental"), { recursive: true });
    await writeFile(binary, "live binary");
    const table = await writeProcessTable(fixture, [{ pid: 4242, cwd: "-", exe: binary }]);

    for (const mode of ["--prune-incremental", "--prune-all"]) {
      const result = buildDiskResult(fixture, [mode, "--apply"], {
        KUZUSHI_BUILD_DISK_PROCESS_TABLE: table,
      });
      assert.equal(result.status, 3, mode);
      assert.match(result.stderr, /refusing .*: executable .* is running from it/);
      assert.match(result.stderr, /nothing was deleted/);
    }
    assert.equal(await exists(binary), true);
    assert.equal(await exists(path.join(target, "debug", "incremental")), true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("refuses to prune while Cargo runs in the owning worktree", async () => {
  const fixture = await createFixture();
  try {
    const target = path.join(fixture.repo, "target");
    await mkdir(path.join(target, "debug", "incremental"), { recursive: true });
    const table = await writeProcessTable(fixture, [
      { pid: 51, cwd: path.join(fixture.repo, "crates"), exe: "/usr/local/bin/cargo" },
    ]);

    const result = buildDiskResult(fixture, ["--prune-incremental", "--apply"], {
      KUZUSHI_BUILD_DISK_PROCESS_TABLE: table,
    });
    assert.equal(result.status, 3);
    assert.match(result.stderr, /cargo \(pid 51\) is running inside/);
    assert.equal(await exists(path.join(target, "debug", "incremental")), true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("fails closed when a Cargo process has an unknown working directory", async () => {
  const fixture = await createFixture();
  try {
    const target = path.join(fixture.repo, "target");
    await mkdir(path.join(target, "debug", "incremental"), { recursive: true });
    const table = await writeProcessTable(fixture, [
      { pid: 99, cwd: "?", exe: "/somewhere/rustc" },
    ]);

    const result = buildDiskResult(fixture, ["--prune-incremental", "--apply"], {
      KUZUSHI_BUILD_DISK_PROCESS_TABLE: table,
    });
    assert.equal(result.status, 3);
    assert.match(result.stderr, /working directory is unknown/);
    assert.equal(await exists(path.join(target, "debug", "incremental")), true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("allows pruning when Cargo runs in an unrelated worktree", async () => {
  const fixture = await createFixture();
  try {
    const target = path.join(fixture.repo, "target");
    await mkdir(path.join(target, "debug", "incremental"), { recursive: true });
    const table = await writeProcessTable(fixture, [
      { pid: 7, cwd: "/somewhere/else/project", exe: "/usr/local/bin/cargo" },
      { pid: 8, cwd: "-", exe: "/usr/bin/vim" },
    ]);

    buildDisk(fixture, ["--prune-incremental", "--apply"], {
      KUZUSHI_BUILD_DISK_PROCESS_TABLE: table,
    });
    assert.equal(await exists(path.join(target, "debug", "incremental")), false);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("live process enumeration refuses a running executable from the target", async () => {
  const fixture = await createFixture();
  try {
    const target = path.join(fixture.repo, "target");
    await mkdir(path.join(target, "debug"), { recursive: true });
    const binary = path.join(target, "debug", "live-sleeper");
    let child;
    if (process.platform === "darwin") {
      // Copies of Apple-signed binaries are killed on exec, and ps comm
      // reflects argv[0]; spawn the system sleep announcing the target path.
      await writeFile(binary, "stand-in for a running build product");
      child = spawn("/bin/sleep", ["60"], { argv0: binary, stdio: "ignore" });
    } else {
      await copyFile("/bin/sleep", binary);
      child = spawn(binary, ["60"], { stdio: "ignore" });
    }
    try {
      await new Promise((resolve) => setTimeout(resolve, 200));
      const result = buildDiskResult(fixture, ["--prune-all", "--apply"], {
        KUZUSHI_BUILD_DISK_PROCESS_TABLE: "",
      });
      assert.equal(result.status, 3, result.stdout + result.stderr);
      assert.match(result.stderr, /refusing/);
      assert.equal(await exists(binary), true);
    } finally {
      child.kill("SIGKILL");
    }
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

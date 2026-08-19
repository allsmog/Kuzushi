import assert from "node:assert/strict";
import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

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
  return { root, repo, home };
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
  return spawnSync("bash", [buildDiskScript, ...args], {
    encoding: "utf8",
    cwd: fixture.repo,
    env: { ...environment, HOME: fixture.home, ...configuredEnvironment },
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

test("refuses every prune mode for a configured unsafe root", async () => {
  const fixture = await createFixture();
  try {
    const sentinel = path.join(fixture.home, "keep");
    await writeFile(sentinel, "operator data");

    for (const mode of ["--prune-aux", "--prune-incremental", "--prune-all"]) {
      const result = buildDiskResult(fixture, [mode, "--apply"], {
        CARGO_TARGET_DIR: fixture.home,
      });
      assert.equal(result.status, 2, mode);
      assert.match(result.stderr, /refusing unsafe prune path/);
    }
    assert.equal(await exists(sentinel), true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

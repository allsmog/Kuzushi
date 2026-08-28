import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  nativeExecutableName,
  nativePlatformSlug,
  nativeRuntimeBinaries,
} from "./native-runtime-contract.mjs";

const script = fileURLToPath(new URL("./stage-native-binary.mjs", import.meta.url));

test("a cross-target stage reads the triple directory and writes its own slug", (t) => {
  const root = fixtureRoot(t, path.join("target", "x86_64-apple-darwin", "release"), "darwin");
  const result = stage(root, ["--target", "x86_64-apple-darwin"]);

  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(stagedNames(root, "darwin-x64"), expectedNames("darwin"));
  assert.equal(readdirSync(path.join(root, "native")).length, 1);
});

test("a host stage keeps reading target/release and staging the host slug", (t) => {
  const root = fixtureRoot(t, path.join("target", "release"), process.platform);
  const result = stage(root, []);

  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(stagedNames(root, nativePlatformSlug()), expectedNames(process.platform));
});

test("KUZUSHI_NATIVE_TARGET selects the cross target when no flag is passed", (t) => {
  const root = fixtureRoot(t, path.join("target", "x86_64-apple-darwin", "release"), "darwin");
  const result = stage(root, [], { KUZUSHI_NATIVE_TARGET: "x86_64-apple-darwin" });

  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(stagedNames(root, "darwin-x64"), expectedNames("darwin"));
});

test("CARGO_TARGET_DIR is honored instead of assuming an in-tree target directory", (t) => {
  const root = fixtureRoot(t, path.join("elsewhere", "x86_64-apple-darwin", "release"), "darwin");
  const result = stage(root, ["--target", "x86_64-apple-darwin"], {
    CARGO_TARGET_DIR: path.join(root, "elsewhere"),
  });

  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(stagedNames(root, "darwin-x64"), expectedNames("darwin"));
});

test("a missing cross-target build refuses to stage a stale or host payload", (t) => {
  const root = fixtureRoot(t, path.join("target", "release"), "darwin");
  const result = stage(root, ["--target", "x86_64-apple-darwin"]);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /target[/\\]x86_64-apple-darwin[/\\]release/);
});

test("an unsupported triple is refused before anything is staged", (t) => {
  const root = fixtureRoot(t, path.join("target", "release"), "darwin");
  const result = stage(root, ["--target", "wasm32-wasi"]);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unsupported Rust target/);
});

function fixtureRoot(t, releaseRelativeDir, platform) {
  const root = mkdtempSync(path.join(tmpdir(), "kuzushi-stage-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const releaseDir = path.join(root, releaseRelativeDir);
  mkdirSync(releaseDir, { recursive: true });
  for (const name of expectedNames(platform)) {
    writeFileSync(path.join(releaseDir, name), `#!/bin/sh\nexit 0\n`);
  }
  return root;
}

function stage(root, args, env = {}) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, CARGO_TARGET_DIR: "", KUZUSHI_NATIVE_TARGET: "", ...env },
  });
}

function expectedNames(platform) {
  return nativeRuntimeBinaries.map((binary) => nativeExecutableName(binary, platform)).sort();
}

function stagedNames(root, slug) {
  return readdirSync(path.join(root, "native", slug)).sort();
}

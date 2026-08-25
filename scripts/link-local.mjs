#!/usr/bin/env node
// Point the globally installed `kuzushi` npm wrapper at this checkout's
// freshly built release binary, so the command on PATH tracks local source
// instead of the binary published with the npm package.
//
//   pnpm link:local            build release + symlink the global binary here
//   pnpm link:local --restore  put the published binary back
//
// The original published binary is kept beside the symlink as
// `kuzushi.npm-orig`; `npm install -g kuzushi` also restores it. Run
// `kuzushi --version` afterwards — the `(sha · profile)` suffix shows which
// build you're on.

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, lstatSync, renameSync, symlinkSync, unlinkSync } from "node:fs";
import { dirname, join } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { cargoReleaseBuildArgs } from "./native-runtime-contract.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const restore = process.argv.includes("--restore");

main();

function main() {
  const binaryPath = globalNativeBinaryPath();
  const backupPath = `${binaryPath}.npm-orig`;
  if (restore) {
    restorePublishedBinary(binaryPath, backupPath);
    return;
  }
  linkLocalBinary(binaryPath, backupPath);
}

function linkLocalBinary(binaryPath, backupPath) {
  const localBinary = buildLocalRelease();
  if (isRegularFile(binaryPath) && !existsSync(backupPath)) {
    renameSync(binaryPath, backupPath);
    log(`backed up published binary to ${backupPath}`);
  }
  if (existsSync(binaryPath) || isSymlink(binaryPath)) {
    unlinkSync(binaryPath);
  }
  symlinkSync(localBinary, binaryPath);
  log(`global kuzushi now points at ${localBinary}`);
  log("future `pnpm link:local` runs rebuild the complete native runtime");
  reportVersion(binaryPath);
}

function restorePublishedBinary(binaryPath, backupPath) {
  if (!existsSync(backupPath)) {
    fail(
      `no backup at ${backupPath} — nothing to restore (reinstall with \`npm install -g kuzushi\` instead)`,
    );
  }
  if (existsSync(binaryPath) || isSymlink(binaryPath)) {
    unlinkSync(binaryPath);
  }
  renameSync(backupPath, binaryPath);
  log("restored the published binary");
  reportVersion(binaryPath);
}

function buildLocalRelease() {
  log("building the release CLI and MCP sidecars…");
  runCargoReleaseBuild();
  const localBinary = localReleaseBinary();
  requireRegularFile(localBinary);
  return localBinary;
}

function runCargoReleaseBuild() {
  const result = spawnSync("cargo", cargoReleaseBuildArgs(), {
    cwd: repoRoot,
    stdio: "inherit",
  });
  if (result.status !== 0) fail("cargo build failed");
}

function localReleaseBinary() {
  const exe = process.platform === "win32" ? "kuzushi.exe" : "kuzushi";
  return join(repoRoot, "target", "release", exe);
}

function requireRegularFile(path) {
  if (!isRegularFile(path)) fail(`expected build output at ${path}`);
}

function globalNativeBinaryPath() {
  const npmRoot = execFileSync("npm", ["root", "-g"], { encoding: "utf8" }).trim();
  const packageRoot = join(npmRoot, "kuzushi");
  if (!existsSync(packageRoot)) {
    fail(
      `kuzushi is not installed globally (looked in ${packageRoot}) — install it with \`npm install -g kuzushi\` first`,
    );
  }
  const exe = process.platform === "win32" ? "kuzushi.exe" : "kuzushi";
  return join(packageRoot, "native", `${process.platform}-${process.arch}`, exe);
}

function reportVersion(binaryPath) {
  const result = spawnSync(binaryPath, ["--version"], { encoding: "utf8" });
  if (result.status === 0) {
    log(`kuzushi --version → ${result.stdout.trim()}`);
  }
}

function isRegularFile(path) {
  return existsSync(path) && lstatSync(path).isFile();
}

function isSymlink(path) {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}

function log(message) {
  process.stdout.write(`link-local: ${message}\n`);
}

function fail(message) {
  process.stderr.write(`link-local: ${message}\n`);
  process.exit(1);
}

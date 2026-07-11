#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { nativeExecutableName, nativePlatformSlug } from "./native-runtime-contract.mjs";

if (process.env.KUZUSHI_VERIFY_PACK_OMIT_NATIVE === "1") {
  process.stdout.write("packed runtime smoke skipped because native payload was omitted\n");
  process.exit(0);
}

const root = process.cwd();
const temp = mkdtempSync(path.join(tmpdir(), "kuzushi-packed-runtime-"));

try {
  const archive = createPackageArchive(temp);
  const extracted = path.join(temp, "extracted");
  mkdirSync(extracted);
  run("tar", ["-xzf", archive, "-C", extracted], { cwd: root });

  const packageRoot = path.join(extracted, "package");
  assertPackagedBridge(packageRoot);
  smokeWrapperWithEmptyPath(packageRoot);
  smokeDirectNativeRuntimeWithEmptyPath(packageRoot);
  process.stdout.write(
    "extracted package wrapper and direct native runtime passed with an empty inherited PATH\n",
  );
} finally {
  rmSync(temp, { recursive: true, force: true });
}

function createPackageArchive(destination) {
  const result = run(
    "npm",
    ["pack", "--ignore-scripts", "--json", "--pack-destination", destination],
    { cwd: root, capture: true },
  );
  const packed = JSON.parse(result.stdout);
  const filename = packed[0]?.filename;
  if (typeof filename !== "string") throw new Error("npm pack did not report an archive filename");
  return path.join(destination, filename);
}

function assertPackagedBridge(packageRoot) {
  for (const relativePath of [
    "scripts/langgraph-bridge.mjs",
    "scripts/langgraph-bridge/mcp.mjs",
    "scripts/kuzushi-dynamic-module-host.mjs",
  ]) {
    if (!existsSync(path.join(packageRoot, relativePath))) {
      throw new Error(`packed runtime is missing ${relativePath}`);
    }
    run(process.execPath, ["--check", path.join(packageRoot, relativePath)], {
      cwd: packageRoot,
      capture: true,
    });
  }
}

function smokeWrapperWithEmptyPath(packageRoot) {
  const manifest = JSON.parse(readFileSync(path.join(packageRoot, "package.json"), "utf8"));
  const wrapper = path.join(packageRoot, "bin", "kuzushi-rs.mjs");
  const version = run(process.execPath, [wrapper, "--version"], {
    cwd: packageRoot,
    capture: true,
    env: isolatedNativeEnvironment(),
  });
  assertMatchingVersion(version.stdout, manifest.version);

  run(process.execPath, [wrapper, "mcp", "health", "tree-sitter"], {
    cwd: packageRoot,
    capture: true,
    env: isolatedNativeEnvironment(),
  });
}

function isolatedNativeEnvironment() {
  const env = { ...process.env, PATH: "" };
  delete env.KUZUSHI_NATIVE_BIN;
  for (const name of Object.keys(env)) {
    if (name.startsWith("KUZUSHI_MCP_") && name.endsWith("_BIN")) delete env[name];
  }
  return env;
}

function assertMatchingVersion(actual, expected) {
  if (actual.includes(expected)) return;
  throw new Error(`packed binary version does not match package ${expected}: ${actual.trim()}`);
}

function smokeDirectNativeRuntimeWithEmptyPath(packageRoot) {
  const runtimeDir = path.join(packageRoot, "native", nativePlatformSlug());
  const cli = path.join(runtimeDir, nativeExecutableName("kuzushi"));
  run(cli, ["mcp", "health", "tree-sitter"], {
    cwd: packageRoot,
    capture: true,
    env: { ...process.env, PATH: "" },
  });
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env,
    encoding: options.capture ? "utf8" : undefined,
    stdio: options.capture ? "pipe" : "inherit",
  });
  if (result.error || result.status !== 0) throw commandFailure(command, args, result);
  return result;
}

function commandFailure(command, args, result) {
  if (result.error) return result.error;
  const detail = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
  return new Error(
    `${command} ${args.join(" ")} failed (${result.status})${detail ? `:\n${detail}` : ""}`,
  );
}

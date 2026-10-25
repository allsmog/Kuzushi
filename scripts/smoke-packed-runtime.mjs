#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { nativeExecutableName, nativePlatformPackage } from "./native-runtime-contract.mjs";
import { PLATFORM_PACKED_BUDGET, PLATFORM_UNPACKED_BUDGET } from "./release-artifact-contract.mjs";

const root = process.cwd();
const temp = mkdtempSync(path.join(tmpdir(), "kuzushi-packed-runtime-"));
const omitNative = process.env.KUZUSHI_VERIFY_PACK_OMIT_NATIVE === "1";

try {
  const packedRoot = createPackageArchive(root, temp);
  if (packedRoot.size > 10 * 1024 * 1024) {
    throw new Error(`thin kuzushi package is ${packedRoot.size} bytes; budget is 10 MiB`);
  }
  const extracted = path.join(temp, "extracted");
  mkdirSync(extracted);
  run("tar", ["-xzf", path.join(temp, packedRoot.filename), "-C", extracted], { cwd: root });

  const packageRoot = path.join(extracted, "package");
  assertPackagedBridge(packageRoot);
  assertPackedManifestSurface(packageRoot);
  assertThinRootPackage(packageRoot);
  if (omitNative) {
    process.stdout.write("native runtime smoke skipped because native payload was omitted\n");
  } else {
    assertMissingOptionalPackageMessage(packageRoot);
    installPackedPlatformPackage(packageRoot, temp);
    smokeWrapperWithEmptyPath(packageRoot);
    smokeDirectNativeRuntimeWithEmptyPath(packageRoot);
    process.stdout.write(
      "extracted package wrapper and direct native runtime passed with an empty inherited PATH\n",
    );
  }
} finally {
  rmSync(temp, { recursive: true, force: true });
}

function assertMissingOptionalPackageMessage(packageRoot) {
  const wrapper = path.join(packageRoot, "bin", "kuzushi-rs.mjs");
  const result = spawnSync(process.execPath, [wrapper, "--version"], {
    cwd: packageRoot,
    encoding: "utf8",
    env: isolatedNativeEnvironment(packageRoot),
  });
  const platformPackage = nativePlatformPackage();
  if (result.status !== 127 || !result.stderr.includes(platformPackage.packageName)) {
    throw new Error(
      `missing optional package must produce an actionable ${platformPackage.packageName} error: ${result.stderr}`,
    );
  }
}

function assertPackedManifestSurface(packageRoot) {
  const manifest = JSON.parse(readFileSync(path.join(packageRoot, "package.json"), "utf8"));
  if (
    manifest.dependencies?.["better-sqlite3"] ||
    manifest.devDependencies?.["@types/better-sqlite3"]
  ) {
    throw new Error("packed runtime must not require better-sqlite3 or its ambient types");
  }
  if (manifest.types !== undefined) {
    throw new Error("packed runtime must not declare a TypeScript library surface");
  }
  process.stdout.write("packed manifest surface checked (CLI-only, no TS library surface)\n");
}

function createPackageArchive(packageDir, destination) {
  const result = run(
    "npm",
    ["pack", packageDir, "--ignore-scripts", "--json", "--pack-destination", destination],
    { cwd: root, capture: true },
  );
  const packed = JSON.parse(result.stdout);
  if (typeof packed[0]?.filename !== "string") {
    throw new Error("npm pack did not report an archive filename");
  }
  return packed[0];
}

function installPackedPlatformPackage(packageRoot, temp) {
  const platformPackage = nativePlatformPackage();
  if (!platformPackage) {
    throw new Error(`no platform package contract for ${process.platform}-${process.arch}`);
  }
  const nativeDir = path.join(root, "native", platformPackage.slug);
  if (!existsSync(nativeDir)) {
    throw new Error(`missing native/${platformPackage.slug}; run pnpm build:native first`);
  }

  const staging = path.join(temp, "platform-staging");
  mkdirSync(path.join(staging, "bin"), { recursive: true });
  cpSync(
    path.join(root, "npm", "platform-packages", platformPackage.slug, "package.json"),
    path.join(staging, "package.json"),
  );
  cpSync(nativeDir, path.join(staging, "bin"), { recursive: true });
  const packed = createPackageArchive(staging, temp);
  if (packed.size > PLATFORM_PACKED_BUDGET || packed.unpackedSize > PLATFORM_UNPACKED_BUDGET) {
    throw new Error(`${platformPackage.packageName} exceeds its package size budget`);
  }

  const extracted = path.join(temp, "platform-extracted");
  mkdirSync(extracted);
  run("tar", ["-xzf", path.join(temp, packed.filename), "-C", extracted], {
    cwd: root,
  });
  const dependencyRoot = path.join(
    packageRoot,
    "node_modules",
    "@kuzushi",
    platformPackage.packageName.split("/")[1],
  );
  mkdirSync(path.dirname(dependencyRoot), { recursive: true });
  renameSync(path.join(extracted, "package"), dependencyRoot);
}

function assertThinRootPackage(packageRoot) {
  if (existsSync(path.join(packageRoot, "native"))) {
    throw new Error("root kuzushi package must not contain native platform payloads");
  }
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
    env: isolatedNativeEnvironment(packageRoot),
  });
  assertMatchingVersion(version.stdout, manifest.version);

  run(process.execPath, [wrapper, "mcp", "health", "tree-sitter"], {
    cwd: packageRoot,
    capture: true,
    env: isolatedNativeEnvironment(packageRoot),
  });
}

function isolatedNativeEnvironment(readRoot) {
  const env = {
    ...process.env,
    PATH: "",
    KUZUSHI_MCP_READ_ROOTS: JSON.stringify([readRoot]),
  };
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
  const platformPackage = nativePlatformPackage();
  const runtimeDir = path.join(
    packageRoot,
    "node_modules",
    "@kuzushi",
    platformPackage.packageName.split("/")[1],
    "bin",
  );
  const cli = path.join(runtimeDir, nativeExecutableName("kuzushi"));
  run(cli, ["mcp", "health", "tree-sitter"], {
    cwd: packageRoot,
    capture: true,
    env: isolatedNativeEnvironment(packageRoot),
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

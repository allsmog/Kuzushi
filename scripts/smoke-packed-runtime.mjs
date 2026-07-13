#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { nativeExecutableName, nativePlatformSlug } from "./native-runtime-contract.mjs";

const root = process.cwd();
const temp = mkdtempSync(path.join(tmpdir(), "kuzushi-packed-runtime-"));
const omitNative = process.env.KUZUSHI_VERIFY_PACK_OMIT_NATIVE === "1";

try {
  const archive = createPackageArchive(temp);
  const extracted = path.join(temp, "extracted");
  mkdirSync(extracted);
  run("tar", ["-xzf", archive, "-C", extracted], { cwd: root });

  const packageRoot = path.join(extracted, "package");
  assertPackagedBridge(packageRoot);
  smokePublicSdkTypes(packageRoot, temp);
  if (omitNative) {
    process.stdout.write("native runtime smoke skipped because native payload was omitted\n");
  } else {
    smokeWrapperWithEmptyPath(packageRoot);
    smokeDirectNativeRuntimeWithEmptyPath(packageRoot);
    process.stdout.write(
      "extracted package wrapper and direct native runtime passed with an empty inherited PATH\n",
    );
  }
} finally {
  rmSync(temp, { recursive: true, force: true });
}

function smokePublicSdkTypes(packageRoot, tempRoot) {
  const manifest = JSON.parse(readFileSync(path.join(packageRoot, "package.json"), "utf8"));
  assertNoSqliteDependency(manifest);
  const consumer = preparePackedConsumer(packageRoot, tempRoot, manifest.dependencies ?? {});
  typecheckPackedConsumer(consumer);
  process.stdout.write("packed kuzushi/modules and kuzushi/testing declarations typechecked\n");
}

function assertNoSqliteDependency(manifest) {
  if (
    manifest.dependencies?.["better-sqlite3"] ||
    manifest.devDependencies?.["@types/better-sqlite3"]
  ) {
    throw new Error("packed SDK consumer must not require better-sqlite3 or its ambient types");
  }
}

function preparePackedConsumer(packageRoot, tempRoot, dependencies) {
  const consumer = path.join(tempRoot, "consumer");
  const consumerModules = path.join(consumer, "node_modules");
  mkdirSync(consumerModules, { recursive: true });
  linkDirectory(packageRoot, path.join(consumerModules, "kuzushi"));
  linkConsumerDependencies(consumerModules, dependencies);
  writePackedConsumerFiles(consumer);
  return consumer;
}

function linkConsumerDependencies(consumerModules, dependencies) {
  for (const dependency of Object.keys(dependencies)) {
    const destination = path.join(consumerModules, ...dependency.split("/"));
    mkdirSync(path.dirname(destination), { recursive: true });
    linkDirectory(path.join(root, "node_modules", ...dependency.split("/")), destination);
  }
}

function writePackedConsumerFiles(consumer) {
  writeFileSync(
    path.join(consumer, "package.json"),
    JSON.stringify({ name: "kuzushi-packed-consumer", private: true, type: "module" }),
  );
  writeFileSync(path.join(consumer, "consumer.ts"), packedConsumerSource());
  writeFileSync(
    path.join(consumer, "tsconfig.json"),
    JSON.stringify({
      compilerOptions: {
        strict: true,
        noEmit: true,
        target: "ES2022",
        module: "NodeNext",
        moduleResolution: "NodeNext",
        preserveSymlinks: true,
        types: [],
      },
      include: ["consumer.ts"],
    }),
  );
}

function typecheckPackedConsumer(consumer) {
  const tsc = path.join(root, "node_modules", "typescript", "bin", "tsc");
  run(process.execPath, [tsc, "-p", path.join(consumer, "tsconfig.json")], {
    cwd: consumer,
    capture: true,
  });
}

function linkDirectory(source, destination) {
  symlinkSync(source, destination, process.platform === "win32" ? "junction" : "dir");
}

function packedConsumerSource() {
  return `
import { defineModule, type DagContext, type DagDatabase } from "kuzushi/modules";
import { assertToolResult, createMockToolContext } from "kuzushi/testing";

const db: DagDatabase = {
  prepare() {
    return {
      run: (...parameters: unknown[]) => ({ changes: parameters.length }),
      get: (...parameters: unknown[]) => parameters[0],
      all: (...parameters: unknown[]) => parameters,
    };
  },
};
const dag: DagContext = {
  runId: "packed-run",
  repoRoot: "/repo",
  repoName: "consumer",
  db,
  upstreamOutputs: new Map(),
};
const context = createMockToolContext({ dag });
assertToolResult({ ok: true, output: context.dag?.runId ?? "" }, { ok: true });
defineModule({
  id: "consumer",
  displayName: "Consumer",
  category: "defense",
  version: "1.0.0",
  description: "Exercises the packed declaration surface.",
  tools: [{
    name: "consumer:run",
    description: "Runs the consumer fixture.",
    inputSchema: { type: "object" },
    headless: true,
    async execute() { return { ok: true, output: "ok" }; },
  }],
});
`;
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

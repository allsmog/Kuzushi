#!/usr/bin/env node

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { relative, resolve } from "node:path";
import {
  PRIVATE_SOURCE_NEEDLE,
  parseCargoLock,
  RESOLVER_PACKAGES,
  resolverStubVersions,
} from "./public-core-cargo-lock.mjs";

const PRIVATE_SOURCE_URL = `https://${PRIVATE_SOURCE_NEEDLE}`;
const REVISION = "[0-9a-f]{40}";

function dependencyPattern(name) {
  const escapedUrl = PRIVATE_SOURCE_URL.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${name} = \\{ git = "${escapedUrl}", rev = "${REVISION}" \\}$`, "m");
}

function portablePath(path) {
  return path.replaceAll("\\", "/");
}

function replacePrivateDependency(manifest, name, stubPath) {
  const pattern = dependencyPattern(name);
  const matches = manifest.match(new RegExp(pattern.source, "gm")) ?? [];
  if (matches.length !== 1) {
    throw new Error(`Cargo.toml must contain one pinned private dependency line for ${name}`);
  }
  return manifest.replace(pattern, `${name} = { path = "${stubPath}" }`);
}

export function rewriteWorkspaceManifest(manifest, stubRoot) {
  const rewritten = RESOLVER_PACKAGES.reduce(
    (current, name) => replacePrivateDependency(current, name, portablePath(`${stubRoot}/${name}`)),
    manifest,
  );
  if (rewritten.includes(PRIVATE_SOURCE_NEEDLE)) {
    throw new Error("public-core Cargo.toml still contains the private source URL");
  }
  return rewritten;
}

function stubManifest(name, version) {
  return `[package]\nname = "${name}"\nversion = "${version}"\nedition = "2021"\npublish = false\n\n[lib]\npath = "lib.rs"\n`;
}

function writeResolverStub(stubsRoot, name, version) {
  const packageRoot = resolve(stubsRoot, name);
  mkdirSync(packageRoot, { recursive: true });
  writeFileSync(resolve(packageRoot, "Cargo.toml"), stubManifest(name, version));
  writeFileSync(
    resolve(packageRoot, "lib.rs"),
    "#![forbid(unsafe_code)]\n// Resolver-only stub; the public-core build never enables this dependency.\n",
  );
}

export function preparePublicCoreWorkspace(workspaceRoot, stubsRoot) {
  const manifestPath = resolve(workspaceRoot, "Cargo.toml");
  const lockPath = resolve(workspaceRoot, "Cargo.lock");
  const versions = resolverStubVersions(parseCargoLock(readFileSync(lockPath, "utf8")));
  const relativeStubRoot = portablePath(relative(workspaceRoot, stubsRoot));
  const manifest = rewriteWorkspaceManifest(readFileSync(manifestPath, "utf8"), relativeStubRoot);
  writeFileSync(manifestPath, manifest);
  for (const name of RESOLVER_PACKAGES) {
    writeResolverStub(stubsRoot, name, versions.get(name));
  }
  return { packages: RESOLVER_PACKAGES.length, stubRoot: relativeStubRoot };
}

function main() {
  const [workspaceRoot, stubsRoot] = process.argv.slice(2);
  if (!workspaceRoot || !stubsRoot) {
    throw new Error("usage: node scripts/public-core-workspace.mjs <workspace-root> <stubs-root>");
  }
  const result = preparePublicCoreWorkspace(workspaceRoot, stubsRoot);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1]?.endsWith("public-core-workspace.mjs")) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`public-core workspace preparation failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

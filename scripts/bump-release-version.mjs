#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const semverPattern = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export function bumpReleaseSources(sources, nextVersion) {
  if (!semverPattern.test(nextVersion)) {
    throw new Error(`release version must be SemVer without build metadata: ${nextVersion}`);
  }
  const manifest = JSON.parse(sources.packageJson);
  const currentVersion = manifest.version;
  assertCurrentVersions(sources, currentVersion);
  manifest.version = nextVersion;
  const cargoToml = replaceOnce(
    sources.cargoToml,
    `version = "${currentVersion}"`,
    `version = "${nextVersion}"`,
    "Cargo workspace version",
  );
  const dynamicHost = replaceOnce(
    sources.dynamicHost,
    `const HOST_PACKAGE_VERSION = "${currentVersion}";`,
    `const HOST_PACKAGE_VERSION = "${nextVersion}";`,
    "dynamic host version",
  );
  const workspacePackages = workspacePackageCount(sources.cargoToml);
  const cargoLock = replaceWorkspaceLockVersions(
    sources.cargoLock,
    currentVersion,
    nextVersion,
    workspacePackages,
  );
  return {
    packageJson: `${JSON.stringify(manifest, null, 2)}\n`,
    cargoToml,
    cargoLock,
    dynamicHost,
  };
}

function assertCurrentVersions(sources, currentVersion) {
  const expectedCargo = `version = "${currentVersion}"`;
  const expectedHost = `const HOST_PACKAGE_VERSION = "${currentVersion}";`;
  if (!sources.cargoToml.includes(expectedCargo)) {
    throw new Error("package.json and Cargo workspace versions are already inconsistent");
  }
  if (!sources.dynamicHost.includes(expectedHost)) {
    throw new Error("package.json and dynamic host versions are already inconsistent");
  }
}

function replaceWorkspaceLockVersions(source, currentVersion, nextVersion, expectedEntries) {
  const escaped = escapeRegExp(currentVersion);
  const pattern = new RegExp(
    `(\\[\\[package\\]\\]\\nname = "kuzushi(?:-[^"]*)?"\\nversion = ")${escaped}("\\n)`,
    "g",
  );
  let replacements = 0;
  const updated = source.replace(pattern, (_match, prefix, suffix) => {
    replacements += 1;
    return `${prefix}${nextVersion}${suffix}`;
  });
  if (replacements !== expectedEntries) {
    throw new Error(
      `Cargo.lock has ${replacements} Kuzushi workspace entries; expected ${expectedEntries}`,
    );
  }
  return updated;
}

function workspacePackageCount(cargoToml) {
  const count = cargoToml.match(/^\s*"crates\/kuzushi(?:-[^"]*)?",?$/gm)?.length ?? 0;
  if (count === 0) throw new Error("Cargo workspace has no Kuzushi package members");
  return count;
}

function replaceOnce(source, current, next, label) {
  const first = source.indexOf(current);
  if (first < 0 || source.indexOf(current, first + current.length) >= 0) {
    throw new Error(`${label} must occur exactly once`);
  }
  return `${source.slice(0, first)}${next}${source.slice(first + current.length)}`;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function readSources(root) {
  return {
    packageJson: readFileSync(path.join(root, "package.json"), "utf8"),
    cargoToml: readFileSync(path.join(root, "Cargo.toml"), "utf8"),
    cargoLock: readFileSync(path.join(root, "Cargo.lock"), "utf8"),
    dynamicHost: readFileSync(path.join(root, "scripts/kuzushi-dynamic-module-host.mjs"), "utf8"),
  };
}

function writeSources(root, sources) {
  writeFileSync(path.join(root, "package.json"), sources.packageJson);
  writeFileSync(path.join(root, "Cargo.toml"), sources.cargoToml);
  writeFileSync(path.join(root, "Cargo.lock"), sources.cargoLock);
  writeFileSync(path.join(root, "scripts/kuzushi-dynamic-module-host.mjs"), sources.dynamicHost);
}

function main() {
  const nextVersion = process.argv[2];
  if (!nextVersion || process.argv.length !== 3) {
    throw new Error("usage: node scripts/bump-release-version.mjs <semver>");
  }
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  writeSources(root, bumpReleaseSources(readSources(root), nextVersion));
  process.stdout.write(`release versions updated to ${nextVersion}; run pnpm check:release\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}

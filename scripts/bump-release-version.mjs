#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const semverPattern = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export function bumpReleaseSources(sources, nextVersion) {
  assertReleaseVersion(nextVersion);
  const manifest = JSON.parse(sources.packageJson);
  const currentVersion = manifest.version;
  assertCurrentVersions(sources, currentVersion);
  updateRootManifest(manifest, nextVersion);
  const platformPackages = updatePlatformManifests(
    sources.platformPackages,
    currentVersion,
    nextVersion,
  );
  const versionedText = updateVersionedTextSources(
    sources,
    currentVersion,
    nextVersion,
    platformPackages.length,
  );
  return {
    packageJson: `${JSON.stringify(manifest, null, 2)}\n`,
    platformPackages,
    ...versionedText,
  };
}

function updateVersionedTextSources(sources, currentVersion, nextVersion, platformPackageCount) {
  const pnpmLock = replaceExactCount(
    sources.pnpmLock,
    `specifier: ${currentVersion}`,
    `specifier: ${nextVersion}`,
    platformPackageCount,
    "pnpm platform package specifiers",
  );
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
    cargoToml,
    cargoLock,
    dynamicHost,
    pnpmLock,
  };
}

function assertReleaseVersion(nextVersion) {
  if (!semverPattern.test(nextVersion)) {
    throw new Error(`release version must be SemVer without build metadata: ${nextVersion}`);
  }
}

function updateRootManifest(manifest, nextVersion) {
  manifest.version = nextVersion;
  for (const packageName of Object.keys(manifest.optionalDependencies ?? {})) {
    if (packageName.startsWith("@kuzushi/")) {
      manifest.optionalDependencies[packageName] = nextVersion;
    }
  }
}

function updatePlatformManifests(sources, currentVersion, nextVersion) {
  return sources.map((source) => {
    const manifest = JSON.parse(source);
    if (manifest.version !== currentVersion) {
      throw new Error(`${manifest.name} and package.json versions are already inconsistent`);
    }
    manifest.version = nextVersion;
    return `${JSON.stringify(manifest, null, 2)}\n`;
  });
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

function replaceExactCount(source, current, next, expectedCount, label) {
  const actualCount = source.split(current).length - 1;
  if (actualCount !== expectedCount) {
    throw new Error(`${label} must occur exactly ${expectedCount} times; found ${actualCount}`);
  }
  return source.split(current).join(next);
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
    platformPackages: platformPackagePaths().map((relativePath) =>
      readFileSync(path.join(root, relativePath), "utf8"),
    ),
    pnpmLock: readFileSync(path.join(root, "pnpm-lock.yaml"), "utf8"),
  };
}

function writeSources(root, sources) {
  writeFileSync(path.join(root, "package.json"), sources.packageJson);
  writeFileSync(path.join(root, "Cargo.toml"), sources.cargoToml);
  writeFileSync(path.join(root, "Cargo.lock"), sources.cargoLock);
  writeFileSync(path.join(root, "scripts/kuzushi-dynamic-module-host.mjs"), sources.dynamicHost);
  writeFileSync(path.join(root, "pnpm-lock.yaml"), sources.pnpmLock);
  platformPackagePaths().forEach((relativePath, index) => {
    writeFileSync(path.join(root, relativePath), sources.platformPackages[index]);
  });
}

function platformPackagePaths() {
  return ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64", "win32-x64"].map(
    (slug) => `npm/platform-packages/${slug}/package.json`,
  );
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

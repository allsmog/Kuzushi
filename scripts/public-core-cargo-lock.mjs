#!/usr/bin/env node

import { readFileSync } from "node:fs";

export const PRIVATE_SOURCE_NEEDLE = "github.com/allsmog/oxidized-joern.git";
export const RESOLVER_PACKAGES = Object.freeze([
  "cpg-analysis",
  "cpg-cli",
  "cpg-core",
  "cpg-incremental",
]);
const RESOLVER_PACKAGE_SET = new Set(RESOLVER_PACKAGES);

function decodeTomlString(value) {
  return JSON.parse(`"${value}"`);
}

function stringField(block, name) {
  const match = block.match(new RegExp(`^${name} = "((?:\\\\.|[^"])*)"$`, "m"));
  return match ? decodeTomlString(match[1]) : undefined;
}

export function parseCargoLock(text) {
  const firstPackage = text.indexOf("[[package]]");
  if (firstPackage === -1) throw new Error("Cargo lock contains no package records");

  return text
    .slice(firstPackage)
    .split(/\n(?=\[\[package\]\]\n)/)
    .map((block) => {
      const name = stringField(block, "name");
      const version = stringField(block, "version");
      if (!name || !version) throw new Error("Cargo lock package is missing name or version");
      return {
        name,
        version,
        source: stringField(block, "source"),
        checksum: stringField(block, "checksum"),
      };
    });
}

function identity(pkg) {
  return JSON.stringify([pkg.name, pkg.version, pkg.source ?? null, pkg.checksum ?? null]);
}

function privatePackages(packages) {
  return packages.filter((pkg) => pkg.source?.includes(PRIVATE_SOURCE_NEEDLE));
}

export function resolverStubVersions(packages) {
  return new Map(
    RESOLVER_PACKAGES.map((name) => {
      const matches = privatePackages(packages).filter((pkg) => pkg.name === name);
      if (matches.length !== 1) {
        throw new Error(`full Cargo.lock must contain one pinned private package for ${name}`);
      }
      return [name, matches[0].version];
    }),
  );
}

function isResolverStub(pkg, versions) {
  return (
    RESOLVER_PACKAGE_SET.has(pkg.name) &&
    pkg.version === versions.get(pkg.name) &&
    !pkg.source &&
    !pkg.checksum
  );
}

function privateSourceErrors(originalPrivate, publicPackages) {
  const errors = [];
  if (originalPrivate.length === 0) {
    errors.push("full Cargo.lock contains no pinned oxidized-joern packages");
  }
  const leaked = privatePackages(publicPackages).map(({ name }) => name);
  if (leaked.length > 0) {
    errors.push(`public lock still resolves private packages: ${leaked.join(", ")}`);
  }
  return errors;
}

function resolverStubErrors(publicPackages, versions) {
  return RESOLVER_PACKAGES.flatMap((name) => {
    const matches = publicPackages.filter(
      (pkg) => pkg.name === name && isResolverStub(pkg, versions),
    );
    return matches.length === 1
      ? []
      : [`public lock must contain one local resolver stub for ${name}`];
  });
}

function externalDriftErrors(original, publicPackages, versions) {
  const originalIdentities = new Set(original.map(identity));
  return publicPackages.flatMap((pkg) => {
    if (isResolverStub(pkg, versions) || originalIdentities.has(identity(pkg))) return [];
    return [
      `public lock introduced or changed external package ${pkg.name} ${pkg.version} (${pkg.source ?? "path"})`,
    ];
  });
}

function droppedPathPackageErrors(original, publicPackages) {
  const publicIdentities = new Set(publicPackages.map(identity));
  return original.flatMap((pkg) => {
    if (pkg.source || RESOLVER_PACKAGE_SET.has(pkg.name)) return [];
    return publicIdentities.has(identity(pkg))
      ? []
      : [`public lock dropped workspace/path package ${pkg.name} ${pkg.version}`];
  });
}

export function validatePublicCoreLock(originalText, publicText) {
  const original = parseCargoLock(originalText);
  const publicPackages = parseCargoLock(publicText);
  const versions = resolverStubVersions(original);
  const originalPrivate = privatePackages(original);
  const errors = [
    ...privateSourceErrors(originalPrivate, publicPackages),
    ...resolverStubErrors(publicPackages, versions),
    ...externalDriftErrors(original, publicPackages, versions),
    ...droppedPathPackageErrors(original, publicPackages),
  ];
  if (errors.length > 0) throw new Error(errors.join("; "));

  return {
    originalPackages: original.length,
    publicPackages: publicPackages.length,
    removedPrivatePackages: originalPrivate.length,
    resolverStubs: RESOLVER_PACKAGES.length,
  };
}

function main() {
  const [originalPath, publicPath] = process.argv.slice(2);
  if (!originalPath || !publicPath) {
    throw new Error("usage: node scripts/public-core-cargo-lock.mjs <full-lock> <public-lock>");
  }
  const result = validatePublicCoreLock(
    readFileSync(originalPath, "utf8"),
    readFileSync(publicPath, "utf8"),
  );
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1]?.endsWith("public-core-cargo-lock.mjs")) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`public-core Cargo lock validation failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

#!/usr/bin/env node

import { readFileSync } from "node:fs";

const PRIVATE_SOURCE_NEEDLE = "github.com/allsmog/oxidized-joern.git";
const RESOLVER_STUBS = new Set([
  "cpg-analysis",
  "cpg-cli",
  "cpg-core",
  "cpg-incremental",
]);

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

function isResolverStub(pkg) {
  return RESOLVER_STUBS.has(pkg.name) && pkg.version === "0.1.0" && !pkg.source;
}

export function validatePublicCoreLock(originalText, publicText) {
  const original = parseCargoLock(originalText);
  const publicPackages = parseCargoLock(publicText);
  const errors = [];
  const originalIdentities = new Set(original.map(identity));
  const publicIdentities = new Set(publicPackages.map(identity));
  const originalPrivate = original.filter((pkg) =>
    pkg.source?.includes(PRIVATE_SOURCE_NEEDLE),
  );

  if (originalPrivate.length === 0) {
    errors.push("full Cargo.lock contains no pinned oxidized-joern packages");
  }

  const leakedPrivate = publicPackages.filter((pkg) =>
    pkg.source?.includes(PRIVATE_SOURCE_NEEDLE),
  );
  if (leakedPrivate.length > 0) {
    errors.push(
      `public lock still resolves private packages: ${leakedPrivate
        .map(({ name }) => name)
        .join(", ")}`,
    );
  }

  for (const expected of RESOLVER_STUBS) {
    const matches = publicPackages.filter(
      (pkg) => pkg.name === expected && isResolverStub(pkg),
    );
    if (matches.length !== 1) {
      errors.push(`public lock must contain one local resolver stub for ${expected}`);
    }
  }

  for (const pkg of publicPackages) {
    if (isResolverStub(pkg)) continue;
    if (!originalIdentities.has(identity(pkg))) {
      errors.push(
        `public lock introduced or changed external package ${pkg.name} ${pkg.version} (${pkg.source ?? "path"})`,
      );
    }
  }

  for (const pkg of original) {
    if (pkg.source || RESOLVER_STUBS.has(pkg.name)) continue;
    if (!publicIdentities.has(identity(pkg))) {
      errors.push(`public lock dropped workspace/path package ${pkg.name} ${pkg.version}`);
    }
  }

  if (errors.length > 0) throw new Error(errors.join("; "));

  return {
    originalPackages: original.length,
    publicPackages: publicPackages.length,
    removedPrivatePackages: originalPrivate.length,
    resolverStubs: RESOLVER_STUBS.size,
  };
}

function main() {
  const [originalPath, publicPath] = process.argv.slice(2);
  if (!originalPath || !publicPath) {
    throw new Error(
      "usage: node scripts/public-core-cargo-lock.mjs <full-lock> <public-lock>",
    );
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

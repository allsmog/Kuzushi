#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  nativeExecutableName,
  nativePlatformPackages,
  nativeRuntimeBinaries,
} from "./native-runtime-contract.mjs";
import { packedInventoryFailures } from "./npm-pack-inventory-contract.mjs";
import { PLATFORM_PACKED_BUDGET, PLATFORM_UNPACKED_BUDGET } from "./release-artifact-contract.mjs";

const root = process.cwd();
const destination = path.resolve(root, process.env.KUZUSHI_NPM_PACK_DESTINATION ?? "dist/npm");
const verifyReleaseAssembly = process.env.KUZUSHI_VERIFY_PACK_RELEASE_ASSEMBLY === "1";

mkdirSync(destination, { recursive: true });
const packedPackages = [];

for (const platformPackage of nativePlatformPackages) {
  const nativeDir = path.join(root, "native", platformPackage.slug);
  if (!existsSync(nativeDir)) {
    if (verifyReleaseAssembly && platformPackage.required) {
      throw new Error(`release assembly is missing required native/${platformPackage.slug}`);
    }
    continue;
  }
  packedPackages.push(stageAndPack(platformPackage, nativeDir));
}

if (packedPackages.length === 0) {
  throw new Error("no native platform directories were available to package");
}

const manifestPath = path.join(destination, "platform-packages.json");
writeFileSync(manifestPath, `${JSON.stringify(packedPackages, null, 2)}\n`);
process.stdout.write(
  `packed ${packedPackages.length} platform package(s); manifest: ${manifestPath}\n`,
);

function stageAndPack(platformPackage, nativeDir) {
  const packageDir = path.join(root, "npm", "platform-packages", platformPackage.slug);
  const packageManifest = JSON.parse(readFileSync(path.join(packageDir, "package.json"), "utf8"));
  assertManifest(platformPackage, packageManifest);
  const executableNames = nativeRuntimeBinaries.map((binary) =>
    nativeExecutableName(binary, platformPackage.os),
  );
  assertNativeDirectory(platformPackage.slug, nativeDir, executableNames);
  stageNativeExecutables(platformPackage, packageDir, nativeDir, executableNames);
  const packed = runNpmPack(packageDir);
  assertPackedInventory(packageManifest.name, packed, executableNames);
  assertPackageBudgets(packageManifest.name, packed);
  return packageReceipt(platformPackage, packageManifest, packed);
}

function assertNativeDirectory(slug, nativeDir, executableNames) {
  const actualNames = readdirSync(nativeDir).sort();
  const expectedNames = [...executableNames].sort();
  if (JSON.stringify(actualNames) !== JSON.stringify(expectedNames)) {
    throw new Error(
      `native/${slug} must contain exactly ${expectedNames.join(", ")}; found ${actualNames.join(", ")}`,
    );
  }
  for (const executableName of expectedNames) {
    const stat = lstatSync(path.join(nativeDir, executableName));
    if (stat.isSymbolicLink() || !stat.isFile()) {
      throw new Error(`native/${slug}/${executableName} must be a regular file`);
    }
  }
}

function assertPackedInventory(packageName, packed, executableNames) {
  const expected = ["package.json", ...executableNames.map((name) => `bin/${name}`)].sort();
  const failures = packedInventoryFailures(packed, expected);
  if (failures.length > 0) {
    throw new Error(`${packageName} packed inventory is unsafe:\n- ${failures.join("\n- ")}`);
  }
}

function stageNativeExecutables(platformPackage, packageDir, nativeDir, executableNames) {
  const binDir = path.join(packageDir, "bin");
  rmSync(binDir, { recursive: true, force: true });
  mkdirSync(binDir, { recursive: true });
  for (const executableName of executableNames) {
    const destinationFile = path.join(binDir, executableName);
    copyFileSync(path.join(nativeDir, executableName), destinationFile);
    if (platformPackage.os !== "win32") chmodSync(destinationFile, 0o755);
  }
}

function assertPackageBudgets(packageName, packed) {
  if (packed.size > PLATFORM_PACKED_BUDGET) {
    throw new Error(`${packageName} packed size ${packed.size} exceeds ${PLATFORM_PACKED_BUDGET}`);
  }
  if (packed.unpackedSize > PLATFORM_UNPACKED_BUDGET) {
    throw new Error(
      `${packageName} unpacked size ${packed.unpackedSize} exceeds ${PLATFORM_UNPACKED_BUDGET}`,
    );
  }
}

function packageReceipt(platformPackage, packageManifest, packed) {
  return {
    name: packageManifest.name,
    version: packageManifest.version,
    slug: platformPackage.slug,
    required: platformPackage.required,
    filename: packed.filename,
    integrity: packed.integrity,
    size: packed.size,
    unpackedSize: packed.unpackedSize,
  };
}

function assertManifest(platformPackage, manifest) {
  const rootManifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
  assertExpectedManifestFields(platformPackage, manifest, rootManifest.version);
  assertManifestLibc(platformPackage, manifest);
  assertOptionalDependency(rootManifest, manifest);
}

function assertExpectedManifestFields(platformPackage, manifest, rootVersion) {
  const expectedFields = {
    name: platformPackage.packageName,
    version: rootVersion,
    os: [platformPackage.os],
    cpu: [platformPackage.cpu],
  };
  for (const [field, value] of Object.entries(expectedFields)) {
    if (JSON.stringify(manifest[field]) !== JSON.stringify(value)) {
      throw new Error(
        `${platformPackage.slug} package ${field} must be ${JSON.stringify(value)}; found ${JSON.stringify(manifest[field])}`,
      );
    }
  }
}

function assertManifestLibc(platformPackage, manifest) {
  if (
    platformPackage.libc &&
    JSON.stringify(manifest.libc) !== JSON.stringify([platformPackage.libc])
  ) {
    throw new Error(`${platformPackage.slug} package must declare libc ${platformPackage.libc}`);
  }
}

function assertOptionalDependency(rootManifest, manifest) {
  if (rootManifest.optionalDependencies?.[manifest.name] !== manifest.version) {
    throw new Error(`${manifest.name} must be an exact-version optional dependency of kuzushi`);
  }
}

function runNpmPack(packageDir) {
  const result = spawnSync(
    "npm",
    ["pack", packageDir, "--ignore-scripts", "--json", "--pack-destination", destination],
    { cwd: root, encoding: "utf8" },
  );
  assertNpmPackSucceeded(packageDir, result);
  return parseNpmPackResult(packageDir, result.stdout);
}

function assertNpmPackSucceeded(packageDir, result) {
  if (result.error || result.status !== 0) {
    const detail = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
    throw result.error ?? new Error(`npm pack failed for ${packageDir}: ${detail}`);
  }
}

function parseNpmPackResult(packageDir, stdout) {
  const packed = JSON.parse(stdout)[0];
  if (!packed?.filename || !packed.integrity) {
    throw new Error(`npm pack returned an incomplete result for ${packageDir}`);
  }
  return packed;
}

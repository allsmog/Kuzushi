#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";
import { nativePlatformPackages } from "./native-runtime-contract.mjs";
import { safePackedInventoryFailures } from "./npm-pack-inventory-contract.mjs";
import {
  artifactSizeFailures,
  createArtifactRecord,
  expectedArtifactSpecifications,
  verifyReleaseManifest,
  writeReleaseManifest,
} from "./release-artifact-contract.mjs";
import { createSourceArchive } from "./source-archive-contract.mjs";

const [outputArg, packagesArg, nativeArg, commitSha, version] = process.argv.slice(2);
if (!outputArg || !packagesArg || !nativeArg || !commitSha || !version) {
  throw new Error(
    "usage: build-release-artifacts.mjs <output> <packed-packages> <native-archives> <sha> <version>",
  );
}

const repo = process.cwd();
const output = path.resolve(outputArg);
const packagesDirectory = path.resolve(packagesArg);
const nativeDirectory = path.resolve(nativeArg);
assertVersion(version);
if (existsSync(output)) throw new Error(`release output already exists: ${output}`);
mkdirSync(path.dirname(output), { recursive: true });
const staging = mkdtempSync(path.join(path.dirname(output), ".release-candidate-"));

try {
  const records = buildRecords({
    repo,
    staging,
    packagesDirectory,
    nativeDirectory,
    commitSha,
    version,
  });
  writeReleaseManifest(staging, commitSha, version, records);
  verifyReleaseManifest(staging, commitSha, version);
  renameSync(staging, output);
  process.stdout.write(`assembled verified release candidate at ${output}\n`);
} finally {
  rmSync(staging, { recursive: true, force: true });
}

function buildRecords(context) {
  mkdirSync(path.join(context.staging, "packages"));
  mkdirSync(path.join(context.staging, "native"));
  mkdirSync(path.join(context.staging, "source"));
  return [
    buildRootPackage(context),
    ...buildPlatformPackages(context),
    ...buildNativeArchives(context),
    buildSource(context),
  ];
}

function buildRootPackage(context) {
  const packed = runNpmPack(context.repo, path.join(context.staging, "packages"));
  const specification = specificationFor(context.version, "root-npm");
  assertPackedMetadata(packed, specification, context.staging);
  const record = createArtifactRecord({
    directory: context.staging,
    specification,
    npmMetadata: packed,
  });
  assertReceiptMatches(record, packed);
  return record;
}

function buildPlatformPackages(context) {
  const receiptPath = path.join(context.packagesDirectory, "platform-packages.json");
  const receipts = JSON.parse(readFileSync(receiptPath, "utf8"));
  assertPlatformReceiptSet(receipts, context.version);
  return nativePlatformPackages.map((platform) => {
    const specification = specificationFor(context.version, "platform-npm", platform.slug);
    const receipt = receipts.find(({ slug }) => slug === platform.slug);
    copyRegularFile(
      path.join(context.packagesDirectory, receipt.filename),
      path.join(context.staging, specification.file),
    );
    const record = createArtifactRecord({
      directory: context.staging,
      specification,
      npmMetadata: receipt,
    });
    assertReceiptMatches(record, receipt);
    return record;
  });
}

function buildNativeArchives(context) {
  return nativePlatformPackages.map((platform) => {
    const specification = specificationFor(context.version, "native", platform.slug);
    copyRegularFile(
      path.join(context.nativeDirectory, path.basename(specification.file)),
      path.join(context.staging, specification.file),
    );
    return createArtifactRecord({ directory: context.staging, specification });
  });
}

function buildSource(context) {
  const specification = specificationFor(context.version, "source");
  createSourceArchive({
    repo: context.repo,
    commitSha: context.commitSha,
    output: path.join(context.staging, specification.file),
  });
  return createArtifactRecord({ directory: context.staging, specification });
}

function runNpmPack(repo, destination) {
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  const args = ["pack", repo, "--ignore-scripts", "--json", "--pack-destination", destination];
  const result = spawnSync(npm, args, { cwd: repo, encoding: "utf8" });
  assertSucceeded("npm pack", result);
  const [packed] = JSON.parse(result.stdout);
  const failures = safePackedInventoryFailures(packed);
  if (failures.length > 0)
    throw new Error(`root package inventory is unsafe:\n- ${failures.join("\n- ")}`);
  return packed;
}

function assertPackedMetadata(packed, specification, staging) {
  if (packed?.name !== specification.name || packed?.version !== specification.version) {
    throw new Error(`npm pack returned ${packed?.name}@${packed?.version}`);
  }
  const actualFile = path.join(staging, "packages", packed.filename ?? "");
  const expectedFile = path.join(staging, specification.file);
  if (actualFile !== expectedFile)
    throw new Error(`npm pack wrote unexpected file ${packed?.filename}`);
}

function assertPlatformReceiptSet(receipts, version) {
  if (!Array.isArray(receipts) || receipts.length !== nativePlatformPackages.length) {
    throw new Error(
      `platform receipt must contain exactly ${nativePlatformPackages.length} packages`,
    );
  }
  for (const platform of nativePlatformPackages) {
    const receipt = receipts.find(({ slug }) => slug === platform.slug);
    const expectedFile = path.basename(
      specificationFor(version, "platform-npm", platform.slug).file,
    );
    if (
      !receipt ||
      receipt.name !== platform.packageName ||
      receipt.version !== version ||
      receipt.filename !== expectedFile
    ) {
      throw new Error(`platform receipt is missing ${platform.packageName}@${version}`);
    }
  }
}

function assertReceiptMatches(record, receipt) {
  const failures = [
    ...(record.size === receipt.size ? [] : [`size ${receipt.size} does not match ${record.size}`]),
    ...(record.npmIntegrity === receipt.integrity
      ? []
      : [`integrity ${receipt.integrity} does not match ${record.npmIntegrity}`]),
    ...artifactSizeFailures(record),
  ];
  if (failures.length > 0) throw new Error(`${record.file}: ${failures.join("; ")}`);
}

function specificationFor(version, kind, slug) {
  const specification = expectedArtifactSpecifications(version).find(
    (candidate) => candidate.kind === kind && candidate.slug === (slug ?? null),
  );
  if (!specification)
    throw new Error(`missing artifact specification for ${kind}/${slug ?? "root"}`);
  return specification;
}

function copyRegularFile(source, destination) {
  const stat = lstatSync(source);
  if (stat.isSymbolicLink() || !stat.isFile())
    throw new Error(`artifact input must be a file: ${source}`);
  copyFileSync(source, destination);
}

function assertVersion(version) {
  const manifest = JSON.parse(readFileSync(path.join(process.cwd(), "package.json"), "utf8"));
  if (manifest.version !== version)
    throw new Error(`package version ${manifest.version} is not ${version}`);
}

function assertSucceeded(command, result) {
  if (!result.error && result.status === 0) return;
  const detail = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
  throw result.error ?? new Error(`${command} failed: ${detail}`);
}

#!/usr/bin/env node

import { readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { nativePlatformPackages, nativeRuntimePackages } from "./native-runtime-contract.mjs";
import {
  actionlintImageFailures,
  callGraphActionPinFailures,
  candidateWorkflowFailures,
  platformPublisherFailures,
  publisherWorkflowFailures,
} from "./release-workflow-contract.mjs";

const root = process.cwd();
const manifest = readJson("package.json");
const cargo = readText("Cargo.toml");
const toolchain = readText("rust-toolchain.toml");
const failures = [];

const cargoVersion = quotedTomlValue(cargo, "version");
const cargoRustVersion = quotedTomlValue(cargo, "rust-version");
const toolchainChannel = quotedTomlValue(toolchain, "channel");

if (manifest.version !== cargoVersion) {
  failures.push(
    `package.json version ${JSON.stringify(manifest.version)} must equal Cargo workspace version ${JSON.stringify(cargoVersion)}`,
  );
}
if (!rustToolchainSatisfiesMsrv(cargoRustVersion, toolchainChannel)) {
  failures.push(
    `rust-toolchain channel ${JSON.stringify(toolchainChannel)} must satisfy Cargo rust-version ${JSON.stringify(cargoRustVersion)}`,
  );
}

for (const workflow of [
  ".github/workflows/ci.yml",
  ".github/workflows/ci-full.yml",
  ".github/workflows/release-candidate.yml",
]) {
  checkWorkflowUsesToolchainFile(workflow);
}
checkNativeRuntimeContract();
checkDynamicHostVersion();
checkPlatformPackageVersions();
checkWorkspaceLockVersions();
checkReleaseWorkflows();
checkReleaseInstructions();

if (process.env.GITHUB_REF_TYPE === "tag") {
  const expectedTag = `v${manifest.version}`;
  if (process.env.GITHUB_REF_NAME !== expectedTag) {
    failures.push(
      `release tag ${JSON.stringify(process.env.GITHUB_REF_NAME)} must equal ${JSON.stringify(expectedTag)}`,
    );
  }
}

if (failures.length > 0) {
  process.stderr.write("release contract check failed:\n");
  for (const failure of failures) process.stderr.write(`- ${failure}\n`);
  process.exit(1);
}

process.stdout.write(
  `release contract check passed (${manifest.version}, Rust ${toolchainChannel})\n`,
);

function checkWorkflowUsesToolchainFile(relativePath) {
  const source = readText(relativePath);
  if (/\bRUST_VERSION\b/.test(source)) {
    failures.push(`${relativePath} must not duplicate the workspace Rust version in RUST_VERSION`);
  }
  if (/\btoolchain:\s*["']?\d+\.\d+/.test(source)) {
    failures.push(`${relativePath} must not pin a numeric Rust toolchain inline`);
  }
  const installsWorkspaceToolchain =
    /moonrepo\/setup-rust@(?:v1|[0-9a-f]{40})/.test(source) &&
    source.includes("inherit-toolchain: true");
  if (!installsWorkspaceToolchain) {
    failures.push(`${relativePath} must install Rust from rust-toolchain.toml`);
  }
}

function checkNativeRuntimeContract() {
  failures.push(
    ...nativePackageFailures(),
    ...mcpExposureFailures(),
    ...nativeHealthEntrypointFailures(),
  );
}

function nativeHealthEntrypointFailures() {
  return nativeRuntimePackages
    .filter(({ binaryName }) => binaryName.startsWith("kuzushi-mcp-"))
    .flatMap(({ packageName, binaryName }) => {
      const source = readText(`crates/${packageName}/src/main.rs`);
      const handlesHealth =
        source.includes('== "--health"') ||
        source.includes("exit_after_standalone_health_if_requested");
      return handlesHealth ? [] : [`${binaryName} must handle --health before stdio startup`];
    });
}

function checkDynamicHostVersion() {
  const host = readText("scripts/kuzushi-dynamic-module-host.mjs");
  const baked = host.match(/const HOST_PACKAGE_VERSION = ["']([^"']+)["']/)?.[1];
  if (baked !== manifest.version) {
    failures.push(
      `dynamic module host version ${JSON.stringify(baked)} must equal package.json version ${JSON.stringify(manifest.version)}`,
    );
  }
}

function checkPlatformPackageVersions() {
  for (const { slug, packageName } of nativePlatformPackages) {
    const platformManifest = readJson(`npm/platform-packages/${slug}/package.json`);
    if (platformManifest.name !== packageName || platformManifest.version !== manifest.version) {
      failures.push(`${slug} platform package must be ${packageName}@${manifest.version}`);
    }
    if (manifest.optionalDependencies?.[packageName] !== manifest.version) {
      failures.push(`${packageName} must be an exact-version optional dependency`);
    }
  }
}

function checkWorkspaceLockVersions() {
  const lock = readText("Cargo.lock");
  const members = [...cargo.matchAll(/^\s*"crates\/([^"]+)",?$/gm)].map((match) => match[1]);
  const lockedVersions = new Map(
    [...lock.matchAll(/\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"/g)].map((match) => [
      match[1],
      match[2],
    ]),
  );
  const mismatches = members.filter((member) => lockedVersions.get(member) !== manifest.version);
  failures.push(
    ...mismatches.map((member) =>
      "Cargo.lock workspace package ".concat(member, " must have version ", manifest.version),
    ),
  );
}

function checkReleaseInstructions() {
  const instructions = readText("RELEASING.md");
  const staged =
    "git add package.json pnpm-lock.yaml npm/platform-packages Cargo.toml Cargo.lock scripts/kuzushi-dynamic-module-host.mjs CHANGELOG.md RELEASING.md";
  if (!instructions.includes(staged)) {
    failures.push("RELEASING.md must stage every release-version source and CHANGELOG.md");
  }
}

function checkReleaseWorkflows() {
  const workflowPaths = [
    ".github/workflows/release-candidate.yml",
    ".github/workflows/release.yml",
    ".github/workflows/ci-full.yml",
    ".github/workflows/published-release-smoke.yml",
  ];
  const workflows = workflowPaths.map((name) => ({ name, source: readText(name) }));
  const [candidate, publisher, fullCi, publishedSmoke] = workflows.map(({ source }) => source);
  failures.push(
    ...candidateWorkflowFailures(candidate),
    ...publisherWorkflowFailures(publisher),
    ...platformPublisherFailures(readText("scripts/publish-platform-packages.mjs")),
    ...callGraphActionPinFailures(workflows),
    ...actionlintImageFailures(fullCi),
    ...publishedSmokeFailures(publishedSmoke),
  );
}

function publishedSmokeFailures(source) {
  return ["ubuntu-24.04", "ubuntu-24.04-arm", "macos-15-intel", "macos-14", "windows-2025"]
    .filter((runner) => !source.includes(runner))
    .map((runner) => `published smoke must run on ${runner}`);
}

function nativePackageFailures() {
  return nativeRuntimePackages.flatMap(nativePackageFailuresFor);
}

function nativePackageFailuresFor({ packageName, binaryName }) {
  const packageManifest = readText(`crates/${packageName}/Cargo.toml`);
  const packageFailures = [];
  if (quotedTomlValue(packageManifest, "name") !== packageName) {
    packageFailures.push(
      `native runtime package ${packageName} must have a matching Cargo manifest`,
    );
  }
  const declaresBinary =
    packageManifest.includes("[[bin]]") && packageManifest.includes(`name = "${binaryName}"`);
  if (!declaresBinary) {
    packageFailures.push(`${packageName} must declare shipped binary ${binaryName}`);
  }
  return packageFailures;
}

function mcpExposureFailures() {
  const commandSource = readText("crates/kuzushi-cli/src/command/subcommands.rs");
  const exposed = new Set(commandSource.match(/"kuzushi-mcp-[a-z-]+"/g)?.map(unquote) ?? []);
  const shipped = new Set(
    nativeRuntimePackages
      .map(({ binaryName }) => binaryName)
      .filter((binaryName) => binaryName.startsWith("kuzushi-mcp-")),
  );
  return [
    ...setDifferenceFailures(exposed, shipped, "CLI exposes", "native runtime does not ship"),
    ...setDifferenceFailures(shipped, exposed, "native runtime ships", "CLI does not expose"),
  ];
}

function setDifferenceFailures(actual, expected, subject, mismatch) {
  return [...actual]
    .filter((binaryName) => !expected.has(binaryName))
    .map((binaryName) => `${subject} MCP binary ${binaryName} but the ${mismatch} it`);
}

function unquote(value) {
  return value.slice(1, -1);
}

function quotedTomlValue(source, key) {
  const pattern = new RegExp(`^${escapeRegExp(key)}\\s*=\\s*["']([^"']+)["']`, "m");
  return source.match(pattern)?.[1];
}

function rustToolchainSatisfiesMsrv(msrv, channel) {
  const minimum = numericVersion(msrv);
  const selected = numericVersion(channel);
  if (!minimum || !selected) return false;
  return numericVersionAtLeast(selected, minimum);
}

function numericVersionAtLeast(selected, minimum) {
  for (let index = 0; index < Math.max(minimum.length, selected.length); index += 1) {
    const selectedPart = selected[index] ?? 0;
    const minimumPart = minimum[index] ?? 0;
    if (selectedPart > minimumPart) return true;
    if (selectedPart < minimumPart) return false;
  }
  return true;
}

function numericVersion(value) {
  if (typeof value !== "string" || !/^\d+(?:\.\d+){1,2}$/.test(value)) return undefined;
  return value.split(".").map(Number);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function readText(relativePath) {
  try {
    return readFileSync(path.join(root, relativePath), "utf8");
  } catch (error) {
    failures.push(`${relativePath} must be readable: ${error.message}`);
    return "";
  }
}

function readJson(relativePath) {
  const source = readText(relativePath);
  try {
    return JSON.parse(source);
  } catch (error) {
    failures.push(`${relativePath} must be valid JSON: ${error.message}`);
    return {};
  }
}

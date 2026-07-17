#!/usr/bin/env node

import { readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { nativeRuntimePackages } from "./native-runtime-contract.mjs";

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
  ".github/workflows/release.yml",
  ".github/workflows/benchmark-regression.yml",
]) {
  checkWorkflowUsesToolchainFile(workflow);
}
checkNativeRuntimeContract();
checkDynamicHostVersion();
checkNativeReleaseSmoke();

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
  if (!source.includes("moonrepo/setup-rust@v1") || !source.includes("inherit-toolchain: true")) {
    failures.push(`${relativePath} must install Rust from rust-toolchain.toml`);
  }
}

function checkNativeRuntimeContract() {
  failures.push(...nativePackageFailures(), ...mcpExposureFailures());
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

function checkNativeReleaseSmoke() {
  const workflow = readText(".github/workflows/release.yml");
  for (const token of [
    "node scripts/smoke-native-runtime.mjs",
    "cargo test -p kuzushi-core fs_atomic::tests",
    "cargo test -p kuzushi-core scan::subprocess::scan_cancellation::tests",
    "cargo test -p kuzushi-cli mcp::tests",
  ]) {
    if (!workflow.includes(token)) failures.push(`release workflow must run ${token}`);
  }
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

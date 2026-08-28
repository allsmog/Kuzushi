#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import process from "node:process";
import { pathToFileURL } from "node:url";
import {
  machineArchitecture,
  nodeArchitectureFailure,
  processIsTranslated,
  rosettaOverrideRequested,
  rosettaTranslationInstalled,
  smokeExecutionPlan,
} from "./local-tarball-smoke-contract.mjs";

const PACKAGE_NAME = "kuzushi";
const REQUIRED_DOCTOR_CHECKS = [
  "target",
  "config",
  "state",
  "findings-db",
  "cpg",
  "treesitter",
  "LangGraph bridge",
];

export function normalizePublishedVersion(value) {
  const normalized = String(value ?? "")
    .trim()
    .replace(/^v/, "");
  if (!/^[0-9][0-9A-Za-z.+-]*$/.test(normalized)) {
    throw new Error(`invalid published version ${JSON.stringify(value)}`);
  }
  return normalized;
}

/**
 * The leg's declared slug, when the caller pins one. A pinned slug is what lets
 * the darwin-x64 leg run on Apple silicon and still prove it installed the
 * Intel payload rather than whatever npm chose for the host.
 */
export function resolveSmokePlan(slug, host) {
  if (!slug?.trim()) return null;
  const allowRosetta = host.allowRosetta;
  const plan = smokeExecutionPlan({
    slug: slug.trim(),
    platform: host.platform,
    arch: machineArchitecture(host.nodeArch, host.translated),
    allowRosetta,
    rosettaInstalled: allowRosetta && host.rosettaInstalled(),
  });
  const failure = nodeArchitectureFailure(plan, host.nodeArch);
  if (failure) throw new Error(failure);
  return plan;
}

function currentSmokeHost() {
  const allowRosetta = rosettaOverrideRequested(process.env);
  return {
    platform: process.platform,
    nodeArch: process.arch,
    translated: processIsTranslated(),
    allowRosetta,
    rosettaInstalled: rosettaTranslationInstalled,
  };
}

export function installedCommandPath(prefix, command, platform = process.platform) {
  return platform === "win32"
    ? path.join(prefix, `${command}.cmd`)
    : path.join(prefix, "bin", command);
}

export function commandRequiresShell(platform = process.platform) {
  return platform === "win32";
}

export function parseJsonOutput(label, output) {
  try {
    return JSON.parse(output.trim());
  } catch (error) {
    throw new Error(`${label} did not emit JSON: ${error.message}\n${output}`);
  }
}

export function assertDoctorReport(report) {
  requireCondition(report?.summary?.fail === 0, "doctor reported a failing check");
  const healthy = new Set(
    (report?.checks ?? []).filter(({ status }) => status === "ok").map(({ name }) => name),
  );
  const missing = REQUIRED_DOCTOR_CHECKS.filter((name) => !healthy.has(name));
  requireCondition(missing.length === 0, `doctor lacks healthy checks: ${missing.join(", ")}`);
}

export function assertDemoReport(report) {
  requireCondition(report?.ok === true, "offline demo did not report success");
  requireCondition(report?.status === "completed", "offline demo did not complete");
  requireCondition(report?.findingsCount > 0, "offline demo produced no findings");
  requireCondition(report?.costUsd === 0, "offline demo incurred model cost");
  requireCondition(report?.errors?.length === 0, "offline demo reported errors");
}

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

function npmCommand() {
  return process.platform === "win32" ? "npm.cmd" : "npm";
}

function runCommand(label, command, args, options = {}) {
  process.stdout.write(`${label}...\n`);
  const result = spawnSync(command, args, {
    encoding: "utf8",
    shell: commandRequiresShell(),
    timeout: options.timeout ?? 300_000,
    cwd: options.cwd,
    env: options.env ?? process.env,
  });
  return successfulCommandOutput(label, result);
}

export function successfulCommandOutput(label, result) {
  if (result.error) throw result.error;
  if (result.status !== 0) throw commandFailure(label, result);
  return result.stdout;
}

function commandFailure(label, result) {
  return new Error(
    `${label} failed with exit ${result.status}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
}

function resolvePublishedVersion(explicitVersion) {
  if (explicitVersion?.trim()) return normalizePublishedVersion(explicitVersion);
  const output = runCommand("resolve npm latest", npmCommand(), [
    "view",
    PACKAGE_NAME,
    "dist-tags.latest",
    "--json",
  ]);
  return normalizePublishedVersion(parseJsonOutput("npm latest", output));
}

function isolatedCliEnvironment(home) {
  const environment = { ...process.env, HOME: home, USERPROFILE: home };
  environment.XDG_CONFIG_HOME = path.join(home, ".config");
  for (const name of ["KUZUSHI_MODEL", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"])
    delete environment[name];
  return environment;
}

function writeReceipt(receipt) {
  const outputPath = process.env.KUZUSHI_SMOKE_RECEIPT;
  if (outputPath) writeFileSync(outputPath, `${JSON.stringify(receipt, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

function prepareSmokeDirectories(root) {
  const paths = {
    prefix: path.join(root, "prefix"),
    target: path.join(root, "target"),
    home: path.join(root, "home"),
  };
  mkdirSync(paths.target);
  mkdirSync(paths.home);
  writeFileSync(path.join(paths.target, "package.json"), '{"name":"published-smoke-target"}\n');
  return paths;
}

function installPublishedPackage(version, prefix, environment) {
  const started = performance.now();
  runCommand(
    "install published package",
    npmCommand(),
    ["install", "--global", "--prefix", prefix, `${PACKAGE_NAME}@${version}`],
    { env: environment, timeout: 1_200_000 },
  );
  return Number(((performance.now() - started) / 1_000).toFixed(2));
}

function exerciseWrappers(version, prefix, commandOptions) {
  for (const command of ["kuzushi", "kz"]) {
    const executable = installedCommandPath(prefix, command);
    const output = runCommand(
      `exercise ${command} wrapper`,
      executable,
      ["--version"],
      commandOptions,
    );
    requireCondition(output.includes(version), `${command} wrapper reported the wrong version`);
  }
}

function collectCommandReports(kuzushi, target, commandOptions) {
  const doctor = parseJsonOutput(
    "doctor",
    runCommand("run doctor", kuzushi, ["doctor", "--target", target, "--json"], commandOptions),
  );
  assertDoctorReport(doctor);
  const demo = parseJsonOutput(
    "offline demo",
    runCommand("run offline demo", kuzushi, ["demo", "--json"], commandOptions),
  );
  assertDemoReport(demo);
  return { doctor, demo };
}

function smokePublishedRelease() {
  const plan = resolveSmokePlan(process.env.KUZUSHI_SMOKE_SLUG, currentSmokeHost());
  const version = resolvePublishedVersion(process.env.KUZUSHI_SMOKE_VERSION);
  const root = mkdtempSync(path.join(tmpdir(), "kuzushi-published-smoke-"));
  try {
    const { prefix, target, home } = prepareSmokeDirectories(root);
    const environment = isolatedCliEnvironment(home);
    const installSeconds = installPublishedPackage(version, prefix, environment);
    const commandOptions = { cwd: target, env: environment };
    exerciseWrappers(version, prefix, commandOptions);
    const kuzushi = installedCommandPath(prefix, "kuzushi");
    const { doctor, demo } = collectCommandReports(kuzushi, target, commandOptions);
    writeReceipt({
      version,
      platform: process.platform,
      arch: process.arch,
      ...(plan
        ? { hostSlug: plan.hostSlug, smokedSlug: plan.smokedSlug, translation: plan.translation }
        : {}),
      installSeconds,
      doctor: doctor.summary,
      demoFindings: demo.findingsCount,
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const entryUrl = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : "";
if (import.meta.url === entryUrl) {
  try {
    smokePublishedRelease();
  } catch (error) {
    process.stderr.write(`${error.stack ?? error}\n`);
    process.exitCode = 1;
  }
}

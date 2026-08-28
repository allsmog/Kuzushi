#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import {
  localConsumerManifest,
  rosettaOverrideRequested,
  rosettaTranslationInstalled,
  selectLocalTarballs,
  translatedCommand,
} from "./local-tarball-smoke-contract.mjs";
import { nativeExecutableName, nativeRuntimeBinaries } from "./native-runtime-contract.mjs";
import { verifyReleaseManifest } from "./release-artifact-contract.mjs";

const [directoryArg, commitSha, version, slug] = process.argv.slice(2);
if (!directoryArg || !commitSha || !version || !slug) {
  throw new Error("usage: smoke-release-tarballs.mjs <directory> <sha> <version> <platform-slug>");
}

const directory = path.resolve(directoryArg);
const manifest = verifyReleaseManifest(directory, commitSha, version);
const allowRosetta = rosettaOverrideRequested(process.env);
const selected = selectLocalTarballs(manifest, directory, slug, process.platform, process.arch, {
  allowRosetta,
  rosettaInstalled: allowRosetta && rosettaTranslationInstalled(),
});
const consumer = mkdtempSync(path.join(tmpdir(), `kuzushi-${slug}-consumer-`));

try {
  writeFileSync(
    path.join(consumer, "package.json"),
    `${JSON.stringify(localConsumerManifest(version, selected), null, 2)}\n`,
  );
  runNpmInstall(consumer);
  assertInstalledManifests(consumer, selected, version);
  const wrapper = path.join(consumer, "node_modules", "kuzushi", "bin", "kuzushi-rs.mjs");
  const versionResult = run(
    process.execPath,
    [wrapper, "--version"],
    consumer,
    isolatedEnvironment(consumer),
  );
  if (!versionResult.stdout.includes(version)) {
    throw new Error(
      `installed candidate reported the wrong version: ${versionResult.stdout.trim()}`,
    );
  }
  run(
    process.execPath,
    [wrapper, "mcp", "health", "tree-sitter"],
    consumer,
    isolatedEnvironment(consumer),
  );
  writeFileSync(
    path.join(process.cwd(), "local-tarball-smoke.json"),
    `${JSON.stringify({ commitSha, version, slug, hostSlug: selected.plan.hostSlug, smokedSlug: selected.plan.smokedSlug, translation: selected.plan.translation, root: selected.root.file, platform: selected.native.file }, null, 2)}\n`,
  );
  process.stdout.write(
    `local tarball install and runtime smoke passed for ${slug} on ${selected.plan.hostSlug} ` +
      `(translation: ${selected.plan.translation})\n`,
  );
} finally {
  rmSync(consumer, { recursive: true, force: true });
}

function runNpmInstall(consumer) {
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  run(
    npm,
    ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false"],
    consumer,
    process.env,
  );
}

function assertInstalledManifests(consumer, selected, version) {
  const root = installedManifest(consumer, "kuzushi");
  const platform = installedManifest(consumer, selected.native.name);
  if (root.version !== version || platform.version !== version) {
    throw new Error(`installed tarballs must both report ${version}`);
  }
  const binDirectory = path.join(
    consumer,
    "node_modules",
    ...selected.native.name.split("/"),
    "bin",
  );
  for (const binary of nativeRuntimeBinaries) {
    const executable = path.join(binDirectory, nativeExecutableName(binary));
    if (!readFileSync(executable))
      throw new Error(`installed platform package is missing ${binary}`);
  }
}

function installedManifest(consumer, packageName) {
  const segments = packageName.split("/");
  const file = path.join(consumer, "node_modules", ...segments, "package.json");
  return JSON.parse(readFileSync(file, "utf8"));
}

function isolatedEnvironment(readRoot) {
  const env = { ...process.env, PATH: "", KUZUSHI_MCP_READ_ROOTS: JSON.stringify([readRoot]) };
  delete env.KUZUSHI_NATIVE_BIN;
  for (const name of Object.keys(env)) {
    if (name.startsWith("KUZUSHI_MCP_") && name.endsWith("_BIN")) delete env[name];
  }
  return env;
}

function run(command, args, cwd, env) {
  // A translated plan must translate the launcher too, so a Rosetta leg can
  // never accidentally exercise the host architecture instead.
  const launched = translatedCommand(selected.plan, command, args);
  const result = spawnSync(launched.command, launched.args, { cwd, env, encoding: "utf8" });
  if (result.error || result.status !== 0) {
    const detail = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
    throw result.error ?? new Error(`${command} ${args.join(" ")} failed: ${detail}`);
  }
  return result;
}

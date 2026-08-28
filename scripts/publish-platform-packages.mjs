#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { verifyReleaseManifest } from "./release-artifact-contract.mjs";

const root = process.cwd();
const destination = path.resolve(root, process.env.KUZUSHI_RELEASE_DIRECTORY ?? "dist/release");
const releaseSha = requiredEnvironment("RELEASE_SHA");
const releaseVersion = requiredEnvironment("RELEASE_VERSION");
const manifest = verifyReleaseManifest(destination, releaseSha, releaseVersion);
const platformPackages = manifest.files.filter(({ kind }) => kind === "platform-npm");
const rootPackage = manifest.files.find(({ kind }) => kind === "root-npm");
if (!rootPackage) throw new Error("release manifest is missing the root npm package");
const packages = [...platformPackages, rootPackage];

run("npm", ["whoami"]);
run("npm", ["access", "list", "packages", "@kuzushi", "--json"]);

const states = packages.map((entry) => ({ entry, published: publishedIntegrity(entry) }));
for (const { entry, published } of states) {
  if (published === entry.npmIntegrity) {
    process.stdout.write(`reusing ${entry.name}@${entry.version} with matching integrity\n`);
    continue;
  }
  if (published) {
    throw new Error(
      `${entry.name}@${entry.version} already exists with integrity ${published}, expected ${entry.npmIntegrity}`,
    );
  }
  const args = [
    "publish",
    path.join(destination, entry.file),
    "--access",
    "public",
    "--tag",
    "latest",
    "--ignore-scripts",
  ];
  if (process.env.NPM_PROVENANCE === "true") args.push("--provenance");
  run("npm", args, { inherit: true });
}

function requiredEnvironment(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function publishedIntegrity(entry) {
  const result = spawnSync(
    "npm",
    ["view", `${entry.name}@${entry.version}`, "dist.integrity", "--json"],
    { cwd: root, encoding: "utf8" },
  );
  if (result.status === 0) return JSON.parse(result.stdout);
  const detail = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  if (/E404|404 Not Found|is not in this registry/i.test(detail)) return undefined;
  throw (
    result.error ?? new Error(`could not inspect ${entry.name}@${entry.version}: ${detail.trim()}`)
  );
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: options.inherit ? undefined : "utf8",
    stdio: options.inherit ? "inherit" : "pipe",
  });
  if (result.error || result.status !== 0) {
    const detail = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
    throw result.error ?? new Error(`${command} ${args.join(" ")} failed: ${detail}`);
  }
  return result;
}

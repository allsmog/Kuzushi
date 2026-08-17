#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const destination = path.resolve(root, process.env.KUZUSHI_NPM_PACK_DESTINATION ?? "dist/npm");
const packages = JSON.parse(readFileSync(path.join(destination, "platform-packages.json"), "utf8"));

run("npm", ["whoami"]);
run("npm", ["access", "list", "packages", "@kuzushi", "--json"]);

const states = packages.map((entry) => ({ entry, published: publishedIntegrity(entry) }));
for (const { entry, published } of states) {
  if (published === entry.integrity) {
    process.stdout.write(`reusing ${entry.name}@${entry.version} with matching integrity\n`);
    continue;
  }
  if (published) {
    throw new Error(
      `${entry.name}@${entry.version} already exists with integrity ${published}, expected ${entry.integrity}`,
    );
  }
  const args = ["publish", path.join(destination, entry.filename), "--access", "public"];
  if (process.env.NPM_PROVENANCE === "true") args.push("--provenance");
  run("npm", args, { inherit: true });
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

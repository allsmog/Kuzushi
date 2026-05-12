#!/usr/bin/env node
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

const repo = process.cwd();
const manifest = JSON.parse(readFileSync(path.join(repo, "package.json"), "utf8"));
const entries = manifest.files ?? [];
const includes = entries.filter((entry) => !entry.startsWith("!"));
const excludes = entries.filter((entry) => entry.startsWith("!")).map((entry) => entry.slice(1));

const denied = [
  /^\.kuzushi(?:\/|$)/,
  /^\.codex-active(?:\/|$)/,
  /^\.ralph(?:\/|$)/,
  /^.*\.sqlite3(?:-|$)/,
  /^.*\.db(?:-|$)/,
  /^target(?:\/|$)/,
];

const files = new Set(["package.json"]);
for (const entry of includes) {
  for (const file of walk(entry)) {
    if (!isExcluded(file)) {
      files.add(file);
    }
  }
}

const sorted = [...files].sort();
const offenders = sorted.filter((file) => denied.some((pattern) => pattern.test(file)));

if (offenders.length > 0) {
  process.stderr.write("package file allowlist includes local-only artifacts:\n");
  for (const offender of offenders) {
    process.stderr.write(`- ${offender}\n`);
  }
  process.exit(1);
}

process.stdout.write(
  JSON.stringify(
    {
      name: manifest.name,
      version: manifest.version,
      fileCount: sorted.length,
      lifecycleScripts: "not run",
    },
    null,
    2,
  ),
);
process.stdout.write("\npackage artifact check passed (no local state in package allowlist)\n");

function walk(rel) {
  const abs = path.join(repo, rel);
  if (!existsSync(abs)) {
    return [];
  }
  const stat = statSync(abs);
  if (stat.isFile()) {
    return [normalize(rel)];
  }
  if (!stat.isDirectory()) {
    return [];
  }
  return readdirSync(abs).flatMap((entry) => walk(path.join(rel, entry)));
}

function isExcluded(rel) {
  const normalized = normalize(rel);
  return excludes.some((exclude) => {
    const normalizedExclude = normalize(exclude);
    return normalized === normalizedExclude || normalized.startsWith(`${normalizedExclude}/`);
  });
}

function normalize(value) {
  return value.split(path.sep).join("/");
}

#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Extensions Biome parses under this repository's configuration. Tracked files
// with any other extension can sit inside `files.includes` and still be skipped
// as unknown types, so the pre-commit hook does not have to match them.
const BIOME_CHECKED_EXTENSIONS = new Set([
  "js",
  "mjs",
  "cjs",
  "jsx",
  "ts",
  "mts",
  "cts",
  "tsx",
  "json",
  "jsonc",
  "css",
  "graphql",
]);

// Glob metacharacters this checker does not implement. Rejecting them keeps a
// config change from silently widening Biome's surface past the hook's.
const UNSUPPORTED_GLOB_SYNTAX = /[{}[\]()?]/;

export function globToRegExp(pattern) {
  if (UNSUPPORTED_GLOB_SYNTAX.test(pattern)) {
    throw new Error(
      `unsupported glob syntax in "${pattern}"; teach scripts/check-format-hook-coverage.mjs about it`,
    );
  }
  let source = "";
  let index = 0;
  while (index < pattern.length) {
    const [expansion, width] = translateGlobToken(pattern, index);
    source += expansion;
    index += width;
  }
  return new RegExp(`^${source}$`);
}

export function matchesGlob(pattern, filePath) {
  const expression = globToRegExp(pattern);
  return ancestorPaths(filePath).some((candidate) => expression.test(candidate));
}

export function isCheckedByBiome(filePath, includes) {
  const extension = filePath.split(".").pop();
  if (!BIOME_CHECKED_EXTENSIONS.has(extension)) return false;
  const excluded = includes
    .filter((pattern) => pattern.startsWith("!"))
    .some((pattern) => matchesGlob(pattern.slice(1), filePath));
  if (excluded) return false;
  return includes
    .filter((pattern) => !pattern.startsWith("!"))
    .some((pattern) => matchesGlob(pattern, filePath));
}

export function hookCheckedExtensions(lintStaged) {
  const extensions = new Set();
  for (const [glob, tasks] of Object.entries(lintStaged)) {
    if (!runsBiomeCheck(tasks)) continue;
    for (const extension of globExtensions(glob)) extensions.add(extension);
  }
  return extensions;
}

export function uncoveredExtensions({ files, includes, lintStaged }) {
  const covered = hookCheckedExtensions(lintStaged);
  const examples = new Map();
  for (const file of files.filter((file) => isCheckedByBiome(file, includes))) {
    const extension = file.split(".").pop();
    if (covered.has(extension)) continue;
    const seen = examples.get(extension) ?? { count: 0, example: file };
    examples.set(extension, { count: seen.count + 1, example: seen.example });
  }
  return [...examples].sort(([left], [right]) => left.localeCompare(right));
}

function translateGlobToken(pattern, index) {
  if (pattern.startsWith("**/", index)) return ["(?:.*/)?", 3];
  if (pattern.startsWith("**", index)) return [".*", 2];
  if (pattern[index] === "*") return ["[^/]*", 1];
  return [pattern[index].replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), 1];
}

function ancestorPaths(filePath) {
  const segments = filePath.split("/");
  return segments.map((_, index) => segments.slice(0, index + 1).join("/"));
}

function runsBiomeCheck(tasks) {
  return [tasks].flat().some((task) => task.includes("biome check"));
}

function globExtensions(glob) {
  const braced = glob.match(/\.\{([^}]+)\}$/);
  if (braced) return braced[1].split(",").map((entry) => entry.trim());
  const single = glob.match(/\.([A-Za-z0-9]+)$/);
  if (single) return [single[1]];
  throw new Error(`cannot read file extensions from lint-staged glob "${glob}"`);
}

function main() {
  const inputs = readRepositoryInputs();
  const uncovered = uncoveredExtensions(inputs);
  if (uncovered.length > 0) {
    reportUncovered(uncovered);
    process.exit(1);
  }
  const covered = [...hookCheckedExtensions(inputs.lintStaged)].sort();
  console.log(`format hook coverage check passed for ${covered.join(", ")}`);
}

function readRepositoryInputs() {
  const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();
  const readJson = (file) => JSON.parse(readFileSync(path.join(root, file), "utf8"));
  const includes = readJson("biome.json").files?.includes;
  if (!Array.isArray(includes)) {
    throw new Error("biome.json declares no files.includes; cannot derive the checked surface");
  }
  return { files: trackedFiles(root), includes, lintStaged: readJson(".lintstagedrc.json") };
}

function reportUncovered(uncovered) {
  console.error("Pre-commit format coverage check failed:");
  for (const [extension, { count, example }] of uncovered) {
    console.error(
      `- .lintstagedrc.json runs no "biome check" task for .${extension} files, but Biome checks ${count} of them (for example ${example}); add ${extension} to that glob`,
    );
  }
}

function trackedFiles(root) {
  const output = execFileSync("git", ["ls-files"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  return output.split("\n").filter(Boolean);
}

const invokedDirectly = process.argv[1]
  ? fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
  : false;
if (invokedDirectly) main();

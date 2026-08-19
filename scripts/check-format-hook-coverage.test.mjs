import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  globToRegExp,
  hookCheckedExtensions,
  isCheckedByBiome,
  matchesGlob,
  uncoveredExtensions,
} from "./check-format-hook-coverage.mjs";

const repo = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const readJson = (file) => JSON.parse(readFileSync(path.join(repo, file), "utf8"));

const biomeTask = ["biome check --write --no-errors-on-unmatched"];
const formatOnlyTask = ["biome format --write --no-errors-on-unmatched"];

test("single-star segments never cross a path separator", () => {
  assert.equal(globToRegExp("*.json").test("package.json"), true);
  assert.equal(globToRegExp("*.json").test("scripts/package.json"), false);
  assert.equal(matchesGlob("*.json", "scripts/package.json"), false);
  assert.equal(matchesGlob("scripts/**", "scripts/nested/tool.mjs"), true);
  assert.equal(matchesGlob("benchmarks/**/repo", "benchmarks/repo"), true);
  assert.equal(matchesGlob("benchmarks/**/repo", "benchmarks/suite/repo"), true);
});

test("directory patterns exclude their descendants", () => {
  const includes = ["scripts/**", "!**/node_modules", "!**/*.generated.*"];
  assert.equal(isCheckedByBiome("scripts/tool.mjs", includes), true);
  assert.equal(isCheckedByBiome("scripts/node_modules/dep/index.mjs", includes), false);
  assert.equal(isCheckedByBiome("scripts/tool.generated.mjs", includes), false);
  assert.equal(isCheckedByBiome("crates/kuzushi-core/build.mjs", includes), false);
});

test("extensions Biome does not parse never demand hook coverage", () => {
  const includes = ["tests/**"];
  assert.equal(isCheckedByBiome("tests/fixtures/sample.c", includes), false);
  assert.equal(isCheckedByBiome("tests/fixtures/sample.toml", includes), false);
  assert.equal(isCheckedByBiome("tests/fixtures/sample.json", includes), true);
});

test("only globs whose tasks run biome check count as hook coverage", () => {
  const covered = hookCheckedExtensions({
    "*.{js,mjs}": biomeTask,
    "*.{md,yml}": formatOnlyTask,
    "*.jsonc": "biome check --write",
  });
  assert.deepEqual([...covered].sort(), ["js", "jsonc", "mjs"]);
});

test("unparseable lint-staged globs fail loudly instead of reporting coverage", () => {
  assert.throws(
    () => hookCheckedExtensions({ "scripts/**": biomeTask }),
    /cannot read file extensions/,
  );
});

test("unsupported glob syntax fails loudly instead of matching by accident", () => {
  assert.throws(() => globToRegExp("scripts/*.{mjs,js}"), /unsupported glob syntax/);
});

test("a Biome-checked extension missing from the hook is reported with an example", () => {
  const uncovered = uncoveredExtensions({
    files: ["scripts/a.mjs", "scripts/b.mjs", "scripts/c.json", "tests/fixtures/sample.c"],
    includes: ["scripts/**", "tests/**"],
    lintStaged: { "*.{js,json}": biomeTask },
  });
  assert.deepEqual(uncovered, [["mjs", { count: 2, example: "scripts/a.mjs" }]]);
});

test("the committed hook covers every extension the committed Biome gate checks", () => {
  const uncovered = uncoveredExtensions({
    files: ["scripts/check-secrets.mjs", "package.json", "tests/fixtures/secret-scan/clean/app.js"],
    includes: readJson("biome.json").files.includes,
    lintStaged: readJson(".lintstagedrc.json"),
  });
  assert.deepEqual(uncovered, []);
});

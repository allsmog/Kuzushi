import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { TYPESCRIPT_PROJECTS } from "./typescript-projects.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("aggregate typecheck contains every declared TypeScript project", () => {
  const packageJson = JSON.parse(readFileSync(resolve(repoRoot, "package.json"), "utf8"));
  const catalog = new Set(TYPESCRIPT_PROJECTS.map((project) => project.config));
  const declared = Object.entries(packageJson.scripts)
    .filter(([name]) => name === "typecheck" || name.startsWith("typecheck:"))
    .map(([, command]) => projectConfig(String(command)))
    .filter(Boolean);

  assert.deepEqual([...catalog].sort(), [
    "benchmarks/tsconfig.json",
    "perf/tsconfig.json",
    "scripts/codegen/tsconfig.json",
    "tsconfig.json",
  ]);
  for (const config of declared) assert.ok(catalog.has(config), `${config} missing from aggregate`);
  for (const config of catalog)
    assert.ok(existsSync(resolve(repoRoot, config)), `${config} missing`);
});

function projectConfig(command) {
  const match = command.match(/(?:^|\s)-p\s+(\S+)/);
  if (match) return match[1];
  return /^tsc(?:\s|$)/.test(command) ? "tsconfig.json" : null;
}

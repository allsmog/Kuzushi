#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export function discoverNodeTests(root) {
  return readdirSync(root, { withFileTypes: true })
    .flatMap((entry) => {
      const file = path.join(root, entry.name);
      if (entry.isDirectory()) return discoverNodeTests(file);
      return entry.isFile() && entry.name.endsWith(".test.mjs") ? [file] : [];
    })
    .sort();
}

export function runNodeTests(root) {
  const files = discoverNodeTests(root);
  if (files.length === 0) throw new Error(`No Node contract tests found under ${root}`);
  const result = spawnSync(process.execPath, ["--test", ...files], { stdio: "inherit" });
  if (result.error) throw result.error;
  return result.status ?? 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = runNodeTests(fileURLToPath(new URL("./", import.meta.url)));
}

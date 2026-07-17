#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { cargoReleaseBuildArgs } from "./native-runtime-contract.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const build = spawnSync("cargo", cargoReleaseBuildArgs(), {
  cwd: root,
  stdio: "inherit",
});

if (build.error) {
  process.stderr.write(`Could not start Cargo: ${build.error.message}\n`);
  process.exit(1);
}
if (build.status !== 0) process.exit(build.status ?? 1);

const stage = spawnSync(process.execPath, [join(root, "scripts", "stage-native-binary.mjs")], {
  cwd: root,
  stdio: "inherit",
});
if (stage.error) {
  process.stderr.write(`Could not stage the native runtime: ${stage.error.message}\n`);
  process.exit(1);
}
process.exit(stage.status ?? 1);

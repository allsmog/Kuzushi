#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  cargoReleaseBuildArgs,
  nativeSlugForTarget,
  resolveNativeTarget,
} from "./native-runtime-contract.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
// `--target <triple>` or `KUZUSHI_NATIVE_TARGET=<triple>` cross-builds one
// supported release platform; without either, this builds and stages the host.
const target = resolveNativeTarget(process.argv.slice(2), process.env);
if (target) {
  process.stdout.write(`cross-building the native runtime for ${nativeSlugForTarget(target)}\n`);
}

const build = spawnSync("cargo", cargoReleaseBuildArgs({ target }), {
  cwd: root,
  stdio: "inherit",
});

if (build.error) {
  process.stderr.write(`Could not start Cargo: ${build.error.message}\n`);
  process.exit(1);
}
if (build.status !== 0) process.exit(build.status ?? 1);

const stageArgs = [join(root, "scripts", "stage-native-binary.mjs")];
if (target) stageArgs.push("--target", target);
const stage = spawnSync(process.execPath, stageArgs, {
  cwd: root,
  stdio: "inherit",
});
if (stage.error) {
  process.stderr.write(`Could not stage the native runtime: ${stage.error.message}\n`);
  process.exit(1);
}
process.exit(stage.status ?? 1);

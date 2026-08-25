#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { cargoNativeBuildArgs, nativeExecutableName } from "./native-runtime-contract.mjs";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const separator = process.argv.indexOf("--");
const cliArgs = process.argv.slice(separator >= 0 ? separator + 1 : 2);

const build = spawnSync("cargo", cargoNativeBuildArgs(), {
  cwd: root,
  stdio: "inherit",
});
if (build.error) fail(`could not start Cargo: ${build.error.message}`);
if (build.status !== 0) process.exit(build.status ?? 1);

const cli = path.join(root, "target", "debug", nativeExecutableName("kuzushi"));
const run = spawnSync(cli, cliArgs, { cwd: root, stdio: "inherit" });
if (run.error) fail(`could not start Kuzushi: ${run.error.message}`);
process.exit(run.status ?? 1);

function fail(message) {
  process.stderr.write(`run-native-dev: ${message}\n`);
  process.exit(1);
}

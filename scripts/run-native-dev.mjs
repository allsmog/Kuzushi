#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { buildSourceRuntime, childExitCode } from "./source-native-runtime.mjs";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const separator = process.argv.indexOf("--");
const cliArgs = process.argv.slice(separator >= 0 ? separator + 1 : 2);

try {
  const cli = buildSourceRuntime(root);
  const run = spawnSync(process.execPath, [path.join(root, "bin", "kuzushi-rs.mjs"), ...cliArgs], {
    stdio: "inherit",
    env: { ...process.env, KUZUSHI_NATIVE_BIN: cli },
  });
  if (run.error) throw new Error(`Could not start Kuzushi: ${run.error.message}`);
  process.exit(childExitCode(run));
} catch (error) {
  process.stderr.write(`run-native-dev: ${error.message}\n`);
  process.exit(error.exitCode ?? 1);
}

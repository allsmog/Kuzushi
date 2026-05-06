#!/usr/bin/env node
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import process from "node:process";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const exe = process.platform === "win32" ? "kuzushi.exe" : "kuzushi";

const candidates = [
  process.env.KUZUSHI_NATIVE_BIN,
  join(root, "native", `${process.platform}-${process.arch}`, exe),
  join(root, "target", "release", exe),
  join(root, "target", "debug", exe),
].filter(Boolean);

const binary = candidates.find((candidate) => existsSync(candidate));
if (!binary) {
  process.stderr.write(
    "Could not find the Kuzushi native binary. Build it with `cargo build -p kuzushi-cli` or set KUZUSHI_NATIVE_BIN.\n",
  );
  process.exit(127);
}

const result = spawnSync(binary, process.argv.slice(2), {
  stdio: "inherit",
  env: process.env,
});

if (result.error) {
  process.stderr.write(`${result.error.message}\n`);
  process.exit(1);
}

process.exit(result.status ?? 0);

#!/usr/bin/env node
import { existsSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import process from "node:process";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const invokedName = basename(process.argv[1] || "kuzushi").replace(/\.cmd$/i, "");
const cliName = invokedName === "kz" ? "kz" : "kuzushi";
const exe = process.platform === "win32" ? `${cliName}.exe` : cliName;
const nativeOverride = process.env.KUZUSHI_NATIVE_BIN;

if (nativeOverride) {
  const overrideName = basename(nativeOverride).replace(/\.exe$/i, "");
  if (!existsSync(nativeOverride)) {
    process.stderr.write(`KUZUSHI_NATIVE_BIN points to missing file: ${nativeOverride}\n`);
    process.exit(127);
  }
  if (overrideName !== cliName) {
    process.stderr.write(
      `KUZUSHI_NATIVE_BIN must point to a ${exe} binary when invoked as ${cliName}; got ${nativeOverride}.\n`,
    );
    process.exit(127);
  }
}

const candidates = [
  nativeOverride,
  join(root, "native", `${process.platform}-${process.arch}`, exe),
  join(root, "target", "release", exe),
  join(root, "target", "debug", exe),
].filter(Boolean);

const binary = candidates.find((candidate) => existsSync(candidate));
if (!binary) {
  process.stderr.write(
    "Could not find the Kuzushi native binary. Expected native/<platform>-<arch>/kuzushi or native/<platform>-<arch>/kz, or a Cargo build output. Run `pnpm build:native`, run `cargo build -p kuzushi-cli`, or set KUZUSHI_NATIVE_BIN. Then check readiness with `kuzushi doctor --target .`.\n",
  );
  process.exit(127);
}

const result = spawnSync(binary, process.argv.slice(2), {
  stdio: "inherit",
  env: { ...process.env, KUZUSHI_CLI_NAME: process.env.KUZUSHI_CLI_NAME ?? cliName },
});

if (result.error) {
  process.stderr.write(`${result.error.message}\n`);
  process.exit(1);
}

process.exit(result.status ?? 0);

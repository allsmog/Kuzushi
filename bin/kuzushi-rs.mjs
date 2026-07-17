#!/usr/bin/env node
import { existsSync, statSync } from "node:fs";
import { constants as osConstants } from "node:os";
import { basename, delimiter, dirname, join } from "node:path";
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
  if (!statSync(nativeOverride).isFile()) {
    process.stderr.write(`KUZUSHI_NATIVE_BIN must point to a file: ${nativeOverride}\n`);
    process.exit(127);
  }
  if (overrideName !== "kuzushi" && overrideName !== "kz") {
    process.stderr.write(
      `KUZUSHI_NATIVE_BIN must point to a kuzushi or kz binary; got ${nativeOverride}.\n`,
    );
    process.exit(127);
  }
}

// The npm package ships one CLI binary per platform (`kuzushi`) alongside its
// MCP servers; `kz` resolves to that CLI and its displayed usage name comes
// from argv0. Cargo checkouts also use the single `kuzushi` CLI build output.
const fallbackExe = process.platform === "win32" ? "kuzushi.exe" : "kuzushi";
const candidates = [
  nativeOverride,
  join(root, "native", `${process.platform}-${process.arch}`, exe),
  join(root, "native", `${process.platform}-${process.arch}`, fallbackExe),
  join(root, "target", "release", exe),
  join(root, "target", "release", fallbackExe),
  join(root, "target", "debug", exe),
  join(root, "target", "debug", fallbackExe),
].filter(Boolean);

const binary = candidates.find(isNativeBinaryFile);
if (!binary) {
  process.stderr.write(
    "Could not find the Kuzushi native binary. Expected native/<platform>-<arch>/kuzushi or a Cargo build output. Run `pnpm build:native`, run `cargo build -p kuzushi-cli`, or set KUZUSHI_NATIVE_BIN. Then check readiness with `kuzushi doctor --target .`.\n",
  );
  process.exit(127);
}

const result = spawnSync(binary, process.argv.slice(2), {
  stdio: "inherit",
  argv0: cliName,
  env: {
    ...process.env,
    KUZUSHI_CLI_NAME: cliName,
    PATH: nativeRuntimePath(binary, process.env.PATH),
  },
});

if (result.error) {
  process.stderr.write(`${result.error.message}\n`);
  process.exit(1);
}

if (result.status === null) {
  const signal = result.signal ?? "unknown signal";
  process.stderr.write(`Kuzushi native binary terminated by ${signal}.\n`);
  process.exit(signalExitCode(result.signal));
}

process.exit(result.status);

function isNativeBinaryFile(candidate) {
  return existsSync(candidate) && statSync(candidate).isFile();
}

function nativeRuntimePath(binaryPath, inheritedPath) {
  const runtimeDir = dirname(binaryPath);
  return inheritedPath ? `${runtimeDir}${delimiter}${inheritedPath}` : runtimeDir;
}

function signalExitCode(signal) {
  if (typeof signal !== "string") return 1;
  const number = osConstants.signals[signal];
  return Number.isInteger(number) ? 128 + number : 1;
}

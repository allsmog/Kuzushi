#!/usr/bin/env node
// check-native-bindings.mjs — Verify the native bindings Kuzushi depends on
// load against the current Node version. If a rebuild is needed (e.g. the
// user upgraded Node major after install), attempt it once automatically.
//
// Wired as `postinstall` in package.json. Designed to never fail the install:
// any unrecoverable problem is printed to stderr with an actionable next step,
// then the script exits 0 so `pnpm install` doesn't break.
//
// Why this exists: better-sqlite3 ships per-Node-major prebuilds. When the
// user bumps from Node 22 → 24/25, the prebuild for the new ABI is missing
// and `require('better-sqlite3')` throws NODE_MODULE_VERSION mismatch errors.
// The shell silently aborts on any code path that opens index.sqlite3.

import { spawnSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function tryLoad(modName) {
  try {
    require(modName);
    return null;
  } catch (err) {
    return err;
  }
}

function logErr(msg) {
  process.stderr.write(`[kuzushi postinstall] ${msg}\n`);
}

function attemptRebuild(modName) {
  // Try `pnpm rebuild` first (we're a pnpm-managed project), then `npm rebuild`.
  for (const [cmd, args] of [
    ["pnpm", ["rebuild", modName]],
    ["npm", ["rebuild", modName]],
  ]) {
    logErr(`Attempting: ${cmd} ${args.join(" ")}`);
    const result = spawnSync(cmd, args, { stdio: "inherit" });
    if (result.status === 0) {
      const retry = tryLoad(modName);
      if (!retry) return true;
      logErr(`${modName} still fails to load after ${cmd} rebuild — ${retry.message}`);
    } else if (result.error?.code === "ENOENT") {
      logErr(`${cmd} not found, trying next option...`);
    }
  }
  return false;
}

function isFile(path) {
  return existsSync(path) && statSync(path).isFile();
}

function nativeBinaryCandidates() {
  const cliName = process.platform === "win32" ? "kuzushi.exe" : "kuzushi";
  const aliasName = process.platform === "win32" ? "kz.exe" : "kz";
  const slug = `${process.platform}-${process.arch}`;
  return [
    process.env.KUZUSHI_NATIVE_BIN,
    join(root, "native", slug, cliName),
    join(root, "native", slug, aliasName),
    join(root, "target", "release", cliName),
    join(root, "target", "debug", cliName),
  ].filter(Boolean);
}

function checkNativeBinary() {
  if (nativeBinaryCandidates().some(isFile)) return true;

  const slug = `${process.platform}-${process.arch}`;
  logErr(`No Kuzushi native binary found for ${slug}.`);
  logErr(`Expected native/${slug}/kuzushi, a Cargo build output, or KUZUSHI_NATIVE_BIN.`);
  logErr(
    "The package can still install, but `kuzushi` will fail until a matching binary is available. Next: install a release that includes this platform, set KUZUSHI_NATIVE_BIN, or build from source with `pnpm build:native`.",
  );
  return false;
}

const NATIVE_DEPS = ["better-sqlite3"];
let recovered = true;

for (const dep of NATIVE_DEPS) {
  const err = tryLoad(dep);
  if (!err) continue;

  // The error message format from Node when ABI mismatches:
  //   "The module '...' was compiled against a different Node.js version using
  //    NODE_MODULE_VERSION X. This version of Node.js requires NODE_MODULE_VERSION Y."
  const isAbiMismatch = /NODE_MODULE_VERSION/.test(err.message);
  if (!isAbiMismatch) {
    logErr(`${dep} failed to load for an unexpected reason: ${err.message}`);
    logErr(`Skipping auto-rebuild — please file an issue if this persists.`);
    recovered = false;
    continue;
  }

  logErr(`${dep} ABI mismatch on Node ${process.version}. Attempting auto-rebuild...`);
  if (!attemptRebuild(dep)) {
    logErr(`Could not auto-rebuild ${dep}. Manual fix: cd to your install dir and run:`);
    logErr(`  pnpm rebuild ${dep}    # or: npm rebuild ${dep}`);
    recovered = false;
  } else {
    logErr(`${dep} rebuilt successfully for Node ${process.version}.`);
  }
}

recovered = checkNativeBinary() && recovered;

// Always exit 0 so `pnpm install` stays green even if rebuild fails.
// The user gets the actionable message via stderr above.
if (!recovered) {
  process.exit(0);
}

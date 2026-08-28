#!/usr/bin/env node
import { chmodSync, copyFileSync, existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";
import {
  cargoReleaseDir,
  nativeExecutableName,
  nativePlatformForSlug,
  nativePlatformSlug,
  nativeRuntimeBinaries,
  nativeSlugForTarget,
  resolveNativeTarget,
} from "./native-runtime-contract.mjs";

const root = process.cwd();
const target = resolveNativeTarget(process.argv.slice(2), process.env);
const slug = target ? nativeSlugForTarget(target) : nativePlatformSlug();
const targetPlatform = nativePlatformForSlug(slug);
// `kz` remains an argv0 alias of `kuzushi`; every executable dependency used
// by the CLI and agent bridge is otherwise shipped as a sibling.
const exes = nativeRuntimeBinaries.map((binary) => nativeExecutableName(binary, targetPlatform));
const retiredExes =
  targetPlatform === "win32"
    ? ["codex.exe", "kuzushi-ts.exe", "kz.exe"]
    : ["codex", "kuzushi-ts", "kz"];
const releaseDir = cargoReleaseDir(root, process.env, target);
const outDir = join(root, "native", slug);

for (const exe of exes) {
  const source = join(releaseDir, exe);
  if (!existsSync(source)) {
    process.stderr.write(
      `Missing ${source}. Run \`node scripts/build-native-runtime.mjs\` before staging the native package.\n`,
    );
    process.exit(1);
  }
}

mkdirSync(outDir, { recursive: true });
const allowedExes = new Set(exes);
for (const entry of readdirSync(outDir)) {
  if (allowedExes.has(entry)) continue;
  const stale = join(outDir, entry);
  rmSync(stale, { recursive: true, force: true });
  process.stdout.write(`removed uncontracted native payload ${stale}\n`);
}

for (const exe of retiredExes) {
  const stale = join(outDir, exe);
  if (existsSync(stale)) {
    rmSync(stale, { force: true });
    process.stdout.write(`removed stale ${stale}\n`);
  }
}

for (const exe of exes) {
  const destination = join(outDir, exe);
  copyFileSync(join(releaseDir, exe), destination);

  if (targetPlatform !== "win32" && process.platform !== "win32") {
    chmodSync(destination, 0o755);
  }

  process.stdout.write(`staged ${destination}\n`);
}

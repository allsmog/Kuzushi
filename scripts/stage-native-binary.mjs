#!/usr/bin/env node
import { chmodSync, copyFileSync, existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";

const root = process.cwd();
const exes =
  process.platform === "win32" ? ["kuzushi.exe", "kz.exe"] : ["kuzushi", "kz"];
const retiredExes =
  process.platform === "win32" ? ["codex.exe", "kuzushi-ts.exe"] : ["codex", "kuzushi-ts"];
const outDir = join(root, "native", `${process.platform}-${process.arch}`);

for (const exe of exes) {
  const source = join(root, "target", "release", exe);
  if (!existsSync(source)) {
    process.stderr.write(
      `Missing ${source}. Run \`cargo build -p kuzushi-cli --release\` before staging the native package.\n`,
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
  const source = join(root, "target", "release", exe);
  const destination = join(outDir, exe);
  copyFileSync(source, destination);

  if (process.platform !== "win32") {
    chmodSync(destination, 0o755);
  }

  process.stdout.write(`staged ${destination}\n`);
}

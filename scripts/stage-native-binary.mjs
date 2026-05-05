#!/usr/bin/env node
import { chmodSync, copyFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";

const root = process.cwd();
const exe = process.platform === "win32" ? "kuzushi.exe" : "kuzushi";
const source = join(root, "target", "release", exe);
const outDir = join(root, "native", `${process.platform}-${process.arch}`);
const destination = join(outDir, exe);

if (!existsSync(source)) {
  process.stderr.write(
    `Missing ${source}. Run \`cargo build -p kuzushi-cli --release\` before staging the native package.\n`,
  );
  process.exit(1);
}

mkdirSync(outDir, { recursive: true });
copyFileSync(source, destination);

if (process.platform !== "win32") {
  chmodSync(destination, 0o755);
}

process.stdout.write(`staged ${destination}\n`);

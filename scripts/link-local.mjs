#!/usr/bin/env node
// Link the complete source checkout, retaining the previous installation for restore.
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { linkCheckout, restoreInstallation } from "./local-install-link.mjs";
import { buildSourceRuntime } from "./source-native-runtime.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

try {
  const args = process.argv.slice(2);
  if (args.some((arg) => arg !== "--restore"))
    throw new Error("Usage: pnpm link:local [--restore]");
  const npmRoot = execFileSync("npm", ["root", "-g"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
  const packageRoot = join(npmRoot, "kuzushi");
  if (args.includes("--restore")) {
    restoreInstallation(packageRoot, repoRoot);
    process.stdout.write(`Restored the previous Kuzushi installation at ${packageRoot}.\n`);
  } else {
    buildSourceRuntime(repoRoot);
    const outcome = linkCheckout(packageRoot, repoRoot);
    process.stdout.write(`Global Kuzushi ${outcome.state}: ${repoRoot}\n`);
    process.stdout.write(
      outcome.backup
        ? `Previous installation: ${outcome.backup}\n`
        : "No prior installation was saved by this command.\n",
    );
    process.stdout.write("kuzushi and kz now check the source build before launching.\n");
    if (outcome.backup) process.stdout.write("Restore with pnpm link:local:restore.\n");
  }
} catch (error) {
  process.stderr.write(`link-local: ${error.message}\n`);
  process.exit(error.exitCode ?? 1);
}

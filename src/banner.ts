import chalk from "chalk";
import { spawn } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function playStartupSound(): void {
  try {
    const soundsDir = path.resolve(__dirname, "..", "assets", "sounds");
    const files = readdirSync(soundsDir).filter((f) => f.endsWith(".wav"));
    if (files.length === 0) return;
    const pick = files[Math.floor(Math.random() * files.length)];
    const filePath = path.join(soundsDir, pick);

    const cmd = process.platform === "darwin" ? "afplay" : process.platform === "linux" ? "aplay" : null;
    if (!cmd) return;

    const child = spawn(cmd, [filePath], { stdio: "ignore", detached: true });
    child.unref();
  } catch {
    // Best-effort — don't break startup if sound fails
  }
}

/**
 * Print the Kuzushi startup banner — ASCII logo above the title.
 */
export function printBanner(): void {
  playStartupSound();

  const rb = chalk.white.bold;
  const dim = chalk.dim;

  // Print ASCII logo with "Bismillah" quote to the right
  try {
    const logoPath = path.resolve(__dirname, "..", "assets", "ascii", "logo-color.txt");
    const logoLines = readFileSync(logoPath, "utf-8").split("\n");
    const quoteRow = Math.min(3, logoLines.length - 1);
    console.log("");
    for (let i = 0; i < logoLines.length; i++) {
      if (i === quoteRow) {
        process.stdout.write(logoLines[i] + "  " + dim(chalk.italic("\"Bismillah\"")) + "\n");
      } else {
        process.stdout.write(logoLines[i] + "\n");
      }
    }
  } catch {
    // Fallback: skip logo if file is missing
  }

  console.log("");
  console.log(rb("   ██╗  ██╗██╗   ██╗███████╗██╗   ██╗███████╗██╗  ██╗██╗"));
  console.log(rb("   ██║ ██╔╝██║   ██║╚══███╔╝██║   ██║██╔════╝██║  ██║██║"));
  console.log(rb("   █████╔╝ ██║   ██║  ███╔╝ ██║   ██║███████╗███████║██║"));
  console.log(rb("   ██╔═██╗ ██║   ██║ ███╔╝  ██║   ██║╚════██║██╔══██║██║"));
  console.log(rb("   ██║  ██╗╚██████╔╝███████╗╚██████╔╝███████║██║  ██║██║"));
  console.log(rb("   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝"));
  console.log("");
  console.log(chalk.white("   崩し ") + dim("— Agentic SAST Orchestration"));
  console.log("");
}

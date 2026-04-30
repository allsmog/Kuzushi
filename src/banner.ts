import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import chalk from "chalk";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Print the Kuzushi startup banner — ASCII logo above the title.
 */
export function printBanner(): void {
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
        process.stdout.write(`${logoLines[i]}  ${dim(chalk.italic('"Bismillah"'))}\n`);
      } else {
        process.stdout.write(`${logoLines[i]}\n`);
      }
    }
  } catch {
    // Cosmetic fallback: ASCII logo file may be missing in minimal installs
    // or when running from source without assets. The text banner below still renders.
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

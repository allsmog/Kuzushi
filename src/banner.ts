import chalk from "chalk";

/**
 * Print the Kuzushi startup banner — coral belt (red & white alternating
 * blocks) above the title, as worn by judo 9th/10th dan grandmasters.
 */
export function printBanner(): void {
  const r = chalk.bgRedBright.redBright;
  const w = chalk.bgWhite.white;
  const rb = chalk.redBright.bold;
  const dim = chalk.dim;

  // Coral belt — 2 rows, 53 visible chars (matches title width of 56 minus 3-space indent = 53).
  // Alternating red/white stripe segments. Knot hangs from center (col ~27).
  // 53 chars = r5 w4 r4 w4 r5 w4 r5 w4 r4 w4 r5 w5 = 53

  // Belt = 53 visible chars (+ 3-space indent = 56 total, matching title width).
  // Pattern: (r5 w4) x 5  then  r5 w3  = 25+20+5+3 = 53
  const beltRow =
    r("█████") + w("████") +
    r("█████") + w("████") +
    r("█████") + w("████") +
    r("█████") + w("████") +
    r("█████") + w("████") +
    r("█████") + w("███");

  // Knot center: col 27 of 53 => indent = 3 + 25 = 28 spaces before ▐██▌
  console.log("");
  console.log("   " + beltRow);
  console.log("   " + beltRow);
  console.log("                            " + r("▐") + w("██") + r("▌"));
  console.log("                           " + r("▐") + w("█") + r("▌") + " " + r("▐") + w("█") + r("▌"));
  console.log("                            " + r("▀") + w("▀") + "  " + r("▀") + w("▀"));
  console.log("");
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

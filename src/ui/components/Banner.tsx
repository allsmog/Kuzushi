/**
 * Kuzushi startup banner — coral belt (red & white alternating blocks)
 * above the title, as worn by judo 9th/10th dan grandmasters.
 * Ported from banner.ts to an Ink component.
 */
import React from "react";
import { Text, Box, Static } from "ink";
import chalk from "chalk";

export function Banner(): React.ReactElement {
  const r = chalk.bgRedBright.redBright;
  const w = chalk.bgWhite.white;
  const rb = chalk.redBright.bold;
  const dim = chalk.dim;

  const beltRow =
    r("█████") + w("████") +
    r("█████") + w("████") +
    r("█████") + w("████") +
    r("█████") + w("████") +
    r("█████") + w("████") +
    r("█████") + w("███");

  return (
    <Static items={["banner"]}>
      {() => (
        <Box key="banner" flexDirection="column">
          <Text>{""}</Text>
          <Text>{"   "}{beltRow}</Text>
          <Text>{"   "}{beltRow}</Text>
          <Text>{"                            "}{r("▐")}{w("██")}{r("▌")}</Text>
          <Text>{"                           "}{r("▐")}{w("█")}{r("▌")} {r("▐")}{w("█")}{r("▌")}</Text>
          <Text>{"                            "}{r("▀")}{w("▀")}{"  "}{r("▀")}{w("▀")}</Text>
          <Text>{""}</Text>
          <Text>{rb("   ██╗  ██╗██╗   ██╗███████╗██╗   ██╗███████╗██╗  ██╗██╗")}</Text>
          <Text>{rb("   ██║ ██╔╝██║   ██║╚══███╔╝██║   ██║██╔════╝██║  ██║██║")}</Text>
          <Text>{rb("   █████╔╝ ██║   ██║  ███╔╝ ██║   ██║███████╗███████║██║")}</Text>
          <Text>{rb("   ██╔═██╗ ██║   ██║ ███╔╝  ██║   ██║╚════██║██╔══██║██║")}</Text>
          <Text>{rb("   ██║  ██╗╚██████╔╝███████╗╚██████╔╝███████║██║  ██║██║")}</Text>
          <Text>{rb("   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝")}</Text>
          <Text>{""}</Text>
          <Text>{chalk.white("   崩し ")} {dim("— Agentic SAST Orchestration")}</Text>
          <Text>{""}</Text>
        </Box>
      )}
    </Static>
  );
}

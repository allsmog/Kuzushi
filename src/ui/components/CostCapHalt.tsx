/**
 * Cost-cap halt card — shown when the pipeline's running cost crosses
 * the operator's configured budget. The scan pauses; the operator
 * chooses to continue (`c`) at their own cost or abort (`a`).
 *
 * Phase B.4. The card is pure presentation — the host wires `c` / `a`
 * to `store.update({ costCapHalted: false })` + the existing
 * `shell.onAbort` handler respectively.
 */

import { Box, Text } from "ink";
import type React from "react";
import { icons } from "../icons.js";
import { tokens } from "../tokens.js";

interface CostCapHaltProps {
  runningCostUsd: number;
  budgetUsd?: number;
}

export function CostCapHalt({ runningCostUsd, budgetUsd }: CostCapHaltProps): React.ReactElement {
  const over = budgetUsd != null ? runningCostUsd - budgetUsd : 0;
  const width = 70;
  const bar = "\u2500".repeat(width - 12);

  return (
    <Box flexDirection="column" marginTop={1} marginBottom={1} paddingLeft={2}>
      <Text>
        {tokens.muted("\u256D\u2500 ")}
        {tokens.dangerStrong("BUDGET EXCEEDED")}
        {tokens.muted(` ${bar}\u256E`)}
      </Text>
      <Row>
        {tokens.label("spent")}
        {"  "}
        {tokens.dangerStrong(`$${runningCostUsd.toFixed(2)}`)}
        {budgetUsd != null
          ? tokens.muted(
              `  of $${budgetUsd.toFixed(2)} budget  (+$${Math.max(0, over).toFixed(2)} over)`,
            )
          : ""}
      </Row>
      <Row>{tokens.muted("The pipeline is paused. Continuing will incur additional charges.")}</Row>
      <Text>{tokens.muted(`\u2570${"\u2500".repeat(width - 2)}\u256F`)}</Text>
      <Box marginTop={1}>
        <Text>
          {tokens.hint("  press ")}
          {tokens.strong("c")}
          {tokens.hint(" to continue   ")}
          {tokens.strong("a")}
          {tokens.hint(" to abort   ")}
          {tokens.muted(icons.warning)}
          {tokens.hint(" this bypasses the budget cap until the next run")}
        </Text>
      </Box>
    </Box>
  );
}

function Row({ children }: { children: React.ReactNode }): React.ReactElement {
  return (
    <Text>
      {tokens.muted("\u2502 ")}
      {children}
    </Text>
  );
}

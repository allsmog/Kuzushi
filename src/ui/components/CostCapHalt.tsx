/**
 * Cost-cap halt card — shown when the pipeline's running cost crosses
 * the operator's configured budget. The scan pauses; the operator
 * chooses to continue (`c`) at their own cost or abort (`a`).
 *
 * Phase B.4. Workstream 3 tightened the copy: the card now always
 * shows `spent / cap (+over)` as its first row, calls out the two
 * keys with their exact semantics, and warns that continuing bypasses
 * the cap for the rest of the run (until the next invocation resets
 * the budget).
 *
 * The card is pure presentation — the host wires `c` / `a` to
 * `store.update({ costCapHalted: false })` + the existing
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
  const over = budgetUsd != null ? Math.max(0, runningCostUsd - budgetUsd) : 0;
  const pct =
    budgetUsd != null && budgetUsd > 0
      ? Math.round((runningCostUsd / budgetUsd) * 100)
      : undefined;
  const width = 70;
  const bar = "─".repeat(width - 12);

  return (
    <Box flexDirection="column" marginTop={1} marginBottom={1} paddingLeft={2}>
      <Text>
        {tokens.muted("╭─ ")}
        {tokens.dangerStrong("BUDGET EXCEEDED")}
        {tokens.muted(` ${bar}╮`)}
      </Text>
      <Row>
        {tokens.label("spent")}
        {"  "}
        {tokens.dangerStrong(`$${runningCostUsd.toFixed(2)}`)}
        {budgetUsd != null
          ? tokens.muted(
              `  of $${budgetUsd.toFixed(2)} cap  (+$${over.toFixed(2)} over${
                pct != null ? `, ${pct}%` : ""
              })`,
            )
          : tokens.muted("  (no cap set)")}
      </Row>
      <Row>
        {tokens.muted(
          "Pipeline paused. Continuing incurs additional charges — the cap is not re-enforced until the next run.",
        )}
      </Row>
      <Text>{tokens.muted(`╰${"─".repeat(width - 2)}╯`)}</Text>
      <Box marginTop={1}>
        <Text>
          {tokens.hint("  press ")}
          {tokens.strong("c")}
          {tokens.hint(" to continue (bypass cap for this run)    ")}
          {tokens.strong("a")}
          {tokens.hint(" to abort (stop the pipeline now)")}
        </Text>
      </Box>
      <Box>
        <Text>
          {tokens.hint(`  ${icons.warning} `)}
          {tokens.hint("raise --budget before the next run to avoid re-hitting this halt")}
        </Text>
      </Box>
    </Box>
  );
}

function Row({ children }: { children: React.ReactNode }): React.ReactElement {
  return (
    <Text>
      {tokens.muted("│ ")}
      {children}
    </Text>
  );
}

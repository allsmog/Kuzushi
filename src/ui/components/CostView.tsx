/**
 * Cost view — live cost breakdown with proportional bars.
 *
 * Shown as a tab during the running phase. Updates as results arrive.
 *
 *  Cost Breakdown ($2.47)
 *
 *    Triage    ████████████░░░░░░░░  $1.48  (60%)
 *    Verify    █████░░░░░░░░░░░░░░░  $0.62  (25%)
 *    PoC       ███░░░░░░░░░░░░░░░░░  $0.37  (15%)
 *
 *  Per-finding average: $0.059
 *  Budget remaining: $2.53 / $5.00
 */

import { Box, Text } from "ink";
import type React from "react";
import { formatCost, miniBarChart } from "../format.js";
import type { ResultLine } from "../state.js";
import { tokens } from "../tokens.js";

interface CostViewProps {
  results: ResultLine[];
  runningCostUsd: number;
  budget?: number;
}

export function CostView({ results, runningCostUsd, budget }: CostViewProps): React.ReactElement {
  // Accumulate per-phase costs from results
  let triageCost = 0;
  let verifyCost = 0;
  let pocCost = 0;

  for (const r of results) {
    const cost = r.costUsd ?? 0;
    if (r.kind === "triage") triageCost += cost;
    else if (r.kind === "verify") verifyCost += cost;
    else if (r.kind === "poc") pocCost += cost;
  }

  const totalCost = runningCostUsd > 0 ? runningCostUsd : triageCost + verifyCost + pocCost;
  const triageCount = results.filter((r) => r.kind === "triage").length;
  const perFinding = triageCount > 0 ? totalCost / triageCount : 0;

  const chartLines = miniBarChart([
    { label: "Triage", value: triageCost, color: tokens.accent },
    { label: "Verify", value: verifyCost, color: tokens.danger },
    { label: "PoC", value: pocCost, color: tokens.warn },
  ]);

  return (
    <Box flexDirection="column" paddingLeft={2} marginTop={1}>
      <Text>{tokens.label(`Cost Breakdown (${formatCost(totalCost)})`)}</Text>
      <Text>{""}</Text>

      {chartLines.length > 0 ? (
        chartLines.map((line, i) => (
          <Text key={i}>  {line}</Text>
        ))
      ) : (
        <Text>  {tokens.muted("No cost data yet...")}</Text>
      )}

      <Text>{""}</Text>

      {triageCount > 0 && (
        <Text>
          {tokens.muted("Per-finding average:")} {formatCost(perFinding)}
          {tokens.muted(`  (${triageCount} findings)`)}
        </Text>
      )}

      {budget != null && budget > 0 && (
        <Text>
          {tokens.muted("Budget remaining:")} {formatCost(Math.max(0, budget - totalCost))}
          {tokens.muted(` / ${formatCost(budget)}`)}
          {totalCost > budget * 0.8 && totalCost < budget
            ? tokens.warn("  ⚠ approaching limit")
            : totalCost >= budget
              ? tokens.danger("  ✗ exceeded")
              : ""}
        </Text>
      )}
    </Box>
  );
}

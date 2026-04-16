/**
 * Individual result line for triage/verify/PoC results.
 *
 * Renders:
 *   [1/142] ✗ TRUE POSITIVE (92%) $0.03 fingerprint12...
 *   [2/142] ✓ false positive (78%) $0.02 fingerprint34...
 *   [3/142] ✗ EXPLOITABLE $0.05 fingerprint56...
 *   [4/142] ⚙ GENERATED parsed $0.03 fingerprint78...
 *   [5/142] ✗ TRIAGE ERROR fingerprint90...
 */

import chalk from "chalk";
import { Text } from "ink";
import type React from "react";
import { colorVerdict, formatCost } from "../format.js";
import { icons } from "../icons.js";
import type { ResultLine as ResultLineData } from "../state.js";

interface ResultLineProps {
  data: ResultLineData;
}

export function ResultLine({ data }: ResultLineProps): React.ReactElement {
  const prefix = `  [${data.index}/${data.total}]`;
  const fingerprint = chalk.dim(`${data.fingerprint.slice(0, 12)}...`);
  const retry = data.attempts && data.attempts > 1 ? chalk.dim(` (retry #${data.attempts})`) : "";

  if (data.kind === "error") {
    const stage = data.errorStage?.toUpperCase() ?? "TRIAGE";
    return (
      <Text>
        {prefix} {chalk.red(`${icons.error} ${stage} ERROR`)}
        {retry} {fingerprint}
        {data.errorMessage ? `\n    ${chalk.dim(data.errorMessage.slice(0, 160))}` : ""}
      </Text>
    );
  }

  if (data.kind === "triage" && data.verdict) {
    const verdict = colorVerdict(data.verdict);
    const conf = chalk.dim(`(${((data.confidence ?? 0) * 100).toFixed(0)}%)`);
    const cost = data.costUsd && data.costUsd > 0 ? ` ${chalk.dim(formatCost(data.costUsd))}` : "";
    return (
      <Text>
        {prefix} {verdict} {conf}
        {cost}
        {retry} {fingerprint}
      </Text>
    );
  }

  if (data.kind === "verify") {
    const statusIcon = data.exploitable ? chalk.red(icons.error) : chalk.green(icons.success);
    const statusLabel = data.exploitable ? "EXPLOITABLE" : "not exploitable";
    const cost = data.costUsd && data.costUsd > 0 ? ` ${chalk.dim(formatCost(data.costUsd))}` : "";
    return (
      <Text>
        {prefix} {statusIcon} {statusLabel}
        {cost}
        {retry} {fingerprint}
      </Text>
    );
  }

  if (data.kind === "poc") {
    const statusIcon = data.skipped ? chalk.yellow(icons.pending) : chalk.cyan(icons.gear);
    const statusLabel = data.skipped ? "SKIPPED" : "GENERATED";
    const parsed = data.skipped ? "" : data.parsed ? " parsed" : " parse-error";
    const cost = data.costUsd && data.costUsd > 0 ? ` ${chalk.dim(formatCost(data.costUsd))}` : "";
    return (
      <Text>
        {prefix} {statusIcon} {statusLabel}
        {parsed}
        {cost}
        {retry} {fingerprint}
      </Text>
    );
  }

  return (
    <Text>
      {prefix} {fingerprint}
    </Text>
  );
}

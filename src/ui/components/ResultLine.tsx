/**
 * Individual result line for triage/verify/PoC results.
 *
 * Uses the unified `tokens` palette instead of direct chalk calls.
 * Leading indent is applied by the parent Box via paddingLeft in App.tsx.
 */

import { Text } from "ink";
import type React from "react";
import { colorVerdict, formatCost, statusBadge } from "../format.js";
import { icons } from "../icons.js";
import type { ResultLine as ResultLineData } from "../state.js";
import { accent, danger, muted, success, warn } from "../tokens.js";

interface ResultLineProps {
  data: ResultLineData;
}

export function ResultLine({ data }: ResultLineProps): React.ReactElement {
  const prefix = `  [${data.index}/${data.total}]`;
  const fingerprint = muted(`${data.fingerprint.slice(0, 12)}...`);
  const retry = data.attempts && data.attempts > 1 ? muted(` (retry #${data.attempts})`) : "";

  if (data.kind === "error") {
    const stage = data.errorStage?.toUpperCase() ?? "TRIAGE";
    const { icon, color } = statusBadge("result", "error");
    return (
      <Text>
        {prefix} {color(`${icon} ${stage} ERROR`)}
        {retry} {fingerprint}
        {data.errorMessage ? `\n    ${muted(data.errorMessage.slice(0, 160))}` : ""}
      </Text>
    );
  }

  if (data.kind === "triage" && data.verdict) {
    const verdict = colorVerdict(data.verdict);
    const conf = muted(`(${((data.confidence ?? 0) * 100).toFixed(0)}%)`);
    const cost = data.costUsd && data.costUsd > 0 ? ` ${muted(formatCost(data.costUsd))}` : "";
    return (
      <Text>
        {prefix} {verdict} {conf}
        {cost}
        {retry} {fingerprint}
      </Text>
    );
  }

  if (data.kind === "verify") {
    const statusIcon = data.exploitable ? danger(icons.error) : success(icons.success);
    const statusLabel = data.exploitable ? "EXPLOITABLE" : "not exploitable";
    const cost = data.costUsd && data.costUsd > 0 ? ` ${muted(formatCost(data.costUsd))}` : "";
    return (
      <Text>
        {prefix} {statusIcon} {statusLabel}
        {cost}
        {retry} {fingerprint}
      </Text>
    );
  }

  if (data.kind === "poc") {
    const statusIcon = data.skipped ? warn(icons.pending) : accent(icons.gear);
    const statusLabel = data.skipped ? "SKIPPED" : "GENERATED";
    const parsed = data.skipped ? "" : data.parsed ? " parsed" : " parse-error";
    const cost = data.costUsd && data.costUsd > 0 ? ` ${muted(formatCost(data.costUsd))}` : "";
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

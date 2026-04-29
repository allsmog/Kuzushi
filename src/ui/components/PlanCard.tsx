/**
 * PlanCard — renders a pending natural-language planner proposal.
 *
 * The shell calls `/plan "<english>"`; a small Haiku call translates the
 * request into a structured `ShellPlan` that lands on `shell.pendingPlan`.
 * This component renders it as a bordered card — reasoning line, option
 * diff table, unsupported-intent row, estimated deltas, and a `y/n/Esc`
 * hint at the bottom.
 *
 * It's pure presentation. The input handler in CopilotShell intercepts
 * `y` / `n` / Esc keys when `pendingPlan` is set, and dispatches through
 * the existing `shell.onInput` callback back to shell.ts which applies
 * or discards the plan.
 */

import { Box, Text } from "ink";
import type React from "react";
import { boxBottomLine, boxRowPrefix, boxTopLine } from "../format.js";
import { useTerminalCardWidth } from "../hooks.js";
import type { ShellPlan, ShellPlanChange } from "../state.js";
import { SPACING, tokens } from "../tokens.js";

interface PlanCardProps {
  plan: ShellPlan;
}

export function PlanCard({ plan }: PlanCardProps): React.ReactElement {
  const { changes, unsupported } = plan;
  const width = useTerminalCardWidth(78, 48);
  const optionWidth = Math.min(
    18,
    Math.max("option".length, ...changes.map((c) => c.option.length)),
  );
  const valueWidth = Math.max(10, Math.min(22, Math.floor((width - optionWidth - 18) / 2)));
  const whyWidth = Math.max(10, width - optionWidth - valueWidth * 2 - 12);
  const topLine = boxTopLine({
    width,
    left: `${tokens.metadata("─")}${tokens.label(" plan ")}${tokens.strong(plan.source)}`,
    right: `${tokens.muted(" ")}${tokens.muted(plan.toolName)}${tokens.muted(" ")}`,
  });

  return (
    <Box
      flexDirection="column"
      paddingLeft={SPACING.md}
      marginTop={SPACING.sm}
      marginBottom={SPACING.sm}
    >
      <Text>{topLine}</Text>

      <Row>
        {tokens.label("intent")}
        {"  "}
        {tokens.value(plan.reasoning || "(no summary)")}
      </Row>

      {changes.length === 0 ? (
        <Row>{tokens.muted("(no option changes proposed — nothing in the request mapped)")}</Row>
      ) : (
        <>
          <Row>
            {tokens.muted("option".padEnd(optionWidth + 2))}
            {tokens.muted("current".padEnd(valueWidth))}
            {tokens.muted("proposed".padEnd(valueWidth))}
            {tokens.muted("why")}
          </Row>
          {changes.map((change) => (
            <PlanRow
              key={change.option}
              change={change}
              optionWidth={optionWidth}
              valueWidth={valueWidth}
              whyWidth={whyWidth}
            />
          ))}
        </>
      )}

      {unsupported.length > 0 && (
        <Row>
          {tokens.warn("unsupported ")}
          {tokens.muted(unsupported.map((u) => `"${u}"`).join(", "))}
          {tokens.hint("  (not modelled as a tool option)")}
        </Row>
      )}

      <Row>
        {tokens.muted("estimate  ")}
        {tokens.value(signedCost(plan.roughCostDeltaUsd))}
        {"  "}
        {tokens.muted("cost delta  \u00B7  ")}
        {tokens.value(signedSeconds(plan.roughWallClockDeltaSeconds))}
        {tokens.muted(" wall-clock  \u00B7  plan cost ")}
        {tokens.value(`$${plan.planCostUsd.toFixed(4)}`)}
      </Row>

      <Text>{boxBottomLine({ width })}</Text>

      <Box marginTop={SPACING.sm}>
        <Text>
          {tokens.hint("  press ")}
          {tokens.strong("y")}
          {tokens.hint(" to apply   ")}
          {tokens.strong("n")}
          {tokens.hint(" to discard   ")}
          {tokens.strong("Esc")}
          {tokens.hint(" to cancel")}
        </Text>
      </Box>
    </Box>
  );
}

function PlanRow({
  change,
  optionWidth,
  valueWidth,
  whyWidth,
}: {
  change: ShellPlanChange;
  optionWidth: number;
  valueWidth: number;
  whyWidth: number;
}): React.ReactElement {
  const option = truncateText(change.option, optionWidth).padEnd(optionWidth + 2);
  const current = truncateText(formatValue(change.current), valueWidth - 1).padEnd(valueWidth);
  const proposed = truncateText(formatValue(change.proposed), valueWidth - 1).padEnd(valueWidth);
  return (
    <Row>
      {tokens.value(option)}
      {tokens.muted(current)}
      {tokens.strong(proposed)}
      {tokens.muted(truncateText(change.why, whyWidth))}
    </Row>
  );
}

function Row({ children }: { children: React.ReactNode }): React.ReactElement {
  return (
    <Text>
      {boxRowPrefix()}
      {children}
    </Text>
  );
}

function formatValue(v: unknown): string {
  if (v === null) return "(default)";
  if (v === undefined) return "(unset)";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  try {
    const s = JSON.stringify(v);
    return s.length > 20 ? `${s.slice(0, 19)}\u2026` : s;
  } catch {
    return String(v);
  }
}

function truncateText(value: string, width: number): string {
  if (value.length <= width) return value;
  if (width <= 1) return value.slice(0, Math.max(0, width));
  return `${value.slice(0, width - 1)}\u2026`;
}

function signedCost(n: number): string {
  const sign = n >= 0 ? "+" : "\u2212";
  return `${sign}$${Math.abs(n).toFixed(2)}`;
}

function signedSeconds(n: number): string {
  const sign = n >= 0 ? "+" : "\u2212";
  const abs = Math.abs(n);
  if (abs < 60) return `${sign}${abs.toFixed(0)}s`;
  return `${sign}${(abs / 60).toFixed(1)}m`;
}

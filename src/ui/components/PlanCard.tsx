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
import type { ShellPlan, ShellPlanChange } from "../state.js";
import { SPACING, tokens } from "../tokens.js";

interface PlanCardProps {
  plan: ShellPlan;
}

export function PlanCard({ plan }: PlanCardProps): React.ReactElement {
  const { changes, unsupported } = plan;
  const optionWidth = Math.max("option".length, ...changes.map((c) => c.option.length));

  return (
    <Box
      flexDirection="column"
      paddingLeft={SPACING.md}
      marginTop={SPACING.sm}
      marginBottom={SPACING.sm}
    >
      <Text>
        {tokens.muted("\u256D\u2500 plan ")}
        {tokens.strong(plan.source)}
        {tokens.muted(`  \u2500  ${plan.toolName}`)}
        {tokens.muted(
          ` ${"\u2500".repeat(Math.max(0, 60 - plan.source.length - plan.toolName.length))}`,
        )}
        {tokens.muted("\u256E")}
      </Text>

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
            {tokens.muted("current".padEnd(22))}
            {tokens.muted("proposed".padEnd(22))}
            {tokens.muted("why")}
          </Row>
          {changes.map((change) => (
            <PlanRow key={change.option} change={change} optionWidth={optionWidth} />
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

      <Text>{tokens.muted(`\u2570${"\u2500".repeat(76)}\u256F`)}</Text>

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
}: {
  change: ShellPlanChange;
  optionWidth: number;
}): React.ReactElement {
  const option = change.option.padEnd(optionWidth + 2);
  const current = formatValue(change.current).padEnd(22);
  const proposed = formatValue(change.proposed).padEnd(22);
  return (
    <Row>
      {tokens.value(option)}
      {tokens.muted(current)}
      {tokens.strong(proposed)}
      {tokens.muted(change.why)}
    </Row>
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

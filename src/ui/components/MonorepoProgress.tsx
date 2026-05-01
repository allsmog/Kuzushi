/**
 * Monorepo module progress tree.
 *
 * Shows each module as a branch with status during parallel scanning.
 * Column alignment uses the shared `padCell` + `truncateMiddle` helpers
 * so the tp/fp/cost/elapsed columns stay aligned across rows, and module
 * names middle-truncate (preserving the trailing segment) when overflowing.
 */

import { Box, Text } from "ink";
import React from "react";
import { formatCost, formatDuration, padCell, statusBadge, truncateMiddle } from "../format.js";
import { useTerminalSize } from "../hooks/useTerminalSize.js";
import { icons } from "../icons.js";
import { SPACING, tokens } from "../tokens.js";
import { Spinner } from "./Spinner.js";

export type ModuleStatus =
  | "pending"
  | "scanning"
  | "triaging"
  | "verifying"
  | "complete"
  | "error"
  | "skipped";

export interface MonorepoModuleState {
  name: string;
  path: string;
  status: ModuleStatus;
  tasks?: string[];
  detail?: string;
  activityDetail?: string;
  tp?: number;
  fp?: number;
  needsReview?: number;
  costUsd?: number;
  elapsedMs?: number;
  startedAt?: number;
}

interface MonorepoProgressProps {
  modules: MonorepoModuleState[];
  phaseLabel?: string;
}

export const MonorepoProgress = React.memo(_MonorepoProgress);

function _MonorepoProgress({
  modules,
  phaseLabel,
}: MonorepoProgressProps): React.ReactElement | null {
  if (modules.length === 0) return null;

  const done = modules.filter((m) => m.status === "complete" || m.status === "skipped").length;
  const total = modules.length;
  const active = modules.filter(
    (m) =>
      m.status !== "pending" &&
      m.status !== "complete" &&
      m.status !== "skipped" &&
      m.status !== "error",
  );

  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Box paddingLeft={SPACING.md}>
        <Spinner color="accent" />
        <Text>
          {" "}
          {/* `focus` (blue bold) is the canonical "active" hue — see
              `statusBadge('active')`. Red was reading as an error rather
              than as a running phase. */}
          {tokens.focus(padCell(phaseLabel ?? "Scanning", 14))}{" "}
          {tokens.strong(`${done}/${total} modules`)}
        </Text>
      </Box>

      {modules.map((mod, i) => {
        const isLast = i === modules.length - 1;
        const connector = isLast ? icons.treeLast : icons.treeMiddle;

        return (
          <Box key={mod.path} paddingLeft={SPACING.md}>
            <Text>{tokens.muted(icons.treePipe)} </Text>
            <ModuleLine module={mod} connector={connector} />
          </Box>
        );
      })}

      {active.length > 0 && (
        <Box paddingLeft={SPACING.md}>
          <Text>{tokens.muted(icons.treePipe)}</Text>
        </Box>
      )}
    </Box>
  );
}

function ModuleLine({
  module: mod,
  connector,
}: {
  module: MonorepoModuleState;
  connector: string;
}): React.ReactElement {
  const { columns } = useTerminalSize();
  const cardWidth = Math.max(60, Math.min(96, columns - 4));
  const nameWidth = Math.max(16, Math.min(26, cardWidth - 44));
  const truncated = truncateMiddle(mod.name, nameWidth);
  const paddedName = padCell(truncated, nameWidth, "left");

  if (mod.status === "complete") {
    const verdicts =
      mod.tp != null
        ? `${tokens.danger(`tp=${mod.tp}`)} ${tokens.success(`fp=${mod.fp ?? 0}`)} ${tokens.warn(`nr=${mod.needsReview ?? 0}`)}`
        : "";
    const cost =
      mod.costUsd != null ? tokens.muted(padCell(formatCost(mod.costUsd), 8, "right")) : "";
    const elapsed =
      mod.elapsedMs != null ? tokens.muted(padCell(formatDuration(mod.elapsedMs), 8, "right")) : "";
    return (
      <Text>
        {tokens.muted(connector)} {tokens.muted(icons.complete)} {tokens.muted(paddedName)}{" "}
        {verdicts} {cost} {elapsed}
      </Text>
    );
  }

  if (mod.status === "skipped") {
    return (
      <Text>
        {tokens.muted(connector)} {tokens.muted(icons.complete)} {tokens.muted(paddedName)}{" "}
        {tokens.muted("skipped")}
      </Text>
    );
  }

  if (mod.status === "error") {
    const { icon, color } = statusBadge("result", "error");
    return (
      <Text>
        {tokens.muted(connector)} {color(icon)} {tokens.danger(paddedName)}{" "}
        {tokens.danger(mod.detail ?? "error")}
      </Text>
    );
  }

  if (mod.status === "pending") {
    return (
      <Text>
        {tokens.muted(connector)} {tokens.muted(icons.pending)} {tokens.muted(paddedName)}
      </Text>
    );
  }

  const statusLabel = mod.detail ?? mod.status;
  const activity = mod.activityDetail ? `  ${tokens.muted(mod.activityDetail.slice(0, 60))}` : "";
  return (
    <Box>
      <Text>{tokens.muted(connector)} </Text>
      <Spinner color="accent" />
      <Text>
        {" "}
        {tokens.strong(paddedName)} {tokens.muted(statusLabel)}
        {activity}
      </Text>
    </Box>
  );
}

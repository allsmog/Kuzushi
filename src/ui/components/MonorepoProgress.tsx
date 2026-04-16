/**
 * Monorepo module progress tree.
 *
 * Shows each module as a branch with status during parallel scanning:
 *
 *   ● Phase 2          5/15 modules
 *   │  ├─ ◆ auth-service       tp=2 fp=5     $0.12   3.2s
 *   │  ├─ ◆ api-gateway        tp=0 fp=3     $0.08   2.1s
 *   │  ├─ ● billing-service    scanning...
 *   │  ├─ ● user-portal        triaging 3/12
 *   │  └─ ○ admin-dashboard
 */

import chalk from "chalk";
import { Box, Text } from "ink";
import type React from "react";
import { formatCost, formatDuration, terminalCardWidth } from "../format.js";
import { icons } from "../icons.js";
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
  /** Latest scan activity text (e.g. current tool call). */
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

export function MonorepoProgress({
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
    <Box flexDirection="column" marginTop={1}>
      {/* Phase header */}
      <Box>
        <Text>{"  "}</Text>
        <Spinner color="red" />
        <Text>
          {" "}
          {chalk.redBright.bold((phaseLabel ?? "Scanning").padEnd(14))}{" "}
          {chalk.white(`${done}/${total} modules`)}
        </Text>
      </Box>

      {/* Module branches */}
      {modules.map((mod, i) => {
        const isLast = i === modules.length - 1;
        const connector = isLast ? icons.treeLast : icons.treeMiddle;

        return (
          <Box key={mod.path}>
            <Text>
              {"  "}
              {chalk.dim(icons.treePipe)}{" "}
            </Text>
            <ModuleLine module={mod} connector={connector} />
          </Box>
        );
      })}

      {/* Summary of active modules */}
      {active.length > 0 && (
        <Text>
          {"  "}
          {chalk.dim(icons.treePipe)}
        </Text>
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
  const nameWidth = Math.max(16, Math.min(26, terminalCardWidth(96, 60) - 44));
  const paddedName =
    mod.name.length > nameWidth
      ? `${mod.name.slice(0, nameWidth - 1)}…`
      : mod.name.padEnd(nameWidth);

  if (mod.status === "complete") {
    const verdicts =
      mod.tp != null
        ? `${chalk.red(`tp=${mod.tp}`)} ${chalk.green(`fp=${mod.fp ?? 0}`)} ${chalk.yellow(`nr=${mod.needsReview ?? 0}`)}`
        : "";
    const cost = mod.costUsd != null ? chalk.dim(formatCost(mod.costUsd)) : "";
    const elapsed = mod.elapsedMs != null ? chalk.dim(formatDuration(mod.elapsedMs)) : "";
    return (
      <Text>
        {chalk.dim(connector)} {chalk.dim(icons.complete)} {chalk.dim(paddedName)} {verdicts} {cost}{" "}
        {elapsed}
      </Text>
    );
  }

  if (mod.status === "skipped") {
    return (
      <Text>
        {chalk.dim(connector)} {chalk.dim(icons.complete)} {chalk.dim(paddedName)}{" "}
        {chalk.dim("skipped")}
      </Text>
    );
  }

  if (mod.status === "error") {
    return (
      <Text>
        {chalk.dim(connector)} {chalk.red(icons.error)} {chalk.red(paddedName)}{" "}
        {chalk.red(mod.detail ?? "error")}
      </Text>
    );
  }

  if (mod.status === "pending") {
    return (
      <Text>
        {chalk.dim(connector)} {chalk.dim(icons.pending)} {chalk.dim(paddedName)}
      </Text>
    );
  }

  // Active states: scanning, triaging, verifying
  const statusLabel = mod.detail ?? mod.status;
  const activity = mod.activityDetail ? `  ${chalk.dim(mod.activityDetail.slice(0, 60))}` : "";
  return (
    <Box>
      <Text>{chalk.dim(connector)} </Text>
      <Spinner color="yellow" />
      <Text>
        {" "}
        {chalk.white(paddedName)} {chalk.dim(statusLabel)}
        {activity}
      </Text>
    </Box>
  );
}

/**
 * Config confirmation prompt for returning users on fresh scans.
 *
 * Shows resolved config and asks to proceed, edit, or quit.
 * NOT shown for --resume runs (those skip straight to pipeline).
 *
 *   ┌─ Config ────────────────────────────────────────────┐
 *   │  Model:     claude-opus       Severity: ERROR, WARNING │
 *   │  Tasks:     semgrep, codeql   Concurrency: 5           │
 *   │  Preset:    standard          Verify: yes               │
 *   └────────────────────────────────────────────────────────┘
 *
 *   [enter] proceed  [e] edit (opens wizard)  [q] quit
 */
import React from "react";
import { Box, Text, useInput, useApp } from "ink";
import chalk from "chalk";
import { icons } from "../icons.js";
import { boxHeader, boxFooter, formatCost } from "../format.js";

export interface ConfigConfirmData {
  model: string;
  tasks: string[];
  severity?: string[];
  concurrency?: number;
  verify?: boolean;
  pocHarness?: boolean;
  preset?: string;
  budget?: number;
}

interface ConfigConfirmProps {
  config: ConfigConfirmData;
  repoName: string;
  onProceed: () => void;
  onEdit: () => void;
  onQuit: () => void;
}

export function ConfigConfirm({
  config,
  repoName,
  onProceed,
  onEdit,
  onQuit,
}: ConfigConfirmProps): React.ReactElement {
  const { exit } = useApp();

  useInput((input, key) => {
    if (key.return || input === "y") {
      onProceed();
    } else if (input === "e") {
      onEdit();
    } else if (input === "q" || key.escape) {
      onQuit();
      exit();
    }
  });

  const modelShort = config.model
    .replace("anthropic:", "")
    .replace("-latest", "");

  return (
    <Box flexDirection="column">
      <Text>{""}</Text>
      <Text>{boxHeader(`${repoName}`, 58)}</Text>
      <Text>{""}</Text>

      <Text>{"  "}{chalk.dim("Model:")}        {chalk.white(modelShort)}</Text>
      <Text>{"  "}{chalk.dim("Tasks:")}        {chalk.white(config.tasks.join(", "))}</Text>

      {config.severity && config.severity.length > 0 && (
        <Text>{"  "}{chalk.dim("Severity:")}     {config.severity.join(", ")}</Text>
      )}
      {config.preset && (
        <Text>{"  "}{chalk.dim("Preset:")}       {config.preset}</Text>
      )}
      {config.verify && (
        <Text>{"  "}{chalk.dim("Verify:")}       {chalk.green("yes")}</Text>
      )}
      {config.pocHarness && (
        <Text>{"  "}{chalk.dim("PoC Harness:")}  {chalk.green("yes")}</Text>
      )}
      {config.concurrency && config.concurrency > 1 && (
        <Text>{"  "}{chalk.dim("Concurrency:")}  {config.concurrency}</Text>
      )}
      {config.budget != null && config.budget > 0 && (
        <Text>{"  "}{chalk.dim("Budget:")}       {formatCost(config.budget)}</Text>
      )}

      <Text>{""}</Text>
      <Text>{"  "}{chalk.redBright.bold("[enter]")} proceed  {chalk.dim("[e]")} edit  {chalk.dim("[q]")} quit</Text>
      <Text>{boxFooter(58)}</Text>
    </Box>
  );
}

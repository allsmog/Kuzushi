/**
 * Pipeline stage header with icon.
 *
 * Renders:   ⚡ Triaging 142 findings via claude-opus...
 */
import React from "react";
import { Text } from "ink";
import chalk from "chalk";
import { icons } from "../icons.js";
import type { Phase } from "../state.js";

const STAGE_ICONS: Record<string, string> = {
  scanning: icons.lightning,
  triaging: icons.lightning,
  verifying: icons.shield,
  poc: icons.gear,
};

const STAGE_COLORS: Record<string, (s: string) => string> = {
  scanning: chalk.green,
  triaging: chalk.yellow,
  verifying: chalk.cyan,
  poc: chalk.magenta,
};

interface StageHeaderProps {
  phase: Phase;
  label: string;
}

export function StageHeader({ phase, label }: StageHeaderProps): React.ReactElement {
  const icon = STAGE_ICONS[phase] ?? icons.active;
  const colorFn = STAGE_COLORS[phase] ?? chalk.white;

  return (
    <Text>{"  "}{colorFn(`${icon} ${label}`)}</Text>
  );
}

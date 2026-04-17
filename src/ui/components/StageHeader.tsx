/**
 * Pipeline stage header with icon.
 *
 * Renders:   ⚡ Triaging 142 findings via claude-opus...
 */

import { Box, Text } from "ink";
import type React from "react";
import { icons } from "../icons.js";
import type { Phase } from "../state.js";
import { tokens } from "../tokens.js";

const STAGE_ICONS: Record<string, string> = {
  scanning: icons.lightning,
  triaging: icons.lightning,
  verifying: icons.shield,
  poc: icons.gear,
};

const STAGE_COLORS: Record<string, (s: string) => string> = {
  scanning: tokens.dangerStrong,
  triaging: tokens.danger,
  verifying: tokens.warn,
  poc: tokens.strong,
};

interface StageHeaderProps {
  phase: Phase;
  label: string;
}

export function StageHeader({ phase, label }: StageHeaderProps): React.ReactElement {
  const icon = STAGE_ICONS[phase] ?? icons.active;
  const colorFn = STAGE_COLORS[phase] ?? tokens.strong;

  return (
    <Box paddingLeft={2}>
      <Text>{colorFn(`${icon} ${label}`)}</Text>
    </Box>
  );
}

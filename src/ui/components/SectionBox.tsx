/**
 * Box-drawing section wrapper using Unicode box characters.
 * Renders a header (╭─ Title ─╮), optional dividers (├──┤), and footer (╰──╯).
 */

import { Box, Text } from "ink";
import type React from "react";
import { boxDivider, boxFooter, boxHeader } from "../format.js";
import type { BorderVariant } from "../glyphs.js";

interface SectionBoxProps {
  title: string;
  width?: number;
  variant?: BorderVariant;
  children: React.ReactNode;
}

export function SectionBox({
  title,
  width = 60,
  variant = "rounded",
  children,
}: SectionBoxProps): React.ReactElement {
  return (
    <Box flexDirection="column">
      <Text>{boxHeader(title, width, { variant })}</Text>
      <Text> </Text>
      {children}
      <Text> </Text>
      <Text>{boxFooter(width, { variant })}</Text>
    </Box>
  );
}

interface SectionDividerProps {
  width?: number;
  variant?: BorderVariant;
}

export function SectionDivider({
  width = 60,
  variant = "rounded",
}: SectionDividerProps): React.ReactElement {
  return <Text>{boxDivider(width, { variant })}</Text>;
}

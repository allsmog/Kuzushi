/**
 * Box-drawing section wrapper using Unicode box characters.
 * Renders a header (╭─ Title ─╮), optional dividers (├──┤), and footer (╰──╯).
 */

import { Box, Text } from "ink";
import type React from "react";
import { boxDivider, boxFooter, boxHeader } from "../format.js";

interface SectionBoxProps {
  title: string;
  width?: number;
  children: React.ReactNode;
}

export function SectionBox({ title, width = 60, children }: SectionBoxProps): React.ReactElement {
  return (
    <Box flexDirection="column">
      <Text>{boxHeader(title, width)}</Text>
      <Text> </Text>
      {children}
      <Text> </Text>
      <Text>{boxFooter(width)}</Text>
    </Box>
  );
}

interface SectionDividerProps {
  width?: number;
}

export function SectionDivider({ width = 60 }: SectionDividerProps): React.ReactElement {
  return <Text>{boxDivider(width)}</Text>;
}

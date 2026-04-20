/**
 * Horizontal tab bar for view switching.
 *
 * Renders:  [Pipeline]  Findings  Cost
 *
 * Active tab uses accent color + underline. Inactive tabs are muted.
 */

import { Box, Text } from "ink";
import type React from "react";
import { tokens } from "../tokens.js";

export interface Tab {
  id: string;
  label: string;
  /** Keyboard shortcut shown after the label. */
  shortcut?: string;
}

interface TabBarProps {
  tabs: Tab[];
  activeId: string;
  onChange?: (id: string) => void;
}

export function TabBar({ tabs, activeId }: TabBarProps): React.ReactElement {
  return (
    <Box flexDirection="row" paddingLeft={2} marginBottom={1}>
      {tabs.map((tab, i) => {
        const isActive = tab.id === activeId;
        const shortcut = tab.shortcut ? tokens.muted(` ${tab.shortcut}`) : "";

        return (
          <Box key={tab.id}>
            {i > 0 && <Text>{tokens.subtle("  │  ")}</Text>}
            {isActive ? (
              <Text underline>{tokens.accent(tab.label)}{shortcut}</Text>
            ) : (
              <Text>{tokens.muted(tab.label)}{shortcut}</Text>
            )}
          </Box>
        );
      })}
    </Box>
  );
}

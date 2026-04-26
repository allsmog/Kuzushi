/**
 * Horizontal tab bar for view switching.
 *
 * Renders:  ● 1 Pipeline  │  2 Findings  │  3 Cost
 *
 * Active tab uses a single high-emphasis treatment. Inactive tabs stay quiet.
 */

import { Box, Text } from "ink";
import React from "react";
import { SPACING, tokens } from "../tokens.js";

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

export const TabBar = React.memo(_TabBar);

function _TabBar({ tabs, activeId }: TabBarProps): React.ReactElement {
  return (
    <Box flexDirection="row" paddingLeft={SPACING.md} marginBottom={SPACING.sm}>
      {tabs.map((tab, i) => {
        const isActive = tab.id === activeId;
        const shortcut = tab.shortcut ? `${tab.shortcut} ` : "";
        const label = `${shortcut}${tab.label}`;

        return (
          <Box key={tab.id}>
            {i > 0 && <Text>{tokens.subtle("  │  ")}</Text>}
            {isActive ? (
              <Text>{tokens.focus(`● ${label}`)}</Text>
            ) : (
              <Text>{tokens.metadata(`  ${label}`)}</Text>
            )}
          </Box>
        );
      })}
    </Box>
  );
}

/**
 * FilterChips — the `[sev: all]  [state: open]  [module: any]` header row
 * shown at the top of the unified findings list (Ink UI v2 screen 04).
 *
 * Read-only in this first pass — the chip with an explicit, non-default value
 * is highlighted; others are muted. Wiring filter state to keyboard input is
 * a follow-up that needs an editable store slice; for now the chips reflect
 * whatever is passed in.
 */

import { Box, Text } from "ink";
import type React from "react";
import { tokens } from "../tokens.js";

export interface FilterChip {
  key: string; // "sev" | "state" | "module" | "since" | "assignee" | …
  value: string; // "all" | "open" | "any" | "2h" | …
  /** Non-default values render with the accent color. */
  explicit?: boolean;
}

interface FilterChipsProps {
  chips: ReadonlyArray<FilterChip>;
}

export function FilterChips({ chips }: FilterChipsProps): React.ReactElement {
  const activeCount = chips.filter((chip) => chip.explicit).length;
  return (
    <Box flexDirection="column">
      <Text>
        {tokens.label("filter")}
        {"   "}
        {chips
          .map((chip) => {
            const body = `[${chip.key}: ${chip.value}]`;
            return chip.explicit ? tokens.accent(body) : tokens.muted(body);
          })
          .join("  ")}
      </Text>
      <Text>
        {tokens.muted(
          `${activeCount} active · /filter <key>:<value> to refine · /filter reset to clear`,
        )}
      </Text>
    </Box>
  );
}

/**
 * KeybindFooter — sticky bottom hint bar showing the active keybindings.
 *
 * Reads from `useKeybindings()` context so each component can register its
 * own bindings at mount; the footer renders the LIFO-most-recent set. Pass
 * `bindings` explicitly to bypass the context (useful in tests or static
 * footers).
 */
import { Box, Text, useStdout } from "ink";
import type { FC } from "react";
import { type Keybinding, useKeybindings } from "../hooks/useKeybindings.js";
import { icons } from "../icons.js";
import { SPACING, tokens } from "../tokens.js";
import { Divider } from "./Divider.js";

export interface KeybindFooterProps {
  bindings?: ReadonlyArray<Keybinding>;
  maxShown?: number;
}

export const KeybindFooter: FC<KeybindFooterProps> = ({ bindings: override, maxShown = 6 }) => {
  const ctx = useKeybindings();
  const { stdout } = useStdout();
  const columns = stdout?.columns ?? 100;
  const bindings = override ?? ctx.bindings;
  if (!bindings || bindings.length === 0) return null;

  const responsiveMax = columns < 52 ? 3 : columns < 72 ? 4 : maxShown;
  const extra = bindings.length > responsiveMax ? bindings.length - (responsiveMax - 1) : 0;
  const shown = extra > 0 ? bindings.slice(0, responsiveMax - 1) : bindings;

  return (
    <Box flexDirection="column">
      <Divider />
      <Box flexDirection="row" paddingLeft={SPACING.md}>
        <Text>
          {shown
            .map((b, i) => {
              const key = `${tokens.subtle("[")}${tokens.label(b.keys)}${tokens.subtle("]")}`;
              const label = b.secondary ? tokens.subtle(b.label) : tokens.metadata(b.label);
              const sep = i > 0 ? tokens.subtle(`  ${icons.dot}  `) : "";
              return `${sep}${key} ${label}`;
            })
            .join("")}
          {extra > 0 ? tokens.subtle(`  +${extra} more`) : ""}
        </Text>
      </Box>
    </Box>
  );
};

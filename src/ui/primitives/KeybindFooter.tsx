/**
 * KeybindFooter — sticky bottom hint bar showing the active keybindings.
 *
 * Reads from `useKeybindings()` context so each component can register its
 * own bindings at mount; the footer renders the LIFO-most-recent set. Pass
 * `bindings` explicitly to bypass the context (useful in tests or static
 * footers).
 */
import { Box, Text } from "ink";
import type { FC } from "react";
import { icons } from "../icons.js";
import {
  type Keybinding,
  useKeybindings,
} from "../hooks/useKeybindings.js";
import { tokens } from "../tokens.js";

export interface KeybindFooterProps {
  bindings?: ReadonlyArray<Keybinding>;
  maxShown?: number;
}

export const KeybindFooter: FC<KeybindFooterProps> = ({
  bindings: override,
  maxShown = 6,
}) => {
  const ctx = useKeybindings();
  const bindings = override ?? ctx.bindings;
  if (!bindings || bindings.length === 0) return null;

  const extra = bindings.length > maxShown ? bindings.length - (maxShown - 1) : 0;
  const shown = extra > 0 ? bindings.slice(0, maxShown - 1) : bindings;
  const ruleWidth = process.stdout.columns ?? 80;

  return (
    <Box flexDirection="column">
      <Text>{tokens.muted(icons.boxHorizontal.repeat(Math.max(8, ruleWidth)))}</Text>
      <Box flexDirection="row">
        <Text>
          {shown
            .map((b, i) => {
              const key = tokens.hint(`[${b.keys}]`);
              const label = b.secondary
                ? tokens.subtle(b.label)
                : tokens.muted(b.label);
              const sep = i > 0 ? tokens.subtle(`  ${icons.dot}  `) : "";
              return `${sep}${key} ${label}`;
            })
            .join("")}
          {extra > 0 ? tokens.muted(`  +${extra} more`) : ""}
        </Text>
      </Box>
    </Box>
  );
};

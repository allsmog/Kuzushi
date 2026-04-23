/**
 * One-line status strip rendered at the top of a screen's content area to
 * surface per-view counts that aren't in shell state (e.g. element count,
 * threat count, source path mtime). The screen's title + breadcrumbs are
 * already drawn by AppLayout from the navigation context — this strip is
 * the screen's only allowed header chrome.
 */

import { Box, Text } from "ink";
import type React from "react";
import { useLayoutContext } from "../layout-context.js";
import { tokens } from "../tokens.js";

export interface ContextStripProps {
  /** Status badges (rendered in `value` token, joined by status separator). */
  status?: ReadonlyArray<string | number>;
  /** Secondary metadata line below status (e.g. source path · mtime). */
  subtitle?: string;
}

export function ContextStrip({ status, subtitle }: ContextStripProps): React.ReactElement | null {
  const { theme } = useLayoutContext();
  const items = (status ?? []).filter((s) => s !== undefined && s !== null && String(s).length > 0);
  if (items.length === 0 && !subtitle) return null;
  const sep = theme.drawing.statusSeparator;
  return (
    <Box flexDirection="column" marginBottom={theme.spacing.sm}>
      {items.length > 0 && (
        <Text>
          {items
            .map((item, i) => `${i === 0 ? "" : tokens.subtle(sep)}${tokens.value(String(item))}`)
            .join("")}
        </Text>
      )}
      {subtitle && <Text>{tokens.metadata(subtitle)}</Text>}
    </Box>
  );
}

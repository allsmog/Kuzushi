/**
 * EmptyState — canonical three-line empty/failure surface: a bold title,
 * a muted reason, and an action hint with the next verb/keystroke.
 *
 * Every "No X" / "(no Y)" string in a shell view should route through this
 * so operators always see the same `title · reason · action` rhythm. Copy
 * itself lives in `describeEmptyState()` inside `src/ui/error-format.ts`
 * (pure, test-friendly, plain-renderer-safe).
 *
 * Width-aware via `useTerminalSize()` — on very narrow terminals the
 * `reason` line truncates with an ellipsis so the action hint always
 * renders. The action line never truncates; dropping it defeats the
 * whole point of the component.
 */

import { Box, Text } from "ink";
import type React from "react";
import {
  describeEmptyState,
  type EmptyStateContext,
  type EmptyStateKind,
} from "../error-format.js";
import { useTerminalSize } from "../hooks/useTerminalSize.js";
import { tokens } from "../tokens.js";

interface EmptyStateProps {
  kind: EmptyStateKind;
  context?: EmptyStateContext;
  /**
   * Optional title override — lets callers embed the view name ("data flow
   * diagram") while keeping the reason/action copy from the kind. Falls back
   * to `describeEmptyState(...).title`.
   */
  titleOverride?: string;
  /** Extra padding from the left edge (defaults to 0, parent handles layout). */
  paddingLeft?: number;
}

/** Narrowest width we'll still attempt to render full copy at. */
const NARROW_COLUMNS = 60;

function truncate(s: string, max: number): string {
  if (max <= 1 || s.length <= max) return s;
  return `${s.slice(0, Math.max(0, max - 1))}…`;
}

export function EmptyState({
  kind,
  context,
  titleOverride,
  paddingLeft = 0,
}: EmptyStateProps): React.ReactElement {
  const { columns } = useTerminalSize();
  const copy = describeEmptyState(kind, context);
  const title = titleOverride ?? copy.title;

  // Budget the reason line so the action hint always survives. Leave
  // ~4 cols of breathing room on the right edge.
  const budget = Math.max(20, columns - paddingLeft - 4);
  const reason = columns < NARROW_COLUMNS ? truncate(copy.reason, budget) : copy.reason;

  return (
    <Box flexDirection="column" paddingLeft={paddingLeft}>
      <Text>{tokens.strong(title)}</Text>
      <Text>{tokens.muted(reason)}</Text>
      <Text>{tokens.hint(copy.action)}</Text>
    </Box>
  );
}

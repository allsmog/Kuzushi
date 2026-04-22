/**
 * ShellHeader — canonical header strip for every `ShellView` sub-screen.
 *
 * Every shell sub-view (catalog / module / findings / finding / tune /
 * threat-*) historically rolled its own `◂ back   <title>   │   <count>`
 * string composition. That meant:
 *
 *   - Each view picked its own column width (72 / 74 / 78 / uncapped).
 *   - Subtitles drifted out of sync with CLAUDE.md §12 (e.g. the module
 *     home line was "· offense · 40+ task pipeline" while TuneView used
 *     "home   tune    prompt    runs").
 *   - Breadcrumb affordances ("◂ back") were manually repeated.
 *
 * This component centralises that pattern:
 *
 *   ShellHeader:   ◂ <back-label>   <title>   │   <subtitle>   ·  <count>
 *                  <secondary line>   (muted, optional)
 *
 * Width discipline — `useTerminalWidth()` + `classifyTerminalWidth()` from
 * agent 1's hook set decide what to show:
 *   - tiny   (< 60) → drop subtitle, keep title + glyph count
 *   - narrow (< 80) → show subtitle truncated; drop secondary line
 *   - ≥ 80         → full layout with secondary line
 *
 * This is purely additive — existing views that haven't been migrated
 * yet keep working and pass through the same `ShellState`. Components
 * opt in by importing + rendering <ShellHeader …/> at the top of their
 * view.
 */

import { Box, Text } from "ink";
import React from "react";
import { classifyTerminalWidth, useTerminalWidth } from "../hooks.js";
import { tokens } from "../tokens.js";

export interface ShellHeaderProps {
  /** Primary title — `tokens.strong` wrapped. Keep under 32 chars. */
  title: string;
  /**
   * Optional subtitle. Renders after a muted `│` divider, in `tokens.value`.
   * On narrow terminals the subtitle is truncated with `…`; on tiny
   * terminals it is suppressed entirely.
   */
  subtitle?: string;
  /**
   * Optional count chip(s) — e.g. "4 elements · 12 threats" or "2000 open".
   * Rendered in `tokens.muted` after a `·` separator.
   */
  count?: string;
  /**
   * Back breadcrumb label. Renders as `◂ <backLabel>` prefix. Defaults to
   * "back" — views that want richer context (e.g. "◂ findings" on the
   * finding deep page) pass their own.
   */
  backLabel?: string;
  /**
   * Optional secondary line rendered below the primary row in `tokens.hint`.
   * Used for "loaded from X (3m ago)" stamps and similar metadata. Dropped
   * on narrow terminals to reclaim vertical space.
   */
  secondary?: string;
  /**
   * Optional maximum content width. Defaults to
   * `min(useTerminalWidth(), 100)` — matches the canonical 100-col soft
   * cap the rest of the shell uses.
   */
  maxWidth?: number;
}

/** Canonical content-width cap — matches FindingsView / StatusFooter (80 / 100). */
export const SHELL_CONTENT_WIDTH_CAP = 100;

/** Resolve the effective content width for a shell view. */
export function resolveContentWidth(columns: number, cap = SHELL_CONTENT_WIDTH_CAP): number {
  return Math.min(Math.max(20, columns), cap);
}

export const ShellHeader = React.memo(function ShellHeader({
  title,
  subtitle,
  count,
  backLabel = "back",
  secondary,
  maxWidth,
}: ShellHeaderProps): React.ReactElement {
  const columns = useTerminalWidth();
  const widthClass = classifyTerminalWidth(columns);
  const width = maxWidth ?? resolveContentWidth(columns);

  const tiny = widthClass === "tiny";
  const narrow = widthClass === "narrow";

  // Reserve space for the "◂ back   " prefix + title + separator glyphs so
  // the subtitle truncation maths stay honest.
  const reservedForChrome = 4 /* ◂ */ + backLabel.length + 3 /* spacing */ + title.length + 4; /* │ */
  const subtitleBudget = Math.max(0, width - reservedForChrome - (count?.length ?? 0) - 6);

  const displaySubtitle = subtitle
    ? tiny
      ? ""
      : truncate(subtitle, subtitleBudget)
    : "";

  return (
    <Box flexDirection="column">
      <Text>
        {tokens.muted(`◂ ${backLabel}   `)}
        {tokens.strong(title)}
        {displaySubtitle ? (
          <>
            {tokens.muted("   │   ")}
            {tokens.value(displaySubtitle)}
          </>
        ) : null}
        {count ? (
          <>
            {subtitle && !tiny ? tokens.muted("  ·  ") : tokens.muted("   ")}
            {tokens.muted(count)}
          </>
        ) : null}
      </Text>
      {secondary && !narrow && !tiny ? (
        <Text>{tokens.hint(secondary)}</Text>
      ) : null}
    </Box>
  );
});

function truncate(text: string, max: number): string {
  if (max <= 0) return "";
  if (text.length <= max) return text;
  if (max <= 1) return "…";
  return `${text.slice(0, max - 1)}…`;
}

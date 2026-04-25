/**
 * Canonical UI glyphs — single source of truth.
 *
 * cc-repo uses `BLACK_CIRCLE` (`⏺`) on macOS and `●` elsewhere because the
 * U+23FA glyph sits lower in most terminal fonts on non-mac platforms,
 * making it look off-baseline next to text. Matching that choice keeps the
 * `⏺` visually anchored to the tool-name row.
 *
 * The `LOWER_HOOK` is the response prefix used under a `BLACK_CIRCLE` parent
 * (matches cc-repo's `⎿`, always `dimColor`).
 *
 * Keep these imports centralized so any future theme/terminal-detect changes
 * flow through one file.
 */

const IS_DARWIN = process.platform === "darwin";

/** `⏺` on macOS, `●` elsewhere — for tool-call headers and assistant text. */
export const BLACK_CIRCLE: string = IS_DARWIN ? "⏺" : "●";

/** `⎿` (U+23BF) — response/result prefix hook, always dimmed. */
export const LOWER_HOOK: string = "⎿";

/** Completion outcome glyphs — used on the `⎿  <glyph> <verb>` line. */
export const OUTCOME_GLYPH = {
  ok: "✓", // ✓
  fail: "✗", // ✗
  abort: "·", // ·
} as const;

/** `✻` — assistant thinking marker for the actor-detail transcript. */
export const THINKING_GLYPH = "✻";

/** `★` — finding marker for the actor-detail transcript. */
export const FINDING_GLYPH = "★";

/** Step-row glyphs for the live ModuleRunView (✓ done, → running, ○ pending). */
export const STEP_GLYPH = {
  done: "✓",
  running: "→",
  pending: "○",
} as const;

export type BorderVariant = "rounded" | "square";

export const BORDER_GLYPHS: Record<
  BorderVariant,
  {
    topLeft: string;
    topRight: string;
    bottomLeft: string;
    bottomRight: string;
    horizontal: string;
    vertical: string;
    dividerLeft: string;
    dividerRight: string;
  }
> = {
  rounded: {
    topLeft: "╭",
    topRight: "╮",
    bottomLeft: "╰",
    bottomRight: "╯",
    horizontal: "─",
    vertical: "│",
    dividerLeft: "├",
    dividerRight: "┤",
  },
  square: {
    topLeft: "┌",
    topRight: "┐",
    bottomLeft: "└",
    bottomRight: "┘",
    horizontal: "─",
    vertical: "│",
    dividerLeft: "├",
    dividerRight: "┤",
  },
} as const;

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

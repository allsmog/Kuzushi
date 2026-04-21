/**
 * Semantic color + typography tokens — the ONLY color/weight surface UI
 * components should use.
 *
 * Do not import `chalk` directly in components. Import these tokens instead so
 * a single palette (and a single weight scale) governs every rendered surface
 * and so theming/light-mode adaptations land in one place.
 *
 * Each token is a `(text: string) => string` wrapper that returns the input
 * string with ANSI codes applied.
 *
 * Color palette discipline:
 *   - `danger` / `dangerStrong`  — errors, true positives, exploitable verdicts
 *   - `success` / `successStrong` — passing checks, safe/mitigated states
 *   - `warn` / `warnStrong`      — cautions, skipped, needs-review
 *   - `info`                     — informational / by-design / neutral link-ish
 *   - `accent`                   — brand accent (cyan); use sparingly for
 *                                  identifiers, file links, PoC/proof callouts
 *   - `muted` / `metadata`       — theme-aware secondary text (same impl —
 *                                  `metadata` names intent at the callsite)
 *   - `subtle`                   — one step lighter than `muted`
 *   - `strong`                   — bold white for emphasis against muted rows
 *
 * Typography scale (weight + italic, not color):
 *   - `heading` — bold + underline; use sparingly, only for section headers
 *   - `label`   — bold; key/column names in detail rows
 *   - `value`   — identity wrapper; present so callers can pair
 *                 `label(key) + " " + value(val)` symmetrically
 *   - `hint`    — italic + muted; parenthetical hints, tertiary annotations
 */
import chalk from "chalk";
import { isHighContrast, isNoColor } from "./severity.js";
import { getTheme } from "./theme.js";

/**
 * Theme-aware secondary/dim: `chalk.dim` on dark, `chalk.gray` on light.
 *
 * Accessibility behavior:
 *   - `NO_COLOR` set → identity (no ANSI applied; downstream can still
 *     pad/layout against the string).
 *   - `KUZUSHI_HIGH_CONTRAST=1` → identity. Dim/gray is often unreadable
 *     against a white-on-black high-contrast terminal, so we upgrade it
 *     to regular weight.
 */
function muted(text: string): string {
  if (isNoColor() || isHighContrast()) return text;
  return getTheme() === "light" ? chalk.gray(text) : chalk.dim(text);
}

/** One step lighter/dimmer than `muted`. Flip the theme mapping to read a bit softer. */
function subtle(text: string): string {
  if (isNoColor() || isHighContrast()) return text;
  return getTheme() === "light" ? chalk.dim(text) : chalk.gray(text);
}

/** Italic + muted — for parenthetical hints and tertiary annotations. */
function hint(text: string): string {
  if (isNoColor()) return text;
  if (isHighContrast()) return chalk.italic(text);
  return chalk.italic(muted(text));
}

export const tokens = {
  // Semantic color
  danger: (text: string) => chalk.red(text),
  dangerStrong: (text: string) => chalk.redBright.bold(text),
  success: (text: string) => chalk.green(text),
  successStrong: (text: string) => chalk.green.bold(text),
  warn: (text: string) => chalk.yellow(text),
  warnStrong: (text: string) => chalk.yellow.bold(text),
  info: (text: string) => chalk.blue(text),
  accent: (text: string) => chalk.cyan(text),
  strong: (text: string) => chalk.white.bold(text),

  // Theme-aware
  muted,
  subtle,
  // Explicit alias for `muted` — read "this value is metadata" at the callsite.
  metadata: muted,

  // Typography (weight + italic, not color)
  heading: (text: string) => chalk.bold.underline(text),
  label: (text: string) => chalk.bold(text),
  value: (text: string) => text,
  hint,
} as const;

// Individual named exports (ergonomic for destructured imports).
export const danger = tokens.danger;
export const dangerStrong = tokens.dangerStrong;
export const success = tokens.success;
export const successStrong = tokens.successStrong;
export const warn = tokens.warn;
export const warnStrong = tokens.warnStrong;
export const info = tokens.info;
export const accent = tokens.accent;
export const strong = tokens.strong;
export const heading = tokens.heading;
export const label = tokens.label;
export const value = tokens.value;
export const metadata = tokens.metadata;
export { hint, muted, subtle };

/**
 * Shared vertical/horizontal spacing scale. Use with Ink `<Box>` `marginTop`,
 * `marginBottom`, `paddingLeft`, etc. so every component pulls from one scale
 * instead of scattering magic numbers.
 */
export const SPACING = {
  xs: 0,
  sm: 1,
  md: 2,
  lg: 3,
  xl: 4,
} as const;

/**
 * Canonical column widths for tabular layouts. Reserved slots for
 * status icons, pipeline stage detail strings, elapsed times, and cost
 * badges. Additional widths should be added here rather than inlined.
 */
export const COLUMN_WIDTHS = {
  stageDetail: 12,
  stageElapsed: 8,
  statusIcon: 2,
  costBadge: 10,
} as const;

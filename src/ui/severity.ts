/**
 * Severity palette + accessibility helpers — single source of truth for
 * how `critical | high | medium | low | info` severities render.
 *
 * Design goals:
 *   - Color-blind-safe: the palette is inspired by the Okabe-Ito set
 *     (vermillion / orange / yellow / sky-blue / bluish-green) which is
 *     distinguishable under deuteranopia, protanopia, and tritanopia.
 *     Pure "red vs green" is deliberately avoided.
 *   - Never rely on hue alone: every severity carries a `glyph` + `label`
 *     pair so a grayscale / screen-reader render still conveys the tier.
 *   - Honor `NO_COLOR` (https://no-color.org): any non-empty value on the
 *     env var suppresses color output — `severityStyle(...).color` returns
 *     `undefined` in that mode so Ink's `<Text color={undefined}>` falls
 *     back to the terminal default.
 *   - `KUZUSHI_HIGH_CONTRAST=1` — forces bright variants and `bold` for
 *     every severity so dim/gray text stays legible on high-contrast-white
 *     terminals where default `gray`/`dim` disappears.
 *
 * This module is intentionally pure/presentational. Consumers:
 *
 *   - Ink: `const { color, bold } = severityStyle("high");
 *           <Text color={color} bold={bold}>{severityToken("high")}</Text>`
 *   - chalk: `severityChalk("high")("HIGH")` to get the wrapped string.
 *   - plain/SR: `severityToken("high")` always includes the glyph+label.
 */

import chalk, { type ChalkInstance } from "chalk";

/** The five severity tiers Kuzushi renders across the TUI + exports. */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/**
 * Ink-compatible color names. Ink maps these onto the terminal's ANSI
 * palette, so staying within the named set lets the terminal's own
 * theme (solarized, dracula, etc.) supply the actual hex.
 */
export type InkColor =
  | "red"
  | "redBright"
  | "yellow"
  | "yellowBright"
  | "cyan"
  | "cyanBright"
  | "blue"
  | "blueBright"
  | "magenta"
  | "magentaBright"
  | "gray"
  | "white";

export interface SeverityStyle {
  /** Ink `<Text color=...>` value. `undefined` under `NO_COLOR`. */
  color: InkColor | undefined;
  /** Ink `<Text bold>` flag. Forced true under `KUZUSHI_HIGH_CONTRAST`. */
  bold: boolean;
  /** Unicode glyph paired with the label — never rely on color alone. */
  glyph: string;
  /** Short operator-facing label (4 chars, padded) for tabular layouts. */
  label: string;
  /** Long label ("CRITICAL") for prose / badges. */
  longLabel: string;
}

/**
 * Visual tokens for each tier. Order of concerns:
 *   - `color` is the preferred ink name for colorful terminals.
 *   - `glyph` is ALWAYS emitted even when color is suppressed.
 *   - `label` / `longLabel` are plain-text — screen readers speak these.
 *
 * Palette mapping (Okabe-Ito friendly):
 *   critical → vermillion (redBright)   — strong attention-getter
 *   high     → orange-ish (yellowBright + bold) in practice renders
 *              as a distinct "bright yellow" which humans read as orange
 *              on most palettes; falls back to red on the plain pass
 *   medium   → amber/yellow             — cautionary, not alarming
 *   low      → sky blue                 — still colored, not dim, so
 *              operators can scan the bottom of a findings list
 *   info     → bluish-green (cyan)      — neutral/by-design
 */
const BASE_PALETTE: Record<Severity, Omit<SeverityStyle, "color" | "bold"> & { color: InkColor }> =
  {
    critical: {
      color: "redBright",
      glyph: "■", // ■ filled square
      label: "CRIT",
      longLabel: "CRITICAL",
    },
    high: {
      color: "red",
      glyph: "▲", // ▲ filled triangle up
      label: "HIGH",
      longLabel: "HIGH",
    },
    medium: {
      color: "yellow",
      glyph: "◆", // ◆ diamond
      label: "MED ",
      longLabel: "MEDIUM",
    },
    low: {
      color: "cyan",
      glyph: "●", // ● circle
      label: "LOW ",
      longLabel: "LOW",
    },
    info: {
      color: "blue",
      glyph: "○", // ○ hollow circle
      label: "INFO",
      longLabel: "INFO",
    },
  };

/**
 * Bright/bold variants used under `KUZUSHI_HIGH_CONTRAST=1`. Every tier
 * upgrades to a `*Bright` color (or stays `redBright`) and forces bold.
 */
const HIGH_CONTRAST_COLOR: Record<Severity, InkColor> = {
  critical: "redBright",
  high: "redBright",
  medium: "yellowBright",
  low: "cyanBright",
  info: "blueBright",
};

/**
 * Returns true when `NO_COLOR` is set to any non-empty value, following
 * https://no-color.org. `NO_COLOR=""` is treated as unset (matches the
 * spec — the var must exist AND be non-empty).
 */
export function isNoColor(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = env["NO_COLOR"];
  return typeof v === "string" && v.length > 0;
}

/**
 * `KUZUSHI_HIGH_CONTRAST=1` forces bright variants + bold + strips dim.
 * Any truthy value ("1", "true", "yes") opts in; empty/unset is off.
 */
export function isHighContrast(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = env["KUZUSHI_HIGH_CONTRAST"];
  if (!v) return false;
  const norm = v.toLowerCase();
  return norm === "1" || norm === "true" || norm === "yes" || norm === "on";
}

/**
 * Return the visual style for a severity tier.
 *
 * Order of precedence:
 *   1. `NO_COLOR` → color is `undefined`, glyph + label preserved.
 *   2. `KUZUSHI_HIGH_CONTRAST` → bold + bright-variant color.
 *   3. Default palette.
 */
export function severityStyle(
  severity: Severity,
  env: NodeJS.ProcessEnv = process.env,
): SeverityStyle {
  const base = BASE_PALETTE[severity];
  const noColor = isNoColor(env);
  const highContrast = isHighContrast(env);

  const color: InkColor | undefined = noColor
    ? undefined
    : highContrast
      ? HIGH_CONTRAST_COLOR[severity]
      : base.color;

  return {
    color,
    // Critical + high-contrast mode always bolded so they stay scannable.
    bold: highContrast || severity === "critical",
    glyph: base.glyph,
    label: base.label,
    longLabel: base.longLabel,
  };
}

/**
 * Operator-facing token for inline prose / tables: `"■ CRIT"`. Always
 * includes the glyph so the tier is readable when color is stripped
 * (screen reader, NO_COLOR, pipe-to-file).
 */
export function severityToken(severity: Severity, env: NodeJS.ProcessEnv = process.env): string {
  const s = severityStyle(severity, env);
  return `${s.glyph} ${s.label}`;
}

/**
 * Chalk-wrapped string helper for callsites that already compose strings
 * (pre-Ink output like `plain-renderer.ts`, CI stream, exports).
 *
 * Returns an identity function when `NO_COLOR` is set.
 */
export function severityChalk(
  severity: Severity,
  env: NodeJS.ProcessEnv = process.env,
): (text: string) => string {
  if (isNoColor(env)) return (t: string) => t;
  const instance = resolveChalk(severity, env);
  return (t: string) => instance(t);
}

function resolveChalk(severity: Severity, env: NodeJS.ProcessEnv): ChalkInstance {
  const highContrast = isHighContrast(env);
  const colorName = highContrast ? HIGH_CONTRAST_COLOR[severity] : BASE_PALETTE[severity].color;
  // Map Ink color name → chalk style. Chalk exposes each as a property.
  const base = (chalk as unknown as Record<string, ChalkInstance>)[colorName] ?? chalk.white;
  return highContrast || severity === "critical" ? base.bold : base;
}

/**
 * Normalize an arbitrary severity string (`"ERROR"`, `"MEDIUM"`, `"crit"`)
 * to the canonical `Severity` union. Unknown → `"info"`.
 */
export function normalizeSeverity(raw: string | undefined | null): Severity {
  if (!raw) return "info";
  const norm = String(raw).toLowerCase();
  if (norm.startsWith("crit")) return "critical";
  if (norm === "error" || norm.startsWith("high")) return "high";
  if (norm === "warning" || norm.startsWith("med")) return "medium";
  if (norm === "low") return "low";
  return "info";
}

/** Ordered list used by reducers/sorters. Higher impact first. */
export const SEVERITY_ORDER: ReadonlyArray<Severity> = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

/** Numeric rank for comparison; critical = 0 (highest), info = 4 (lowest). */
export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

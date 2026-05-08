/**
 * Severity palette + accessibility helpers — single source of truth for
 * how `critical | high | medium | low | info` severities render.
 *
 * Design goals:
 *   - Restrained severity ladder: warm hues carry risk, cooler/neutral hues
 *     carry lower-priority context. This keeps the shell from reading like a
 *     rainbow while preserving quick scanability.
 *   - Never rely on hue alone: every severity carries a `glyph` + `label`
 *     pair so a grayscale / screen-reader render still conveys the tier.
 *   - Honor `NO_COLOR` (https://no-color.org): any non-empty value on the
 *     env var suppresses color output - `severityStyle(...).color` returns
 *     `undefined` in that mode so renderers can fall back to the terminal
 *     default.
 *   - `KUZUSHI_HIGH_CONTRAST=1` — forces bright variants and `bold` for
 *     every severity so dim/gray text stays legible on high-contrast-white
 *     terminals where default `gray`/`dim` disappears.
 *
 * This module is intentionally pure/presentational. Consumers:
 *
 *   - chalk: `severityChalk("high")("HIGH")` to get the wrapped string.
 *   - plain/SR: `severityToken("high")` always includes the glyph+label.
 *
 * Relationship to `tokens` (`src/ui/tokens.ts`):
 *   The `tokens` vocabulary owns *generic* semantic colors (danger / warn /
 *   info / accent / muted / etc.). Severity is its own axis with its own
 *   accessibility contract (severity ladder + glyph pairing + NO_COLOR /
 *   KUZUSHI_HIGH_CONTRAST), so it is intentionally NOT folded into
 *   `tokens.danger`. Use `severityChalk(sev)(text)` at chalk callsites and
 *   `severityStyle(sev)` in Rust/terminal renderers. Keep `tokens.*` for
 *   non-severity color decisions.
 */

import chalk, { type ChalkInstance } from "chalk";

/** The five severity tiers Kuzushi renders across the TUI + exports. */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/**
 * Terminal color names that map onto the ANSI palette. Staying within the
 * named set lets the terminal's own theme supply the actual hex.
 */
export type TerminalColor =
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
  /** Terminal color name. `undefined` under `NO_COLOR`. */
  color: TerminalColor | undefined;
  /** Bold flag. Forced true under `KUZUSHI_HIGH_CONTRAST`. */
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
 *   - `color` is the preferred terminal color name.
 *   - `glyph` is ALWAYS emitted even when color is suppressed.
 *   - `label` / `longLabel` are plain-text — screen readers speak these.
 *
 * Palette mapping:
 *   critical → bright red               — strongest attention-getter
 *   high     → red                      — urgent, but below critical
 *   medium   → yellow                   — cautionary, not alarming
 *   low      → blue                     — low-priority but still scannable
 *   info     → gray                     — informational/by-design
 */
const BASE_PALETTE: Record<
  Severity,
  Omit<SeverityStyle, "color" | "bold"> & { color: TerminalColor }
> = {
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
      color: "blue",
      glyph: "●", // ● circle
      label: "LOW ",
      longLabel: "LOW",
    },
    info: {
      color: "gray",
      glyph: "○", // ○ hollow circle
      label: "INFO",
      longLabel: "INFO",
    },
};

/**
 * Bright/bold variants used under `KUZUSHI_HIGH_CONTRAST=1`. Every tier
 * upgrades to a `*Bright` color (or stays `redBright`) and forces bold.
 */
const HIGH_CONTRAST_COLOR: Record<Severity, TerminalColor> = {
  critical: "redBright",
  high: "redBright",
  medium: "yellowBright",
  low: "blueBright",
  info: "white",
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

  const color: TerminalColor | undefined = noColor
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
 * ASCII-only severity label for the plain-text renderer / CI stream /
 * piped output. Returns a bracketed token (`"[CRIT]" | "[HIGH]" |
 * "[MED ]" | "[LOW ]" | "[INFO]"`) — fixed-width so columns line up
 * without padding and no Unicode glyphs that mangle on dumb terminals.
 */
const PLAIN_SEVERITY_LABEL: Record<Severity, string> = {
  critical: "[CRIT]",
  high: "[HIGH]",
  medium: "[MED ]",
  low: "[LOW ]",
  info: "[INFO]",
};

export function severityPlainLabel(severity: Severity): string {
  return PLAIN_SEVERITY_LABEL[severity];
}

/**
 * Chalk-wrapped string helper for callsites that already compose strings
 * (plain renderer, CI stream, exports).
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
  // Map terminal color name to chalk style. Chalk exposes each as a property.
  const base = (chalk as unknown as Record<TerminalColor, ChalkInstance>)[colorName] ?? chalk.white;
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

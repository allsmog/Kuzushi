/**
 * Semantic tokens for the Kuzushi TUI Kit.
 *
 * `Tone` is the kit's color vocabulary — the 8-role text theme plus the
 * severity scale and the selection highlight. Every text-bearing component
 * accepts a `tone` and maps it to a `kz-tone-<role>` class defined in
 * styles.css; nothing in the kit takes a raw hex color.
 */

/** The 8-role text theme, the selection highlight, and the severity scale. */
export type Tone =
  | "primary"
  | "muted"
  | "subtle"
  | "accent"
  | "label"
  | "heading"
  | "success"
  | "warn"
  | "danger"
  | "selection"
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "unknown";

/** Console line kinds — each maps to a leading glyph and a tone. */
export type LogKind =
  | "in" // operator input echoed back
  | "run" // a tool / module dispatch
  | "ok" // success
  | "err" // failure / refused
  | "agent" // an LLM agent message
  | "flow" // streaming / in-flight
  | "find" // a finding / red flag
  | "log"; // ambient, low-signal

/** Severity level for {@link SeverityBadge} and severity-toned text. */
export type Severity = "critical" | "high" | "medium" | "low" | "info" | "unknown";

/** Default token set, matching crates/kuzushi-tui/src/theme/mod.rs. */
export const DEFAULT_THEME_TOKENS = {
  termBg: "#0b0d10",
  termBgElev: "#0f1115",
  chromeBg: "#15181d",
  primary: "#cfd6e0",
  muted: "#7d8794",
  subtle: "#3d4654",
  accent: "#7fb8ff",
  label: "#a6cdff",
  heading: "#ffffff",
  success: "#57c479",
  warn: "#e2c14a",
  danger: "#e25c5c",
  selectionFg: "#0b0d10",
  selectionBg: "#7fb8ff",
  sevCritical: "#e25c5c",
  sevHigh: "#ff8b8b",
  sevMedium: "#e2c14a",
  sevLow: "#8aa6c4",
  sevInfo: "#8aa6c4",
  sevUnknown: "#7d8794",
} as const;

/** High-contrast token set, matching Rust's high_contrast style branches. */
export const HIGH_CONTRAST_THEME_TOKENS = {
  ...DEFAULT_THEME_TOKENS,
  primary: "#ffffff",
  muted: "#cfd6e0",
  subtle: "#7d8794",
  accent: "#ffffff",
  label: "#ffffff",
  heading: "#ffffff",
  sevCritical: "#e25c5c",
  sevHigh: "#e25c5c",
  sevMedium: "#e2c14a",
  sevLow: "#ffffff",
  sevInfo: "#ffffff",
  sevUnknown: "#cfd6e0",
} as const;

export const THEME_TOKENS = {
  default: DEFAULT_THEME_TOKENS,
  "high-contrast": HIGH_CONTRAST_THEME_TOKENS,
} as const;

export type ThemeName = keyof typeof THEME_TOKENS;
export type ThemeTokenName = keyof typeof DEFAULT_THEME_TOKENS;

/** Resolve a {@link Tone} to its stylesheet class. */
export function toneClass(tone?: Tone): string | undefined {
  return tone ? `kz-tone-${tone}` : undefined;
}

/** The glyph + tone each {@link LogKind} renders with. */
export const LOG_GLYPH: Record<LogKind, { glyph: string; tone: Tone }> = {
  in: { glyph: "●", tone: "accent" },
  run: { glyph: "⏵", tone: "primary" },
  ok: { glyph: "✓", tone: "success" },
  err: { glyph: "✗", tone: "danger" },
  agent: { glyph: "◆", tone: "accent" },
  flow: { glyph: "…", tone: "muted" },
  find: { glyph: "▸", tone: "warn" },
  log: { glyph: "·", tone: "subtle" },
};

/** Default grid width, in monospace cells, of a full terminal frame. */
export const DEFAULT_COLS = 96;

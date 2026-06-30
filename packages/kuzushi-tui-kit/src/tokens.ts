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
  | "low";

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
export type Severity = "critical" | "high" | "medium" | "low";

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

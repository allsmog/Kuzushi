import { type Severity, toneClass } from "./tokens";

const GLYPH: Record<Severity, string> = {
  critical: "C",
  high: "H",
  medium: "M",
  low: "L",
  info: "I",
  unknown: "?",
};

export interface SeverityBadgeProps {
  /** The severity level — sets the color and the default label. */
  level: Severity;
  /** Override the displayed text (defaults to the upper-cased level). */
  label?: string;
  /**
   * Render the compact single-letter glyph (`C/H/M/L/I/?`) instead of the word,
   * as the review queue does when a row is too narrow for the full band.
   */
  glyph?: boolean;
}

/**
 * A severity chip — bold, space-padded, coloured text in the severity scale
 * (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`). Drop it inline in a finding
 * line or a {@link Row} to mark a finding's severity. Pass `glyph` for the
 * compact single-letter form (`C/H/M/L/I/?`) the review queue uses in narrow rows.
 *
 * @example
 * <SeverityBadge level="critical" />
 * <SeverityBadge level="high" glyph />
 * <SeverityBadge level="low" label="LOW · accepted" />
 */
export function SeverityBadge({ level, label, glyph }: SeverityBadgeProps) {
  const text = label ?? (glyph ? GLYPH[level] : level.toUpperCase());
  return <span className={`kz-badge ${toneClass(level)}`}>{` ${text} `}</span>;
}

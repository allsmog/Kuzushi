import { type Severity, toneClass } from "./tokens";

export interface SeverityBadgeProps {
  /** The severity level — sets the color and the default label. */
  level: Severity;
  /** Override the displayed text (defaults to the upper-cased level). */
  label?: string;
}

/**
 * A severity chip — bold, space-padded, colored text in the severity scale
 * (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`). Drop it inline in a finding line
 * or a {@link Row} to mark a finding's severity.
 *
 * @example
 * <SeverityBadge level="critical" />
 * <SeverityBadge level="low" label="LOW · accepted" />
 */
export function SeverityBadge({ level, label }: SeverityBadgeProps) {
  const text = label ?? level.toUpperCase();
  return <span className={`kz-badge ${toneClass(level)}`}>{` ${text} `}</span>;
}

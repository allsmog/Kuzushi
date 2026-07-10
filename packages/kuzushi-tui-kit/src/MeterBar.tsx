import { Glyph } from "./Glyph";
import { type Tone, toneClass } from "./tokens";

export interface MeterBarProps {
  /** Current value (e.g. dollars spent, files covered). */
  value: number;
  /** The cap / total the bar fills toward. */
  max: number;
  /** Leading label (e.g. `budget`, `coverage`). */
  label?: string;
  /** Bar width in monospace cells. */
  width?: number;
  /**
   * Filled-segment tone. Omit to auto-tone by fill ratio — accent under 70%,
   * `warn` at 70%+, `danger` at 90%+ (the Rust budget meter's thresholds).
   * Pass a tone to override the ramp.
   */
  tone?: Tone;
  /** Readout text shown after the bar; defaults to `value / max`. */
  readout?: string;
}

function clampFill(value: number, max: number, width: number): number {
  if (max <= 0) return 0;
  return Math.max(0, Math.min(width, Math.round((value / max) * width)));
}

/** The Rust budget-meter ramp: ≥0.9 danger, ≥0.7 warn, else accent. */
function ratioTone(value: number, max: number): Tone {
  const ratio = max > 0 ? value / max : 0;
  if (ratio >= 0.9) return "danger";
  if (ratio >= 0.7) return "warn";
  return "accent";
}

/**
 * A `▓▓▓░░` meter for a bounded quantity — the budget cap, sweep coverage, a
 * verify pass. Filled cells auto-tone by how full the bar is (accent → `warn`
 * at 70% → `danger` at 90%), exactly like the Rust cockpit's budget line, so a
 * near-cap meter reads hot without any caller wiring; empty cells stay subtle.
 * Cost is always visible in the control room, so this is the budget line's
 * building block. Drop it inside a {@link Row}.
 *
 * @example
 * <Row><MeterBar label="budget" value={0.85} max={2} readout="$0.85 / $2.00" /></Row>
 * <Row><MeterBar label="coverage" value={7} max={12} width={16} tone="success" /></Row>
 */
export function MeterBar({ value, max, label, width = 12, tone, readout }: MeterBarProps) {
  const filled = clampFill(value, max, width);
  const fillTone = tone ?? ratioTone(value, max);
  const text = readout ?? `${value} / ${max}`;
  return (
    <>
      {label ? <Glyph tone="muted">{`${label} `}</Glyph> : null}
      <span className={toneClass(fillTone)}>{"▓".repeat(filled)}</span>
      <Glyph tone="subtle">{"░".repeat(width - filled)}</Glyph>
      <Glyph tone="primary">{`  ${text}`}</Glyph>
    </>
  );
}

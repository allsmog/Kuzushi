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
  /** Filled-segment tone (default `accent`; shift to `warn`/`danger` near the cap). */
  tone?: Tone;
  /** Readout text shown after the bar; defaults to `value / max`. */
  readout?: string;
}

function clampFill(value: number, max: number, width: number): number {
  if (max <= 0) return 0;
  return Math.max(0, Math.min(width, Math.round((value / max) * width)));
}

/**
 * A `▓▓▓░░` meter for a bounded quantity — the budget cap, sweep coverage, a
 * verify pass. Filled cells take the given tone (shift it to `warn` or `danger`
 * as the value nears the cap); empty cells stay subtle. Cost is always visible
 * in the control room, so this is the budget line's building block. Drop it
 * inside a {@link Row}.
 *
 * @example
 * <Row><MeterBar label="budget" value={0.85} max={2} readout="$0.85 / $2.00" tone="warn" /></Row>
 * <Row><MeterBar label="coverage" value={7} max={12} width={16} /></Row>
 */
export function MeterBar({ value, max, label, width = 12, tone = "accent", readout }: MeterBarProps) {
  const filled = clampFill(value, max, width);
  const text = readout ?? `${value} / ${max}`;
  return (
    <>
      {label ? <Glyph tone="muted">{`${label} `}</Glyph> : null}
      <span className={toneClass(tone)}>{"▓".repeat(filled)}</span>
      <Glyph tone="subtle">{"░".repeat(width - filled)}</Glyph>
      <Glyph tone="primary">{`  ${text}`}</Glyph>
    </>
  );
}

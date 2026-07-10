import { Glyph } from "./Glyph";
import type { Tone } from "./tokens";

export interface StatusChipProps {
  /** Optional leading glyph (e.g. `●`, `○`, `✓`, `⚠`). */
  glyph?: string;
  /** The chip text (e.g. `LIVE`, `ctx: built`, `scope: on`). */
  label: string;
  /** Semantic tone for the chip (default `muted`). */
  tone?: Tone;
}

/**
 * A single status chip for the cockpit chrome — a glyph + a short label in one
 * tone. It is the building block for the top-bar / footer indicators the Rust
 * shell shows: liveness (`● LIVE` success / `○ idle` subtle), context freshness
 * (`✓ ctx: built` success / `ctx: not built` muted / `⚠ ctx: malformed` warn),
 * and the bug-bounty scope gate (`scope: on` success). Separate several with
 * the ` · ` the strip uses between fields.
 *
 * @example
 * <StatusChip glyph="●" label="LIVE" tone="success" />
 * <StatusChip glyph="✓" label="ctx: built" tone="success" />
 * <StatusChip label="scope: on" tone="success" />
 */
export function StatusChip({ glyph, label, tone = "muted" }: StatusChipProps) {
  return (
    <Glyph tone={tone}>{glyph ? `${glyph} ${label}` : label}</Glyph>
  );
}

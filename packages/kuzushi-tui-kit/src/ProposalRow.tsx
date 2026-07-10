import { Glyph } from "./Glyph";
import { Row } from "./Row";
import type { Tone } from "./tokens";

/**
 * A proposal's disposition in the hunt queue, mirroring the Rust
 * `proposal_marker` set: awaiting a keep/skip decision, kept (approved), skipped
 * (rejected), running (dispatched, in flight), or failed.
 */
export type ProposalState = "proposed" | "kept" | "skipped" | "running" | "failed";

const MARK: Record<ProposalState, { glyph: string; tone: Tone }> = {
  proposed: { glyph: "▸", tone: "accent" },
  kept: { glyph: "✓", tone: "success" },
  skipped: { glyph: "✗", tone: "subtle" },
  running: { glyph: "⠿", tone: "accent" },
  failed: { glyph: "!", tone: "danger" },
};

export interface ProposalRowProps {
  /** Proposal id (e.g. `P-001`). */
  id: string;
  /** What the proposal would hunt (e.g. `incomplete-fix hunt`). */
  title: string;
  /** The signal generator that proposed it (e.g. `commits`, `threat-model`). */
  generator?: string;
  /** Estimated price (e.g. `$0.40`). */
  price?: string;
  /** Yield score, 0–1 (rendered as `.82`). */
  yieldScore?: number;
  /** proposed · kept · skipped — sets the leading marker. */
  state?: ProposalState;
  /** Highlight as the j/k cursor line. */
  selected?: boolean;
  /** Fix the row to a grid width in cells. */
  cols?: number;
}

function fmtYield(y?: number): string | null {
  if (y == null) return null;
  return y.toFixed(2).replace(/^0/, "");
}

/**
 * One priced, budget-gated hunt proposal — a candidate scan the operator keeps
 * or skips before firing. A signal generator (commit-archaeology, threat-model,
 * dep-intel, …) proposes it with an estimated `price` and a `yield` score; the
 * row shows `id · title · generator · $price · yield`, a keep/skip hint, and its
 * disposition marker. Stack these to build the hunt queue.
 *
 * @example
 * <ProposalRow id="P-001" title="incomplete-fix hunt" generator="commits"
 *   price="$0.40" yieldScore={0.82} state="kept" cols={64} />
 */
export function ProposalRow({
  id,
  title,
  generator,
  price,
  yieldScore,
  state = "proposed",
  selected,
  cols,
}: ProposalRowProps) {
  const mark = MARK[state];
  const y = fmtYield(yieldScore);
  const meta = [generator, price, y != null ? `yield ${y}` : null].filter(Boolean).join(" · ");
  return (
    <Row cols={cols} selected={selected}>
      {" "}
      <Glyph tone={mark.tone}>{mark.glyph}</Glyph>{" "}
      <Glyph tone="accent">{id}</Glyph>
      {"  "}
      <Glyph tone="primary">{title}</Glyph>
      {meta ? <Glyph tone="muted">{`  ${meta}`}</Glyph> : null}
      {state === "proposed" ? <Glyph tone="muted">{"   [k/s]"}</Glyph> : null}
    </Row>
  );
}

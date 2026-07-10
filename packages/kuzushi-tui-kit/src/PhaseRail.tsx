import { Fragment } from "react";
import { Glyph } from "./Glyph";
import { Row } from "./Row";
import type { Tone } from "./tokens";

/**
 * Where a phase actually stands, derived from engagement reality — mirroring
 * the Rust `JourneyPhaseState`. `done` ✓, the single `current` ●, and the
 * `pending`/`failed`/`skipped` bands each carry their own glyph and tone.
 */
export type PhaseState = "done" | "current" | "pending" | "failed" | "skipped";

export interface Phase {
  /** Phase name (e.g. `hunt`). Rendered upper-cased when it is the current phase. */
  label: string;
  /** Optional leading kanji (組 崩 作 掛 …), matching the Rust journey rail. */
  kanji?: string;
  /** done · current · pending · failed · skipped — exactly one phase should be `current`. */
  state: PhaseState;
}

const STATE: Record<PhaseState, { tone: Tone; glyph: string }> = {
  done: { tone: "success", glyph: "✓" },
  current: { tone: "warn", glyph: "●" },
  failed: { tone: "danger", glyph: "!" },
  skipped: { tone: "muted", glyph: "⊘" },
  pending: { tone: "subtle", glyph: "·" },
};

export interface PhaseRailProps {
  /** The ordered phases (組 map → 崩 hunt → 作 confirm → 掛 fix → report). */
  phases: Phase[];
  /** Fix the rail to a grid width in cells. */
  cols?: number;
}

/**
 * The engagement phase rail: the 組 map → 崩 hunt → 作 confirm → 掛 fix → report
 * spine, each phase coloured by where the engagement actually is — mirroring the
 * Rust journey rail exactly. `done` reads success + ✓, the single `current` phase
 * reads warn + ● and upper-cased, `pending` stays subtle + ·, and the off-path
 * `failed` (! danger) / `skipped` (⊘ muted) bands are honest about reality.
 * Phases join with ` · `. State comes from workspace reality, never the viewed
 * page, so the rail never fabricates progress.
 *
 * @example
 * <PhaseRail cols={72} phases={[
 *   { kanji: "組", label: "map", state: "done" },
 *   { kanji: "崩", label: "hunt", state: "current" },
 *   { kanji: "作", label: "confirm", state: "pending" },
 *   { kanji: "掛", label: "fix", state: "pending" },
 * ]} />
 */
export function PhaseRail({ phases, cols }: PhaseRailProps) {
  return (
    <Row cols={cols}>
      {" "}
      {phases.map((p, i) => {
        const s = STATE[p.state];
        const name = p.state === "current" ? p.label.toUpperCase() : p.label;
        return (
          <Fragment key={p.label}>
            {p.kanji ? <Glyph tone={s.tone}>{`${p.kanji} `}</Glyph> : null}
            <Glyph tone={s.tone} bold={p.state === "current"}>
              {name}
            </Glyph>
            <Glyph tone={s.tone}>{` ${s.glyph}`}</Glyph>
            {i !== phases.length - 1 ? <Glyph tone="subtle">{" · "}</Glyph> : null}
          </Fragment>
        );
      })}
    </Row>
  );
}

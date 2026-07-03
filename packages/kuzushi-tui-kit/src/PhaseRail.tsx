import { Fragment } from "react";
import { Glyph } from "./Glyph";
import { Row } from "./Row";
import type { Tone } from "./tokens";

/** Where a phase actually stands, derived from engagement reality. */
export type PhaseState = "done" | "current" | "todo";

export interface Phase {
  /** Phase name (e.g. `hunt`). Rendered upper-cased when it is the current phase. */
  label: string;
  /** Optional leading kanji (組 崩 作 掛 …), matching the Rust journey rail. */
  kanji?: string;
  /** done · current · todo — exactly one phase should be `current`. */
  state: PhaseState;
}

const STATE: Record<PhaseState, { tone: Tone; glyph: string }> = {
  done: { tone: "success", glyph: " ✓" },
  current: { tone: "accent", glyph: " ▸" },
  todo: { tone: "subtle", glyph: "" },
};

export interface PhaseRailProps {
  /** The ordered phases (組 map → 崩 hunt → 作 confirm → 掛 fix → report). */
  phases: Phase[];
  /** Fix the rail to a grid width in cells. */
  cols?: number;
}

/**
 * The engagement phase rail: the 組 map → 崩 hunt → 作 confirm → 掛 fix → report
 * spine, each phase colored by where the engagement actually is. `done` reads
 * success + ✓, the single `current` phase reads accent + ▸ and upper-cased, and
 * `todo` phases stay subtle. It mirrors the Rust journey rail — state comes from
 * workspace reality, never the viewed page, so it never fabricates progress.
 *
 * @example
 * <PhaseRail cols={72} phases={[
 *   { kanji: "組", label: "aim", state: "done" },
 *   { kanji: "崩", label: "hunt", state: "current" },
 *   { kanji: "作", label: "confirm", state: "todo" },
 *   { kanji: "掛", label: "fix", state: "todo" },
 *   { kanji: "▪", label: "report", state: "todo" },
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
            {s.glyph ? <Glyph tone={s.tone}>{s.glyph}</Glyph> : null}
            {i !== phases.length - 1 ? "   " : null}
          </Fragment>
        );
      })}
    </Row>
  );
}

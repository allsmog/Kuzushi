import { type Tone, toneClass } from "./tokens";

/** A finding's proof state — the confirmed-vs-guess signal. */
export type ProofState = "confirmed" | "candidate" | "unverified" | "rejected";

const PROOF: Record<ProofState, { glyph: string; tone: Tone; word: string }> = {
  confirmed: { glyph: "✓", tone: "success", word: "confirmed" },
  candidate: { glyph: "◇", tone: "warn", word: "candidate" },
  unverified: { glyph: "?", tone: "muted", word: "unverified" },
  rejected: { glyph: "!", tone: "danger", word: "rejected" },
};

export interface ProofBadgeProps {
  /** The proof state: confirmed (✓), candidate (◇), unverified (?), or rejected (!). */
  state: ProofState;
  /** Override the label (defaults to the state word — e.g. `confirmed · path`). */
  label?: string;
  /** Render only the marker glyph, without the word. */
  glyphOnly?: boolean;
}

/**
 * The confirmed-vs-guess proof marker for a finding — the kit's trust primitive.
 * A guilty-until-proven-innocent verifier promotes a finding up the evidence
 * ladder; this badge shows where it landed: `✓ confirmed` (success), `◇ candidate`
 * (warn), `? unverified` (muted), `! rejected` (danger). Put one on every finding
 * row so the ledger reads confirmed-vs-guess at a glance — not only in the detail
 * pane.
 *
 * @example
 * <ProofBadge state="confirmed" />
 * <ProofBadge state="candidate" label="candidate · linked" />
 * <ProofBadge state="unverified" glyphOnly />
 */
export function ProofBadge({ state, label, glyphOnly }: ProofBadgeProps) {
  const p = PROOF[state];
  const text = glyphOnly ? p.glyph : `${p.glyph} ${label ?? p.word}`;
  return <span className={`kz-badge ${toneClass(p.tone)}`}>{text}</span>;
}

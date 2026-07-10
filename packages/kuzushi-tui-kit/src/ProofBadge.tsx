import { type Tone, toneClass } from "./tokens";

/**
 * A finding's proof confidence — the confirmed-vs-guess signal, mirroring the
 * Rust `ProofConfidence` ladder. The strong bands (`confirmed`, `likely`) are
 * uppercased for prominence; the honest lower bands stay lowercase.
 */
export type ProofState = "confirmed" | "likely" | "unverified" | "dismissed";

const PROOF: Record<ProofState, { glyph: string; tone: Tone; word: string }> = {
  confirmed: { glyph: "✓", tone: "success", word: "CONFIRMED" },
  likely: { glyph: "◇", tone: "accent", word: "LIKELY" },
  unverified: { glyph: "?", tone: "muted", word: "unverified" },
  dismissed: { glyph: "·", tone: "dim", word: "dismissed" },
};

export interface ProofBadgeProps {
  /**
   * The proof confidence: `confirmed` (✓ green, runtime-exploited), `likely`
   * (◇ blue, static evidence links it), `unverified` (? grey, the honest
   * unknown), or `dismissed` (· dim, statically rejected / false-positive).
   */
  state: ProofState;
  /** Override the label (defaults to the state word — e.g. `LIKELY · source→sink`). */
  label?: string;
  /** Render only the marker glyph, without the word. */
  glyphOnly?: boolean;
}

/**
 * The confirmed-vs-guess proof chip for a finding — the kit's trust primitive.
 * A guilty-until-proven-innocent verifier promotes a finding up the evidence
 * ladder; this chip shows where it landed and colours it exactly like the Rust
 * cockpit: `✓ CONFIRMED` (success, runtime-verified), `◇ LIKELY` (accent,
 * statically linked), `? unverified` (muted, the honest unknown), `· dismissed`
 * (dim, rejected / false-positive). Put one on every finding row so the ledger
 * reads confidence-first at a glance — not only in the detail pane.
 *
 * @example
 * <ProofBadge state="confirmed" />
 * <ProofBadge state="likely" label="LIKELY · source→sink" />
 * <ProofBadge state="unverified" glyphOnly />
 */
export function ProofBadge({ state, label, glyphOnly }: ProofBadgeProps) {
  const p = PROOF[state];
  const text = glyphOnly ? p.glyph : `${p.glyph} ${label ?? p.word}`;
  return <span className={`kz-badge ${toneClass(p.tone)}`}>{text}</span>;
}

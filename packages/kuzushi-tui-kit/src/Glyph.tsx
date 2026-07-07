import type { ReactNode } from "react";
import { type Tone, toneClass } from "./tokens";

export interface GlyphProps {
  /** Semantic color role applied to the text run. */
  tone?: Tone;
  /** Render bold regardless of the tone's default weight. */
  bold?: boolean;
  /** The text or status glyph (e.g. `✓`, `▸`, `F-0012`). */
  children: ReactNode;
}

/**
 * A run of text or a status glyph in one semantic tone — the kit's atomic
 * colored span. Use it for status markers (`✓` success, `✗` danger, `▸` find),
 * labels, finding ids, and any inline emphasis inside a {@link Row}.
 *
 * @example
 * <Glyph tone="success">✓</Glyph>
 * <Glyph tone="accent">F-0012</Glyph>
 */
export function Glyph({ tone, bold, children }: GlyphProps) {
  const cls = toneClass(tone);
  return (
    <span
      className={cls}
      style={bold ? { fontWeight: 700 } : undefined}
    >
      {children}
    </span>
  );
}

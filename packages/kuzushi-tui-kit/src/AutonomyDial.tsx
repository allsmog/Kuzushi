import { Glyph } from "./Glyph";

/** An autonomy posture rung — how far the operator lets the walker run unattended. */
export type AutonomyRung = "recon" | "hunt" | "confirm" | "fix";

const RUNG_KANJI: Record<AutonomyRung, string> = {
  recon: "組",
  hunt: "崩",
  confirm: "作",
  fix: "掛",
};

export interface AutonomyDialProps {
  /** The current posture rung — its ceiling phase sets the kanji. */
  rung: AutonomyRung;
  /**
   * Show the `⚠` throttle marker — the dial is capping the walker below the
   * phase the engagement has actually reached.
   */
  throttled?: boolean;
}

/**
 * The autonomy dial chip — `⛭ <kanji> <rung>`, the always-visible posture
 * indicator, mirroring the Rust `autonomy_footer_segment`. The gear `⛭` is
 * constant; the kanji is the rung's ceiling phase (recon 組 · hunt 崩 · confirm
 * 作 · fix 掛). A trailing `⚠` (warn) appears when the dial is throttling — its
 * ceiling sits below where the engagement has actually reached — so raising or
 * lowering the dial never silently forges or blocks progress.
 *
 * @example
 * <AutonomyDial rung="fix" />
 * <AutonomyDial rung="recon" throttled />
 */
export function AutonomyDial({ rung, throttled }: AutonomyDialProps) {
  return (
    <>
      <Glyph tone="accent">⛭ </Glyph>
      <Glyph tone="primary">{`${RUNG_KANJI[rung]} ${rung}`}</Glyph>
      {throttled ? <Glyph tone="warn"> ⚠</Glyph> : null}
    </>
  );
}

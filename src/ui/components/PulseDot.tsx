/**
 * Pulsing `⏺` glyph — cc-repo's ToolUseLoader equivalent.
 *
 * Uses the shared `SpinnerClock` frame so every pulse ticks in phase with
 * the rest of the UI (no independent setInterval bleed).
 *
 * The pulse is now a low-motion intensity cycle instead of a hard hide/show
 * blink. That keeps the row visibly alive without the "disappearing dot"
 * flicker that reads as layout instability in a busy TUI.
 */

import { Text } from "ink";
import React from "react";
import { BLACK_CIRCLE } from "../glyphs.js";
import { useSpinnerFrame } from "../primitives/SpinnerClock.js";
import { tokens } from "../tokens.js";

type PulseStatus = "running" | "warn" | "ok" | "fail" | "abort";

interface PulseDotProps {
  /** Lifecycle state — chooses color + whether the glyph animates. */
  status: PulseStatus;
}

/**
 * Maps status → ANSI color wrapper. `running` and `warn` both animate;
 * resolved states render solid. `warn` is used when a running tool has
 * been silent for ≥15s (ToolRunningStatus staleness affordance).
 */
const COLOR_BY_STATUS: Record<PulseStatus, (s: string) => string> = {
  running: tokens.accent,
  warn: tokens.warn,
  ok: tokens.success,
  fail: tokens.danger,
  abort: tokens.muted,
};

export const PulseDot = React.memo(function PulseDot({
  status,
}: PulseDotProps): React.ReactElement {
  const frame = useSpinnerFrame();
  const pulseFrame = Math.floor(frame / 2) % 4;

  if (status === "running") {
    const runningFrames = [tokens.subtle, tokens.accent, tokens.focus, tokens.accent] as const;
    return <Text>{runningFrames[pulseFrame]!(BLACK_CIRCLE)}</Text>;
  }

  if (status === "warn") {
    const warnFrames = [tokens.muted, tokens.warn, tokens.warnStrong, tokens.warn] as const;
    return <Text>{warnFrames[pulseFrame]!(BLACK_CIRCLE)}</Text>;
  }

  const colorFn = COLOR_BY_STATUS[status];
  return <Text>{colorFn(BLACK_CIRCLE)}</Text>;
});

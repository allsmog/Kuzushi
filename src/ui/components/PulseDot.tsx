/**
 * Pulsing `⏺` glyph — cc-repo's ToolUseLoader equivalent.
 *
 * Uses the shared `SpinnerClock` frame so every pulse ticks in phase with
 * the rest of the UI (no independent setInterval bleed).
 *
 * The pulse is a visibility toggle: `⏺` → space → `⏺` → space …, at a
 * ~400ms rate (every other 200ms spinner tick). This matches cc-repo's
 * `useBlink` behavior and preserves baseline alignment because space is
 * rendered inside a `Gutter` (fixed width) so layout never shifts.
 */

import { Text } from "ink";
import React from "react";
import { useSpinnerFrame } from "../primitives/SpinnerClock.js";
import { tokens } from "../tokens.js";
import { BLACK_CIRCLE } from "../glyphs.js";

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
  // Pulse at 400ms (every 2 ticks) while running or waiting; solid glyph
  // otherwise.
  const animates = status === "running" || status === "warn";
  const visible = animates ? Math.floor(frame / 2) % 2 === 0 : true;
  const colorFn = COLOR_BY_STATUS[status];
  return <Text>{visible ? colorFn(BLACK_CIRCLE) : " "}</Text>;
});

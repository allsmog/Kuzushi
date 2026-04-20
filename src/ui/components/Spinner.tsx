/**
 * Animated braille-dot spinner component.
 *
 * Reads the current frame from the shared `SpinnerClockContext` so all
 * spinners tick in phase with a single interval — no more N independent
 * setIntervals causing cascading subtree re-renders (see SpinnerClock.tsx).
 */

import { Text } from "ink";
import React from "react";
import { useSpinnerFrame } from "../primitives/SpinnerClock.js";
import { tokens } from "../tokens.js";

const FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/** Semantic spinner colors — map onto the shared token palette. */
export type SpinnerColor = "accent" | "success" | "warn" | "danger" | "muted";

interface SpinnerProps {
  label?: string;
  color?: SpinnerColor;
}

const COLOR_MAP: Record<SpinnerColor, (text: string) => string> = {
  accent: tokens.accent,
  success: tokens.success,
  warn: tokens.warn,
  danger: tokens.danger,
  muted: tokens.muted,
};

export const Spinner = React.memo(function Spinner({
  label,
  color = "accent",
}: SpinnerProps): React.ReactElement {
  const frame = useSpinnerFrame();
  const glyph = FRAMES[frame % FRAMES.length]!;
  const colorFn = COLOR_MAP[color] ?? tokens.accent;
  return (
    <Text>
      {colorFn(glyph)}
      {label ? ` ${label}` : ""}
    </Text>
  );
});

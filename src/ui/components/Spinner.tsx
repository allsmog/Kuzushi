/**
 * Animated braille-dot spinner component.
 * Cycles through frames for a smooth loading animation.
 */

import { Text } from "ink";
import type React from "react";
import { useEffect, useState } from "react";
import { tokens } from "../tokens.js";

const FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const FRAME_INTERVAL = 80; // ms per frame

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

export function Spinner({ label, color = "accent" }: SpinnerProps): React.ReactElement {
  const [frameIndex, setFrameIndex] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setFrameIndex((prev) => (prev + 1) % FRAMES.length);
    }, FRAME_INTERVAL);
    return () => clearInterval(timer);
  }, []);

  const frame = FRAMES[frameIndex]!;
  const colorFn = COLOR_MAP[color] ?? tokens.accent;
  const coloredFrame = colorFn(frame);

  return (
    <Text>
      {coloredFrame}
      {label ? ` ${label}` : ""}
    </Text>
  );
}

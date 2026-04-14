/**
 * Animated braille-dot spinner component.
 * Cycles through frames for a smooth loading animation.
 */
import React, { useState, useEffect } from "react";
import { Text } from "ink";
import chalk from "chalk";

const FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const FRAME_INTERVAL = 80; // ms per frame

interface SpinnerProps {
  label?: string;
  color?: "green" | "yellow" | "cyan" | "magenta" | "red";
}

export function Spinner({ label, color = "cyan" }: SpinnerProps): React.ReactElement {
  const [frameIndex, setFrameIndex] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setFrameIndex((prev) => (prev + 1) % FRAMES.length);
    }, FRAME_INTERVAL);
    return () => clearInterval(timer);
  }, []);

  const frame = FRAMES[frameIndex]!;
  const colorFn = chalk[color] ?? chalk.cyan;
  const coloredFrame = colorFn(frame);

  return (
    <Text>
      {coloredFrame}
      {label ? ` ${label}` : ""}
    </Text>
  );
}

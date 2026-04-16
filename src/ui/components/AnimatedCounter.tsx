/**
 * Animated counter — counts up from 0 to a target number with ease-out.
 *
 * Fast at start, slows down near the target, like a slot machine settling.
 * Used for the finding count reveal after scan completes.
 */

import { Text } from "ink";
import type React from "react";
import { useEffect, useState } from "react";

interface AnimatedCounterProps {
  /** Target number to count up to. */
  target: number;
  /** Duration of the animation in ms (default 1200). */
  durationMs?: number;
  /** Tick interval in ms (default 40 for smooth 25fps). */
  tickMs?: number;
  /** Prefix text before the number. */
  prefix?: string;
  /** Suffix text after the number. */
  suffix?: string;
  /** Chalk function to apply to the number. */
  color?: (text: string) => string;
}

export function AnimatedCounter({
  target,
  durationMs = 1200,
  tickMs = 40,
  prefix = "",
  suffix = "",
  color,
}: AnimatedCounterProps): React.ReactElement {
  const [current, setCurrent] = useState(0);

  useEffect(() => {
    if (target <= 0) {
      setCurrent(target);
      return;
    }

    const startTime = Date.now();
    const interval = setInterval(() => {
      const elapsed = Date.now() - startTime;
      const progress = Math.min(1, elapsed / durationMs);

      // Ease-out cubic: fast start, slow finish
      const eased = 1 - (1 - progress) ** 3;
      const value = Math.round(eased * target);

      setCurrent(value);

      if (progress >= 1) {
        setCurrent(target);
        clearInterval(interval);
      }
    }, tickMs);

    return () => clearInterval(interval);
  }, [target, durationMs, tickMs]);

  const formatted = current.toLocaleString();
  const display = color ? color(formatted) : formatted;

  return (
    <Text>
      {prefix}
      {display}
      {suffix}
    </Text>
  );
}

/**
 * Shared spinner clock — one setInterval for all spinners.
 *
 * Previously, every `<Spinner>` instance owned its own setInterval. With
 * many spinners visible at once (stage headers, scan sub-tasks, monorepo
 * module rows), each interval ticked independently and caused cascading
 * subtree re-renders at slightly-offset times — visible as flicker.
 *
 * With this context, all spinners read `frame` from one clock and tick
 * in phase. The clock only runs while a small number of indicators is
 * mounted; crowded views render static glyphs because many animated
 * cells force whole-frame terminal repaints that read as flicker.
 *
 * Inspired by CC's useAnimationFrame hook in cc-repo/src/ink/hooks/
 * use-animation-frame.ts.
 */

import React from "react";

const FRAME_INTERVAL_MS = 400;
const MAX_ANIMATED_SUBSCRIBERS = 3;

const SpinnerClockContext = React.createContext<{
  frame: number;
  motionEnabled: boolean;
  register: () => () => void;
}>({
  frame: 0,
  motionEnabled: false,
  register: () => () => {},
});

export function SpinnerClockProvider({
  children,
}: {
  children: React.ReactNode;
}): React.ReactElement {
  const [frame, setFrame] = React.useState(0);
  const [subscriberCount, setSubscriberCount] = React.useState(0);
  const motionEnabled = subscriberCount > 0 && subscriberCount <= MAX_ANIMATED_SUBSCRIBERS;

  const register = React.useCallback((): (() => void) => {
    setSubscriberCount((count) => count + 1);
    return () => {
      setSubscriberCount((count) => Math.max(0, count - 1));
    };
  }, []);

  React.useEffect(() => {
    if (!motionEnabled) return;
    const id = setInterval(() => {
      setFrame((f) => (f + 1) % 10_000);
    }, FRAME_INTERVAL_MS);
    return () => clearInterval(id);
  }, [motionEnabled]);

  const value = React.useMemo(
    () => ({ frame: motionEnabled ? frame : 0, motionEnabled, register }),
    [frame, motionEnabled, register],
  );

  return <SpinnerClockContext.Provider value={value}>{children}</SpinnerClockContext.Provider>;
}

/**
 * Subscribe to the shared spinner clock. Each call to `useSpinnerFrame`
 * registers one subscriber; the clock only runs while ≥1 subscribers exist.
 */
export function useSpinnerFrame(): number {
  const { frame, register } = React.useContext(SpinnerClockContext);
  React.useEffect(() => register(), [register]);
  return frame;
}

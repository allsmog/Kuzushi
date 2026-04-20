/**
 * Shared spinner clock — one setInterval for all spinners.
 *
 * Previously, every `<Spinner>` instance owned its own setInterval. With
 * many spinners visible at once (stage headers, scan sub-tasks, monorepo
 * module rows), each interval ticked independently and caused cascading
 * subtree re-renders at slightly-offset times — visible as flicker.
 *
 * With this context, all spinners read `frame` from one clock and tick
 * in phase. The clock only runs while at least one spinner is mounted
 * (tracked via a subscriber counter ref) so we don't burn CPU when the
 * UI is in preflight/summary/done modes.
 *
 * Inspired by CC's useAnimationFrame hook in cc-repo/src/ink/hooks/
 * use-animation-frame.ts.
 */

import React from "react";

const FRAME_INTERVAL_MS = 200;

const SpinnerClockContext = React.createContext<{
  frame: number;
  register: () => () => void;
}>({
  frame: 0,
  register: () => () => {},
});

export function SpinnerClockProvider({
  children,
}: {
  children: React.ReactNode;
}): React.ReactElement {
  const [frame, setFrame] = React.useState(0);
  const subscriberCountRef = React.useRef(0);
  const intervalRef = React.useRef<NodeJS.Timeout | null>(null);

  const startTicking = React.useCallback(() => {
    if (intervalRef.current != null) return;
    intervalRef.current = setInterval(() => {
      setFrame((f) => (f + 1) % 10_000);
    }, FRAME_INTERVAL_MS);
  }, []);

  const stopTicking = React.useCallback(() => {
    if (intervalRef.current == null) return;
    clearInterval(intervalRef.current);
    intervalRef.current = null;
  }, []);

  const register = React.useCallback((): (() => void) => {
    subscriberCountRef.current += 1;
    if (subscriberCountRef.current === 1) startTicking();
    return () => {
      subscriberCountRef.current = Math.max(0, subscriberCountRef.current - 1);
      if (subscriberCountRef.current === 0) stopTicking();
    };
  }, [startTicking, stopTicking]);

  React.useEffect(() => {
    // Cleanup on unmount: stop the interval regardless of counter state.
    return () => stopTicking();
  }, [stopTicking]);

  const value = React.useMemo(() => ({ frame, register }), [frame, register]);

  return (
    <SpinnerClockContext.Provider value={value}>{children}</SpinnerClockContext.Provider>
  );
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

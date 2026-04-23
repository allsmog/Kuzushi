import type React from "react";
import { createContext, useContext, useEffect, useState } from "react";

export interface UiClock {
  now(): number;
  setInterval(callback: () => void, everyMs: number): () => void;
}

export interface ManualUiClock extends UiClock {
  set(nowMs: number): void;
  advanceBy(deltaMs: number): void;
}

const SYSTEM_UI_CLOCK: UiClock = {
  now: () => Date.now(),
  setInterval: (callback, everyMs) => {
    const id = globalThis.setInterval(callback, everyMs);
    return () => globalThis.clearInterval(id);
  },
};

const UiClockContext = createContext<UiClock>(SYSTEM_UI_CLOCK);

export function UiClockProvider({
  clock = SYSTEM_UI_CLOCK,
  children,
}: {
  clock?: UiClock;
  children: React.ReactNode;
}): React.ReactElement {
  return <UiClockContext.Provider value={clock}>{children}</UiClockContext.Provider>;
}

export function useUiClock(): UiClock {
  return useContext(UiClockContext);
}

export function useUiNow(tickMs: number | null): number {
  const clock = useUiClock();
  const [now, setNow] = useState(() => clock.now());

  useEffect(() => {
    setNow(clock.now());
    if (tickMs == null || tickMs <= 0) return;
    return clock.setInterval(() => setNow(clock.now()), tickMs);
  }, [clock, tickMs]);

  return now;
}

export function createManualUiClock(initialNowMs = 0): ManualUiClock {
  let nowMs = initialNowMs;
  let nextId = 1;
  const timers = new Map<number, { callback: () => void; everyMs: number; nextAt: number }>();

  return {
    now: () => nowMs,
    setInterval: (callback, everyMs) => {
      const safeEveryMs = Math.max(1, Math.floor(everyMs));
      const id = nextId++;
      timers.set(id, {
        callback,
        everyMs: safeEveryMs,
        nextAt: nowMs + safeEveryMs,
      });
      return () => {
        timers.delete(id);
      };
    },
    set: (nextNowMs) => {
      nowMs = Math.max(0, Math.floor(nextNowMs));
    },
    advanceBy: (deltaMs) => {
      const target = nowMs + Math.max(0, Math.floor(deltaMs));
      while (true) {
        let nextTimerId: number | null = null;
        let nextTimerAt = Number.POSITIVE_INFINITY;
        for (const [id, timer] of timers.entries()) {
          if (timer.nextAt < nextTimerAt) {
            nextTimerId = id;
            nextTimerAt = timer.nextAt;
          }
        }
        if (nextTimerId == null || nextTimerAt > target) break;
        nowMs = nextTimerAt;
        const timer = timers.get(nextTimerId);
        if (!timer) continue;
        timer.callback();
        const current = timers.get(nextTimerId);
        if (current) {
          current.nextAt = nowMs + current.everyMs;
          timers.set(nextTimerId, current);
        }
      }
      nowMs = target;
    },
  };
}

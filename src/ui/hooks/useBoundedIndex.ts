/**
 * useBoundedIndex — bounded integer cursor driven by arrow keys + vim j/k.
 *
 * Replaces the 4+ bespoke copies of
 *   setIdx(i => Math.max(0, i - 1))
 *   setIdx(i => Math.min(size - 1, i + 1))
 * scattered across the interactive components.
 */
import { useInput } from "ink";
import { useCallback, useEffect, useRef, useState } from "react";

export interface UseBoundedIndexOptions {
  initial?: number;
  wrap?: boolean;
  isActive?: boolean;
  onChange?: (next: number) => void;
}

export interface UseBoundedIndexResult {
  index: number;
  setIndex: (n: number) => void;
  next: () => void;
  prev: () => void;
}

export function useBoundedIndex(
  size: number,
  options: UseBoundedIndexOptions = {},
): UseBoundedIndexResult {
  const { initial = 0, wrap = true, isActive = true, onChange } = options;
  const [index, setIndexState] = useState<number>(() =>
    Math.min(Math.max(0, initial), Math.max(0, size - 1)),
  );
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  useEffect(() => {
    if (size <= 0) {
      if (index !== 0) setIndexState(0);
      return;
    }
    if (index > size - 1) setIndexState(size - 1);
  }, [size, index]);

  const setIndex = useCallback(
    (n: number) => {
      setIndexState((prev) => {
        const max = Math.max(0, size - 1);
        const clamped = Math.min(Math.max(0, n), max);
        if (clamped !== prev) onChangeRef.current?.(clamped);
        return clamped;
      });
    },
    [size],
  );

  const next = useCallback(() => {
    if (size <= 0) return;
    setIndexState((prev) => {
      const max = size - 1;
      const candidate = prev + 1;
      const nextIdx = candidate > max ? (wrap ? 0 : max) : candidate;
      if (nextIdx !== prev) onChangeRef.current?.(nextIdx);
      return nextIdx;
    });
  }, [size, wrap]);

  const prev = useCallback(() => {
    if (size <= 0) return;
    setIndexState((cur) => {
      const max = size - 1;
      const candidate = cur - 1;
      const nextIdx = candidate < 0 ? (wrap ? max : 0) : candidate;
      if (nextIdx !== cur) onChangeRef.current?.(nextIdx);
      return nextIdx;
    });
  }, [size, wrap]);

  useInput(
    (input, key) => {
      if (key.upArrow || input === "k") prev();
      else if (key.downArrow || input === "j") next();
    },
    { isActive },
  );

  return { index, setIndex, next, prev };
}

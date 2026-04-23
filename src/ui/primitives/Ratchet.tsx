/**
 * Height-locking container — a lightweight port of cc-repo's `Ratchet`.
 *
 * Once a child has rendered at height H, this box won't allow its own
 * height to shrink below H on subsequent renders. The goal is to prevent
 * visual jitter when content in the live rendering zone mutates
 * (e.g. a running tool-call entry ticking between pulse frames, or a
 * resolved tool-call swapping in a longer `renderResult` summary).
 *
 * Without this, Ink's full-frame diff + repaint model can make a
 * one-line `⎿  …` temporarily disappear for a tick while layout
 * recomputes, producing noticeable flicker. Ratchet caps the minimum
 * height at the largest height observed so far, so any shrink is
 * rendered as padding rather than a collapse.
 *
 * This is a simplified version of cc-repo's component — no viewport
 * measurement, no `lock="offscreen"` mode. We just use
 * `measureElement` to track the tallest rendering and set `minHeight`
 * accordingly.
 */

import { Box, type DOMElement, measureElement } from "ink";
import type React from "react";
import { useLayoutEffect, useRef, useState } from "react";

interface RatchetProps {
  children: React.ReactNode;
  minHeight?: number;
  growSettleFrames?: number;
  shrinkSettleFrames?: number;
}

type PendingLock = { direction: "grow" | "shrink"; height: number; frames: number } | null;

export function Ratchet({
  children,
  minHeight = 0,
  growSettleFrames = 2,
  shrinkSettleFrames = 3,
}: RatchetProps): React.ReactElement {
  const ref = useRef<DOMElement | null>(null);
  const [lockedHeight, setLockedHeight] = useState(minHeight);
  const pendingRef = useRef<PendingLock>(null);

  useLayoutEffect(() => {
    if (!ref.current) return;
    try {
      const { height } = measureElement(ref.current);
      const measured = Math.max(minHeight, height);
      if (measured === lockedHeight) {
        pendingRef.current = null;
        return;
      }
      const direction = measured > lockedHeight ? "grow" : "shrink";
      const settleFrames = direction === "grow" ? growSettleFrames : shrinkSettleFrames;
      const pending = pendingRef.current;
      if (pending && pending.direction === direction && pending.height === measured) {
        if (pending.frames + 1 >= settleFrames) {
          pendingRef.current = null;
          setLockedHeight(measured);
        } else {
          pendingRef.current = { ...pending, frames: pending.frames + 1 };
        }
        return;
      }
      pendingRef.current = { direction, height: measured, frames: 1 };
    } catch {
      // Ink renders under ink-testing-library don't always implement
      // measureElement; we silently skip the ratchet in that case.
    }
  });

  return (
    <Box ref={ref} flexDirection="column" minHeight={lockedHeight || undefined}>
      {children}
    </Box>
  );
}

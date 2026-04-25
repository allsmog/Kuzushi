/**
 * useRawModeWatchdog — keep stdin in raw mode while the TUI is alive.
 *
 * The Claude Agent SDK subprocess (spawned by `randori`, `threat-hunt`,
 * agentic-sast, taint-iris, etc.) opens `/dev/tty` and disables raw mode
 * on the parent. When it exits it doesn't restore. Once raw mode is off,
 * Ink's `useInput` stops receiving Ctrl+C as `0x03`, the terminal falls
 * back to cooked mode, and typed characters echo below the Ink frame —
 * exactly what users have reported.
 *
 * Mount this hook at a level that survives mode/view transitions
 * (e.g. `AppInner`) so it doesn't unmount when the app flips from
 * `mode="shell"` → `mode="running"` and the per-mode subtree swaps.
 *
 * Two layers of defence:
 * - `useLayoutEffect`: re-assert raw mode synchronously during every
 *   commit. Closes the window before Ink's next render cycle.
 * - `setInterval(75ms)`: backstop for the rare case where no React
 *   commit fires between a subprocess exit and the next keypress
 *   (e.g. no progress events stream in).
 *
 * Do not trust `stdin.isRaw` here. Node updates that flag when this
 * ReadStream calls `setRawMode`, but another process or another `/dev/tty`
 * file descriptor can change the terminal back to cooked mode without
 * updating the flag. Reasserting raw mode is what keeps Ctrl+C delivered
 * as `0x03` instead of echoed as `^C`.
 */

import { useEffect, useLayoutEffect } from "react";

function ensureRawMode(): void {
  const stdin = process.stdin as NodeJS.ReadStream & {
    isRaw?: boolean;
    setRawMode?: (mode: boolean) => void;
  };
  if (!stdin.isTTY || !stdin.setRawMode) return;
  try {
    stdin.setRawMode(true);
  } catch {
    /* best-effort — terminal may be in a transient state */
  }
}

export function useRawModeWatchdog(active: boolean = true): void {
  useLayoutEffect(() => {
    if (!active) return;
    ensureRawMode();
  });

  useEffect(() => {
    if (!active) return;
    const id = setInterval(ensureRawMode, 75);
    return () => clearInterval(id);
  }, [active]);
}

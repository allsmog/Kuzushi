/**
 * useCursorVisibility — explicit terminal-cursor hide/show with guaranteed
 * restoration on exit.
 *
 * ANSI DECTCEM sequences:
 *   Hide cursor: \u001b[?25l
 *   Show cursor: \u001b[?25h
 *
 * Registers a one-shot `process.on("exit")` listener so the cursor is
 * restored even if React never unmounts (crash, SIGTERM).
 */
import { useEffect } from "react";

const HIDE_CURSOR = "\u001b[?25l";
const SHOW_CURSOR = "\u001b[?25h";

export interface UseCursorVisibilityOptions {
  visible?: boolean;
  restoreOnExit?: boolean;
}

export function useCursorVisibility(
  options: UseCursorVisibilityOptions = {},
): void {
  const { visible = false, restoreOnExit = true } = options;

  useEffect(() => {
    if (!process.stdout.isTTY) return;
    let restored = false;
    const restore = () => {
      if (restored) return;
      restored = true;
      try {
        process.stdout.write(SHOW_CURSOR);
      } catch {
        /* noop */
      }
    };

    if (!visible) {
      try {
        process.stdout.write(HIDE_CURSOR);
      } catch {
        /* noop */
      }
    }

    if (restoreOnExit) {
      process.on("exit", restore);
    }
    return () => {
      if (restoreOnExit) process.off("exit", restore);
      restore();
    };
  }, [visible, restoreOnExit]);
}

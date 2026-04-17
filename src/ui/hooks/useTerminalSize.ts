/**
 * useTerminalSize — live terminal dimensions with SIGWINCH-driven updates.
 *
 * Subscribes to stdout "resize" events and debounces at 50ms to avoid render
 * thrash during drag-resize. Non-TTY fallback is a static 80x24.
 */
import { useStdout } from "ink";
import { useEffect, useState } from "react";

export interface TerminalSize {
  columns: number;
  rows: number;
}

const FALLBACK: TerminalSize = { columns: 80, rows: 24 };
const DEBOUNCE_MS = 50;

function measure(stdout: NodeJS.WriteStream | undefined): TerminalSize {
  const s = stdout ?? process.stdout;
  return {
    columns: s?.columns ?? FALLBACK.columns,
    rows: s?.rows ?? FALLBACK.rows,
  };
}

export function useTerminalSize(): TerminalSize {
  const { stdout } = useStdout();
  const [size, setSize] = useState<TerminalSize>(() => measure(stdout));

  useEffect(() => {
    const s = stdout ?? process.stdout;
    if (!s || !s.isTTY || typeof s.on !== "function") return;
    let timer: NodeJS.Timeout | null = null;
    const handleResize = () => {
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => {
        const next = measure(s);
        setSize((prev) => (prev.columns === next.columns && prev.rows === next.rows ? prev : next));
      }, DEBOUNCE_MS);
    };
    s.on("resize", handleResize);
    return () => {
      if (timer) clearTimeout(timer);
      s.off("resize", handleResize);
    };
  }, [stdout]);

  return size;
}

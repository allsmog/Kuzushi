/**
 * Terminal viewport controls used by the Ink renderer.
 *
 * Alternate screen keeps the live TUI out of the user's normal scrollback.
 * That matters for Ink because large frame rewrites can otherwise push rows
 * into scrollback and create visible tearing.
 */

export const ENTER_ALTERNATE_SCREEN = "\u001b[?1049h";
export const EXIT_ALTERNATE_SCREEN = "\u001b[?1049l";
export const SHOW_CURSOR = "\u001b[?25h";

interface WritableLike {
  isTTY?: boolean;
  write(chunk: string): unknown;
}

export interface AlternateScreenSessionOptions {
  enabled?: boolean;
  stdout?: WritableLike;
  processLike?: NodeJS.Process;
}

let activeSessions = 0;
let restoreInstalled = false;

function safeWrite(stdout: WritableLike, chunk: string): void {
  try {
    stdout.write(chunk);
  } catch {
    /* noop */
  }
}

function restoreTerminal(stdout: WritableLike): void {
  if (!stdout.isTTY) return;
  safeWrite(stdout, EXIT_ALTERNATE_SCREEN);
  safeWrite(stdout, SHOW_CURSOR);
}

function installProcessRestore(stdout: WritableLike, processLike: NodeJS.Process): void {
  if (restoreInstalled) return;
  restoreInstalled = true;
  const restore = () => restoreTerminal(stdout);
  processLike.once("exit", restore);
  processLike.once("SIGINT", restore);
  processLike.once("SIGTERM", restore);
}

/**
 * Enter the alternate screen buffer once per process and return an idempotent
 * cleanup. Multiple callers share a ref-count so nested renderers/tests don't
 * exit the alternate screen until the last session closes.
 */
export function enterAlternateScreen({
  enabled = true,
  stdout = process.stdout,
  processLike = process,
}: AlternateScreenSessionOptions = {}): () => void {
  if (!enabled || !stdout.isTTY) return () => {};

  installProcessRestore(stdout, processLike);
  if (activeSessions === 0) {
    safeWrite(stdout, ENTER_ALTERNATE_SCREEN);
  }
  activeSessions += 1;

  let closed = false;
  return () => {
    if (closed) return;
    closed = true;
    activeSessions = Math.max(0, activeSessions - 1);
    if (activeSessions === 0) {
      restoreTerminal(stdout);
    }
  };
}

/**
 * DEC 2026 synchronized output — atomic terminal writes.
 *
 * Many modern terminals (iTerm2 ≥ 3.6.6, WezTerm, Ghostty, Kitty,
 * Alacritty, mintty, Windows Terminal) support the private-mode
 * sequence DEC 2026: `\x1b[?2026h` pauses frame commits and
 * `\x1b[?2026l` resumes. Writes between those markers appear to the
 * user as a single atomic frame, eliminating partial-redraw tearing
 * (the "flicker" users perceive when Ink rewrites a live region).
 *
 * We wrap `process.stdout.write` on startup when the terminal advertises
 * support, so every Ink frame gets atomically emitted without forking
 * Ink itself. Inspired by CC's implementation in
 * `cc-repo/src/ink/log-update.ts:166`.
 *
 * Tmux breaks atomicity by splitting writes across panes, so we
 * explicitly disable the wrap under TMUX regardless of the underlying
 * terminal's capabilities.
 */

const SYNC_START = "\x1b[?2026h";
const SYNC_END = "\x1b[?2026l";

/**
 * Detect whether the current terminal supports DEC 2026 synchronized
 * output. Conservative — only returns true for terminals we know ship
 * a working implementation.
 */
export function supportsSyncOutput(): boolean {
  // Tmux intercepts and reorders writes — breaks atomicity even when
  // the underlying terminal supports the mode.
  if (process.env["TMUX"]) return false;

  // Explicit opt-in/out via env var for testing or known-bad setups.
  const force = process.env["KUZUSHI_SYNC_OUTPUT"];
  if (force === "1" || force === "true") return true;
  if (force === "0" || force === "false") return false;

  const term = process.env["TERM_PROGRAM"] ?? "";
  if (term === "iTerm.app" || term === "WezTerm" || term === "ghostty") return true;
  if (term === "vscode") return true;

  if (process.env["KITTY_WINDOW_ID"]) return true;
  if (process.env["ALACRITTY_LOG"]) return true;

  // Windows Terminal sets WT_SESSION.
  if (process.env["WT_SESSION"]) return true;

  return false;
}

/**
 * Patch `process.stdout.write` to wrap each chunk with DEC 2026 sync
 * markers. Returns a cleanup function that restores the original writer.
 *
 * Only active when the terminal advertises support (see
 * `supportsSyncOutput`). On unsupported terminals, this is a no-op.
 */
export function wrapStdoutForSyncOutput(): () => void {
  if (!supportsSyncOutput()) return () => {};
  const stdout = process.stdout;
  const origWrite = stdout.write.bind(stdout);

  type WriteArgs =
    | [chunk: string | Uint8Array, cb?: (err?: Error | null) => void]
    | [chunk: string | Uint8Array, encoding?: BufferEncoding, cb?: (err?: Error | null) => void];

  const patched = ((...args: WriteArgs) => {
    const chunk = args[0];
    const wrapped: string | Uint8Array =
      typeof chunk === "string"
        ? `${SYNC_START}${chunk}${SYNC_END}`
        : Buffer.concat([Buffer.from(SYNC_START), Buffer.from(chunk), Buffer.from(SYNC_END)]);
    if (args.length === 1) return origWrite(wrapped);
    if (args.length === 2) return origWrite(wrapped, args[1] as never);
    return origWrite(wrapped, args[1] as never, args[2] as never);
  }) as typeof stdout.write;

  stdout.write = patched;
  return () => {
    stdout.write = origWrite;
  };
}

/**
 * Spool — tee every printed line to a file.
 *
 * Inspired by msfconsole's `spool <file>`: an audit-trail toggle that
 * mirrors the shell's rendered output to disk. Indispensable for
 * engagements where you want a literal transcript.
 *
 * Design: the print sink exposes an `onPrint` hook. The host wires a
 * single hook that consults a SpoolController for an active write
 * stream. `spool <file>` opens one; `spool off` closes it.
 */

import { closeSync, openSync, writeSync } from "node:fs";
import path from "node:path";

export class SpoolController {
  private fd: number | null = null;
  private filePath: string | null = null;
  private startedAt = 0;

  /** Is a file currently being spooled to? */
  isActive(): boolean {
    return this.fd !== null;
  }

  /** Absolute path of the active spool file, or undefined. */
  path(): string | undefined {
    return this.filePath ?? undefined;
  }

  /** Short display name (basename + elapsed seconds). */
  status(): string | undefined {
    if (!this.filePath) return undefined;
    const elapsed = Math.round((Date.now() - this.startedAt) / 1000);
    return `📝 ${path.basename(this.filePath)} (${elapsed}s)`;
  }

  /**
   * Start spooling. If a previous file is open, close it first. Returns
   * the resolved absolute path of the new file. Uses sync fs so the next
   * `tap()` call is guaranteed to land in the file.
   */
  start(filePath: string, cwd: string): string {
    const resolved = path.isAbsolute(filePath) ? filePath : path.resolve(cwd, filePath);
    this.stop();
    this.fd = openSync(resolved, "a");
    this.filePath = resolved;
    this.startedAt = Date.now();
    writeSync(this.fd, `\n--- kuzushi spool started at ${new Date().toISOString()} ---\n`);
    return resolved;
  }

  /** Stop the active spool (if any). Returns the closed file path or undefined. */
  stop(): string | undefined {
    if (this.fd === null) return undefined;
    const closed = this.filePath ?? undefined;
    try {
      writeSync(this.fd, `--- kuzushi spool stopped at ${new Date().toISOString()} ---\n`);
      closeSync(this.fd);
    } catch {
      // best-effort close
    }
    this.fd = null;
    this.filePath = null;
    this.startedAt = 0;
    return closed;
  }

  /**
   * Tee hook — write one line to the active spool file. No-ops when
   * inactive. The print sink doesn't always append a newline, so we do.
   */
  tap(line: string): void {
    if (this.fd === null) return;
    try {
      writeSync(this.fd, line.endsWith("\n") ? line : `${line}\n`);
    } catch {
      // If writing fails (disk full, etc.), silently stop the spool rather
      // than spamming errors on every subsequent print call.
      this.stop();
    }
  }
}

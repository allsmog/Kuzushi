/**
 * $EDITOR subprocess launcher — used by the dispatcher's `edit` command.
 *
 * Writes `initial` to a tempfile, spawns $EDITOR synchronously (inheriting
 * the TTY), and reads the file back on exit. Returns null if the user
 * cancelled (non-zero exit), otherwise the file contents.
 *
 * Intentionally synchronous: no shell renderer should keep writing while the
 * editor owns the TTY. This module just handles the mechanics.
 */

import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

export interface EditorOptions {
  /** Override $EDITOR — useful for tests (e.g. pass `cat` or a script). */
  editor?: string;
  /** Filename stem + extension hint (e.g. "prompt.md" → tempfile ends in .md). */
  hint?: string;
}

/**
 * Open $EDITOR on a scratch file pre-seeded with `initial`, return edited
 * contents on save or null on cancel / non-zero exit.
 */
export async function openInEditor(
  initial: string,
  opts: EditorOptions = {},
): Promise<string | null> {
  const editor = opts.editor ?? process.env["EDITOR"] ?? process.env["VISUAL"] ?? "vi";
  const dir = mkdtempSync(path.join(tmpdir(), "kuzushi-edit-"));
  const name = opts.hint ?? `prompt-${randomBytes(4).toString("hex")}.md`;
  const file = path.join(dir, name);
  writeFileSync(file, initial, "utf8");

  try {
    const result = spawnSync(editor, [file], { stdio: "inherit" });
    if (result.error) throw result.error;
    if ((result.status ?? 1) !== 0) return null;
    return readFileSync(file, "utf8");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

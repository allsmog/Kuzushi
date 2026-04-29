/**
 * Shared helper for resolving operator-overridable agent prompts.
 *
 * The pattern: each agentic sub-module (`triage`, `verify`, `patch`,
 * `carlini-threat-hunt`, `agentic-sast`, `context`) registers an advanced `*_PROMPT`
 * option via `Opt.string`. Operators set it via `set TRIAGE_PROMPT ./mine.md`
 * or `setg TRIAGE_PROMPT "inline text"`, then `run` picks it up and threads
 * it into the task config as `promptOverride`.
 *
 * This resolver accepts either a literal prompt string or a file path. The
 * path detection is conservative — only strings starting with `./`, `/`, or
 * ending with `.md` / `.txt` / `.prompt` are treated as paths. Everything else
 * passes through as the prompt body.
 */

import { readFile } from "node:fs/promises";
import path from "node:path";

/** Keys operators can target with `edit`/`set`/`setg` for prompt overrides. */
export const PROMPT_OPTION_KEYS = [
  "TRIAGE_PROMPT",
  "VERIFY_PROMPT",
  "PATCH_PROMPT",
  "CARLINI_THREAT_HUNT_PROMPT",
  "CONTEXT_PROMPT",
] as const;

export type PromptOptionKey = (typeof PROMPT_OPTION_KEYS)[number];

/** Heuristic: does this look like a filesystem path rather than inline text? */
export function looksLikePromptPath(value: string): boolean {
  if (value.startsWith("./") || value.startsWith("../") || value.startsWith("/")) return true;
  const lower = value.toLowerCase();
  return lower.endsWith(".md") || lower.endsWith(".txt") || lower.endsWith(".prompt");
}

/**
 * Resolve an operator-provided prompt value into the literal prompt body.
 * If `value` is path-like, reads the file (relative to `cwd` when not absolute);
 * otherwise returns the value unchanged. Returns undefined when no override.
 */
export async function resolvePromptValue(
  value: string | undefined,
  cwd: string,
): Promise<string | undefined> {
  if (value == null || value === "") return undefined;
  if (!looksLikePromptPath(value)) return value;
  const abs = path.isAbsolute(value) ? value : path.resolve(cwd, value);
  return readFile(abs, "utf8");
}

/**
 * Normalize camelCase / alias fields in a Claude Agent SDK tool input to the
 * snake_case shape the SDK's built-in Zod schemas accept.
 *
 * Weaker sub-Claude models frequently emit `{filePath: "x"}` for Write/Edit/Read
 * — the SDK rejects these with "Validation failed for tool X" and the model
 * retries in a loop, burning tokens and wall-clock. We shim the common aliases
 * at PreToolUse so the tool actually runs. Returns the same reference when no
 * rewrite is needed so callers can cheaply detect "nothing changed".
 */

type ToolInput = Record<string, unknown>;

export interface NormalizationResult {
  input: ToolInput;
  changed: boolean;
  renames: string[];
}

/**
 * Alias map per built-in tool. Keys are the SDK's canonical field names;
 * values are common camelCase / synonym forms models produce instead. The
 * normalizer copies the first matching alias's value to the canonical key
 * (when the canonical key is absent) and deletes the alias.
 */
const ALIASES: Record<string, Record<string, string[]>> = {
  Write: {
    file_path: ["filePath", "path", "filename", "file"],
    content: ["text", "body"],
  },
  Edit: {
    file_path: ["filePath", "path", "filename", "file"],
    old_string: ["oldString", "old", "search"],
    new_string: ["newString", "new", "replace"],
    replace_all: ["replaceAll"],
  },
  MultiEdit: {
    file_path: ["filePath", "path", "filename", "file"],
  },
  Read: {
    file_path: ["filePath", "path", "filename", "file"],
    offset: ["start", "startLine"],
    limit: ["lines", "count"],
  },
  NotebookEdit: {
    notebook_path: ["notebookPath", "path", "file_path", "filePath"],
    new_source: ["newSource", "source", "content"],
    cell_id: ["cellId"],
    cell_type: ["cellType"],
    edit_mode: ["editMode"],
  },
  Bash: {
    command: ["cmd", "script"],
  },
  Grep: {
    pattern: ["query", "regex"],
    path: ["target", "dir", "directory"],
  },
  Glob: {
    pattern: ["query", "glob"],
    path: ["target", "dir", "directory"],
  },
  WebFetch: {
    url: ["uri", "href"],
  },
};

export function normalizeToolInput(toolName: string, raw: unknown): NormalizationResult {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { input: (raw as ToolInput) ?? {}, changed: false, renames: [] };
  }
  const aliases = ALIASES[toolName];
  if (!aliases) return { input: raw as ToolInput, changed: false, renames: [] };

  const original = raw as ToolInput;
  let next: ToolInput | null = null;
  const renames: string[] = [];

  for (const [canonical, alts] of Object.entries(aliases)) {
    if (canonical in original) continue;
    for (const alt of alts) {
      if (alt in original) {
        next ??= { ...original };
        next[canonical] = next[alt];
        delete next[alt];
        renames.push(`${alt}→${canonical}`);
        break;
      }
    }
  }

  if (!next) return { input: original, changed: false, renames: [] };
  return { input: next, changed: true, renames };
}

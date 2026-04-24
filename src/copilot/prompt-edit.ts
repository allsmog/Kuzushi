/**
 * Helpers for the `/prompt edit`, `/prompt show`, and `/show prompts` verbs.
 *
 * The existing pattern in Kuzushi is that each agentic tool declares a
 * `*_PROMPT` option on its inputSchema (see `PROMPT_OPTION_KEYS` in
 * `src/modules/sast/prompts.ts`). Operators override by setting that option
 * to either inline text or a file path; `resolvePromptValue` reads it at
 * tool-execution time.
 *
 * This module adds the missing round-trip on the *shell* side:
 *
 *   - `editPrompt(moduleId, verb, opts)` — opens $EDITOR on a file under
 *     `.kuzushi/prompts/<moduleId>/<verb>.md`, persists the edit, and reports
 *     the absolute path the shell should `set` on the tool's options.
 *   - `readPromptAudit(core, moduleOptions)` — cross-module table rows of
 *     every tool that exposes a `*_PROMPT` option, with source, length, and
 *     file path when file-backed.
 *
 * Read + write are plain filesystem operations — no runtime dependency on
 * Datastore or the Ink UI layer, so the functions are easy to unit-test.
 */

import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { CopilotCore } from "./core.js";
import { openInEditor } from "./editor.js";

// The PROMPT_OPTION_KEYS list lives in src/modules/sast/prompts.ts; we copy
// it here to avoid a module → copilot circular import (the shell can't
// cleanly import from individual modules).
const PROMPT_OPTION_KEYS = [
  "TRIAGE_PROMPT",
  "VERIFY_PROMPT",
  "PATCH_PROMPT",
  "THREAT_HUNT_PROMPT",
  "CONTEXT_PROMPT",
  "TAINT_IRIS_PROMPT",
  "RANDORI_PROMPT",
] as const;

export type PromptOptionKey = (typeof PROMPT_OPTION_KEYS)[number];

// ---------------------------------------------------------------------------
// Key ↔ verb mapping.
// ---------------------------------------------------------------------------

/**
 * Translate a verb (the text after the colon in a fully-qualified tool name)
 * to the canonical `*_PROMPT` key declared by that tool's inputSchema.
 *
 * Mapping is case-insensitive; hyphens become underscores so `threat-hunt`
 * → `THREAT_HUNT_PROMPT`.
 */
export function verbToPromptKey(verb: string): PromptOptionKey | undefined {
  const normalized = verb.trim().toUpperCase().replace(/-/g, "_");
  const candidate = `${normalized}_PROMPT` as PromptOptionKey;
  return PROMPT_OPTION_KEYS.includes(candidate) ? candidate : undefined;
}

/** Inverse: `TRIAGE_PROMPT` → `triage`. */
export function promptKeyToVerb(key: PromptOptionKey): string {
  return key
    .replace(/_PROMPT$/, "")
    .toLowerCase()
    .replace(/_/g, "-");
}

// ---------------------------------------------------------------------------
// File I/O.
// ---------------------------------------------------------------------------

/** `.kuzushi/prompts/<moduleId>/<verb>.md` — per-module prompt override home. */
export function promptFilePath(dataDir: string, moduleId: string, verb: string): string {
  return path.join(dataDir, "prompts", moduleId, `${verb}.md`);
}

function ensureDir(filePath: string): void {
  mkdirSync(path.dirname(filePath), { recursive: true });
}

function safeReadFile(filePath: string): string | undefined {
  try {
    return readFileSync(filePath, "utf-8");
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Edit workflow.
// ---------------------------------------------------------------------------

export interface EditPromptInput {
  /** `.kuzushi/` directory for this session. */
  dataDir: string;
  /** Focused module id (e.g. "sast"). */
  moduleId: string;
  /** Verb (e.g. "triage") — translated into a prompt key. */
  verb: string;
  /** Tool description — used as a seed comment on first edit. */
  toolDescription?: string;
}

export interface EditPromptOutput {
  /** Absolute path the operator's override lives at (may not exist on cancel). */
  filePath: string;
  /** The prompt key the shell should `set` to `filePath` (`TRIAGE_PROMPT` etc). */
  promptKey: PromptOptionKey;
  /** True when the user saved non-empty content; false on cancel or empty. */
  saved: boolean;
  /** Size of the saved file in bytes, 0 when saved is false. */
  byteLen: number;
}

/**
 * Open $EDITOR on the override file for a `(module, verb)` pair. On save,
 * write the content to disk and report the absolute path back so the caller
 * can `set <PROMPT_KEY> <path>` on the tool's options.
 *
 * Returns `saved: false` on cancel or empty result; caller should leave the
 * existing configuration untouched in that case.
 */
export async function editPrompt(input: EditPromptInput): Promise<EditPromptOutput> {
  const promptKey = verbToPromptKey(input.verb);
  if (!promptKey) {
    throw new Error(
      `No prompt override for verb "${input.verb}". Known verbs: ${PROMPT_OPTION_KEYS.map((k) => promptKeyToVerb(k)).join(", ")}`,
    );
  }
  const filePath = promptFilePath(input.dataDir, input.moduleId, input.verb);
  const existing = safeReadFile(filePath);
  const seed =
    existing ??
    [
      `<!-- ${input.moduleId}:${input.verb} prompt override -->`,
      `<!-- ${input.toolDescription ?? ""} -->`,
      "",
      "# System prompt",
      "",
      "Write the operator override here. Delete this file or leave it empty",
      "to fall back to the compiled default.",
      "",
    ].join("\n");

  const edited = await openInEditor(seed, { hint: `${input.moduleId}-${input.verb}.md` });
  if (edited == null) {
    return { filePath, promptKey, saved: false, byteLen: 0 };
  }
  const trimmed = edited.replace(/\r\n/g, "\n").trimEnd();
  if (trimmed.length === 0) {
    return { filePath, promptKey, saved: false, byteLen: 0 };
  }
  ensureDir(filePath);
  writeFileSync(filePath, `${trimmed}\n`, "utf-8");
  return { filePath, promptKey, saved: true, byteLen: Buffer.byteLength(trimmed, "utf-8") + 1 };
}

// ---------------------------------------------------------------------------
// Show effective prompt value for one tool.
// ---------------------------------------------------------------------------

export interface EffectivePrompt {
  promptKey: PromptOptionKey;
  toolName: string;
  /** Where the value comes from. */
  source: "inline" | "file" | "default" | "unset";
  /** Raw stored value (inline text or path-like string) if set. */
  rawValue?: string;
  /** Resolved content. For `file` sources, read from disk. */
  resolved?: string;
  /** Absolute path when `source === "file"`. */
  filePath?: string;
  /** Size of the resolved body in bytes. */
  byteLen?: number;
  /** Last-modified time for file-backed prompts. */
  mtime?: Date;
}

function looksLikePath(value: string): boolean {
  if (value.startsWith("./") || value.startsWith("../") || value.startsWith("/")) return true;
  const lower = value.toLowerCase();
  return lower.endsWith(".md") || lower.endsWith(".txt") || lower.endsWith(".prompt");
}

/**
 * Describe the currently-effective prompt for a (tool, key) pair, given the
 * shell's `moduleOptions[toolName]` map.
 */
export function readEffectivePrompt(
  toolName: string,
  promptKey: PromptOptionKey,
  storedOptions: Record<string, unknown> | undefined,
  cwd: string,
): EffectivePrompt {
  const raw = storedOptions?.[promptKey];
  if (typeof raw !== "string" || raw.length === 0) {
    return { promptKey, toolName, source: "default" };
  }
  if (looksLikePath(raw)) {
    const abs = path.isAbsolute(raw) ? raw : path.resolve(cwd, raw);
    const content = safeReadFile(abs);
    if (content == null) {
      return { promptKey, toolName, source: "unset", rawValue: raw, filePath: abs };
    }
    let mtime: Date | undefined;
    try {
      mtime = statSync(abs).mtime;
    } catch {
      // ignore — mtime is purely cosmetic
    }
    return {
      promptKey,
      toolName,
      source: "file",
      rawValue: raw,
      resolved: content,
      filePath: abs,
      byteLen: Buffer.byteLength(content, "utf-8"),
      mtime,
    };
  }
  return {
    promptKey,
    toolName,
    source: "inline",
    rawValue: raw,
    resolved: raw,
    byteLen: Buffer.byteLength(raw, "utf-8"),
  };
}

// ---------------------------------------------------------------------------
// Cross-module audit (`/show prompts`).
// ---------------------------------------------------------------------------

export interface PromptAuditRow {
  moduleId: string;
  toolName: string;
  verb: string;
  promptKey: PromptOptionKey;
  effective: EffectivePrompt;
}

/**
 * Walk every loaded module and list tools that expose a `*_PROMPT` option.
 * Merges in the shell's current `moduleOptions` so each row reflects what
 * `run` would actually see.
 */
export function readPromptAudit(
  core: CopilotCore,
  moduleOptions: Record<string, Record<string, unknown>>,
  cwd: string,
): PromptAuditRow[] {
  const rows: PromptAuditRow[] = [];
  for (const info of core.listModules()) {
    const mod = core.registry.get(info.id);
    for (const tool of mod.tools) {
      const schema = tool.inputSchema as { properties?: Record<string, unknown> } | undefined;
      const props = schema?.properties;
      if (!props || typeof props !== "object") continue;
      for (const key of PROMPT_OPTION_KEYS) {
        if (!(key in props)) continue;
        const effective = readEffectivePrompt(tool.name, key, moduleOptions[tool.name], cwd);
        rows.push({
          moduleId: info.id,
          toolName: tool.name,
          verb: tool.name.includes(":") ? tool.name.split(":").slice(1).join(":") : tool.name,
          promptKey: key,
          effective,
        });
      }
    }
  }
  return rows;
}

// ---------------------------------------------------------------------------
// Formatting helpers (used by shell.ts output).
// ---------------------------------------------------------------------------

function shortPath(abs: string): string {
  const home = process.env["HOME"];
  if (home && abs.startsWith(home)) return `~${abs.slice(home.length)}`;
  return abs;
}

export function formatEffectivePromptLine(e: EffectivePrompt): string {
  switch (e.source) {
    case "default":
      return `${e.promptKey}  source=default  (no override set)`;
    case "unset":
      return `${e.promptKey}  source=unset  path=${e.filePath ? shortPath(e.filePath) : "?"}  (file missing)`;
    case "inline": {
      const preview = (e.resolved ?? "").slice(0, 80).replace(/\n/g, " ");
      return `${e.promptKey}  source=inline  ${e.byteLen ?? 0} bytes\n  "${preview}${(e.resolved ?? "").length > 80 ? "\u2026" : ""}"`;
    }
    case "file":
      return `${e.promptKey}  source=file  ${e.byteLen ?? 0} bytes  path=${shortPath(e.filePath ?? "")}`;
  }
}

export function formatPromptAuditTable(rows: PromptAuditRow[]): string {
  if (rows.length === 0) return "No tools declare prompt overrides.";
  const header = ["tool", "key", "source", "bytes", "where"];
  const body = rows.map((r) => {
    const e = r.effective;
    const where =
      e.source === "file"
        ? shortPath(e.filePath ?? "")
        : e.source === "inline"
          ? "(inline)"
          : e.source === "unset"
            ? `(missing: ${shortPath(e.filePath ?? "")})`
            : "(compiled default)";
    return [r.toolName, r.promptKey, e.source, e.byteLen != null ? String(e.byteLen) : "-", where];
  });
  const widths = header.map((h, i) =>
    Math.max(h.length, ...body.map((row) => (row[i] ?? "").length)),
  );
  const pad = (row: string[]) =>
    row.map((cell, i) => cell.padEnd(widths[i] ?? cell.length)).join("  ");
  return [pad(header), pad(header.map((h) => "─".repeat(h.length))), ...body.map(pad)].join("\n");
}

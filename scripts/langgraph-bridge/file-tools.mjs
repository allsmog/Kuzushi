import { globSync, readdirSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, resolve, sep } from "node:path";
import { tool } from "@langchain/core/tools";
import { z } from "zod";
import {
  canonicalPathWithinRoots as confineToRoots,
  readConfinedText,
} from "./confined-file-read.mjs";
import { GREP_MAX_PATTERN_CHARS, scanBoundedRegex } from "./grep-regex-runner.mjs";

const READ_MAX_LINES = 2000;
const READ_DEFAULT_LINES = 250;
const READ_MAX_LINE_CHARS = 500;
const LS_MAX_ENTRIES = 500;
const GLOB_MAX_RESULTS = 200;
const GREP_MAX_FILES = 5000;
const CONFINE_MAX_CANDIDATES = 25_000;
const GREP_MAX_MATCHES = 100;
const GREP_MAX_FILE_BYTES = 1_000_000;
const SKIPPED_DIRS = new Set([".git", "node_modules", "target", ".kuzushi"]);

/** Local read-only file tools for the agent loop. `toolPolicy.tools` names
 * the built-ins a module grants (e.g. the `whitebox-static` profile grants
 * Read/Glob/Grep/LS); MCP servers cover structured queries but the agent
 * still needs plain source access for languages and paths MCP cannot reach.
 * Every path is canonicalized and confined to `toolPolicy.mcpReadRoots`. */
export function fileToolsForRequest(request, fileReadHooks = {}) {
  const roots = readRootsFor(request);
  if (roots.length === 0) return [];
  const granted = grantedToolNames(request);
  const available = {
    Read: readTool(roots, fileReadHooks),
    LS: lsTool(roots, fileReadHooks),
    Glob: globTool(roots),
    Grep: grepTool(roots, fileReadHooks),
  };
  return Object.entries(available)
    .filter(([name]) => granted.has(name))
    .map(([, built]) => built);
}

function grantedToolNames(request) {
  const raw = request?.toolPolicy?.tools ?? request?.tool_policy?.tools;
  return new Set(Array.isArray(raw) ? raw.filter((name) => typeof name === "string") : []);
}

function readRootsFor(request) {
  const raw = request?.toolPolicy?.mcpReadRoots ?? request?.toolPolicy?.mcp_read_roots;
  if (!Array.isArray(raw)) return [];
  const roots = [];
  for (const root of raw) {
    try {
      const canonical = realpathSync(root);
      if (statSync(canonical).isDirectory()) roots.push(canonical);
    } catch {
      // An unavailable root grants nothing.
    }
  }
  return [...new Set(roots)];
}

// Confine a glob match by its canonical target while retaining the ORIGINAL
// matched path for operator-visible citations. Reads must use `canonicalPath`:
// reopening `matchedPath` after validation would create a symlink-swap window
// in which an untrusted workspace could redirect Grep outside the read roots.
function confinedMatch(base, match, roots) {
  const matchedPath = resolve(base, match);
  const canonicalPath = confineToRoots(matchedPath, roots);
  return canonicalPath === null ? null : { canonicalPath, matchedPath };
}

// Bound confinement work itself, not just accepted results: every inspected
// candidate costs a realpath call, so an untrusted workspace stuffed with
// escaping symlinks must not buy unbounded synchronous work with entries that
// are all rejected. Rejected candidates still never consume `quota`.
export function confinedCandidates(matches, base, roots, quota) {
  const inspected = matches.slice(0, CONFINE_MAX_CANDIDATES);
  const { kept, overQuota } = admitCandidates(inspected, base, roots, quota);
  return { kept, truncated: overQuota || inspected.length < matches.length };
}

function admitCandidates(matches, base, roots, quota) {
  const kept = [];
  for (const match of matches) {
    const candidate = confinedMatch(base, match, roots);
    if (candidate === null) continue;
    if (kept.length >= quota) return { kept, overQuota: true };
    kept.push(candidate);
  }
  return { kept, overQuota: false };
}

function workspaceRelative(absolute, base) {
  return absolute.startsWith(`${base}${sep}`) ? absolute.slice(base.length + 1) : absolute;
}

function authorizedPath(candidate, roots) {
  const base = roots[0];
  const absolute = isAbsolute(candidate) ? candidate : resolve(base, candidate);
  const canonical = confineToRoots(absolute, roots);
  if (canonical === null) {
    throw new Error(`path is outside the workspace read roots: ${candidate}`);
  }
  return canonical;
}

function readTool(roots, hooks) {
  return tool(
    ({ file_path, offset, limit }) => {
      const path = authorizedPath(file_path, roots);
      const text = readConfinedText(path, roots, null, () => hooks.afterFileValidation?.("Read", path));
      return renderFileSlice(text, offset, limit);
    },
    {
      name: "Read",
      description:
        "Read a source file from the workspace (returns numbered lines). Paths may be absolute or relative to the workspace root. Use offset/limit for large files.",
      schema: z.object({
        file_path: z.string().describe("File path (absolute, or relative to the workspace root)"),
        offset: z.number().int().min(1).optional().describe("1-based first line to read"),
        limit: z.number().int().min(1).optional().describe("Maximum number of lines to return"),
      }),
    },
  );
}

function renderFileSlice(text, offset, limit) {
  const lines = text.split("\n");
  const first = Math.max(1, offset ?? 1);
  // Default small: every line returned here is re-sent to the provider on
  // each subsequent agent hop, so oversized reads compound into quota burn.
  const count = Math.min(limit ?? READ_DEFAULT_LINES, READ_MAX_LINES);
  const slice = lines.slice(first - 1, first - 1 + count);
  const numbered = slice.map(
    (line, index) => `${String(first + index).padStart(6)}\t${line.slice(0, READ_MAX_LINE_CHARS)}`,
  );
  const remaining = lines.length - (first - 1 + slice.length);
  if (remaining > 0) numbered.push(`… ${remaining} more line(s); continue with offset=${first + slice.length}`);
  return numbered.join("\n") || "(empty file)";
}

function lsTool(roots, hooks) {
  return tool(
    ({ path }) => {
      const authorized = authorizedPath(path ?? roots[0], roots);
      hooks.afterDirectoryValidation?.("LS", authorized);
      return renderDirectory(authorized, roots);
    },
    {
      name: "LS",
      description: "List the entries of a workspace directory (directories get a trailing slash).",
      schema: z.object({
        path: z.string().optional().describe("Directory path; defaults to the workspace root"),
      }),
    },
  );
}

function renderDirectory(path, roots) {
  const names = readdirSync(path);
  if (confineToRoots(path, roots) === null) {
    throw new Error("workspace directory changed during authorization");
  }
  const entries = names.flatMap((name) => confinedDirectoryLabel(path, name, roots)).sort();
  const shown = entries.slice(0, LS_MAX_ENTRIES);
  if (entries.length > shown.length) shown.push(`… ${entries.length - shown.length} more entries omitted`);
  return shown.join("\n") || "(empty directory)";
}

function confinedDirectoryLabel(base, name, roots) {
  const canonical = confineToRoots(resolve(base, name), roots);
  if (canonical === null) return [];
  try {
    return [statSync(canonical).isDirectory() ? `${name}/` : name];
  } catch {
    return [];
  }
}

function globTool(roots) {
  return tool(
    ({ pattern, path }) => renderGlob(pattern, authorizedPath(path ?? roots[0], roots), roots),
    {
      name: "Glob",
      description:
        'Find workspace files by glob pattern, e.g. "**/PostAddNodesTask.scala" or "src/**/*.go". Returns workspace-relative paths.',
      schema: z.object({
        pattern: z.string().describe("Glob pattern to match file paths against"),
        path: z.string().optional().describe("Directory to search in; defaults to the workspace root"),
      }),
    },
  );
}

function renderGlob(pattern, base, roots) {
  const raw = globSync(pattern, { cwd: base, exclude: (name) => SKIPPED_DIRS.has(name) });
  const { kept, truncated } = confinedCandidates(raw, base, roots, Infinity);
  const matches = kept.map((candidate) => workspaceRelative(candidate.matchedPath, base)).sort();
  const shown = matches.slice(0, GLOB_MAX_RESULTS);
  if (matches.length > shown.length) shown.push(`… ${matches.length - shown.length} more matches omitted`);
  if (truncated) shown.push(`… inspection stopped after ${CONFINE_MAX_CANDIDATES} candidates — narrow the pattern`);
  return shown.join("\n") || `no files match ${pattern}`;
}

function grepTool(roots, hooks) {
  return tool(
    async ({ pattern, path, glob }) =>
      renderGrep(pattern, authorizedPath(path ?? roots[0], roots), roots, glob, hooks),
    {
      name: "Grep",
      description:
        "Search workspace file contents with a regular expression. Scope the search with path and/or a glob filter — an unscoped search over a huge workspace is truncated.",
      schema: z.object({
        pattern: z
          .string()
          .min(1)
          .max(GREP_MAX_PATTERN_CHARS)
          .describe("Regular expression to search for"),
        path: z.string().optional().describe("File or directory to search; defaults to the workspace root"),
        glob: z.string().optional().describe('Glob filter for files to search, e.g. "**/*.scala"'),
      }),
    },
  );
}

async function renderGrep(pattern, base, roots, glob, hooks) {
  const { files, truncatedWalk } = grepCandidateFiles(base, roots, glob);
  const { lines, scanned } = await collectGrepMatches(files, base, pattern, roots, hooks);
  const truncated = truncatedWalk || scanned < files.length;
  const note = grepScanNote(lines.length, scanned, truncated);
  if (note) lines.push(note);
  return lines.join("\n") || `no matches for ${pattern}`;
}

async function collectGrepMatches(files, base, pattern, roots, hooks) {
  const { matches, scanned } = await scanBoundedRegex({
    pattern,
    files,
    maxMatches: GREP_MAX_MATCHES,
    readText: (candidate) => grepCandidateText(candidate, roots, hooks),
  });
  const lines = matches.map(({ fileIndex, line, preview }) => {
    const relative = workspaceRelative(files[fileIndex].matchedPath, base);
    return `${relative}:${line}:${preview}`;
  });
  return { lines, scanned };
}

function grepCandidateText(candidate, roots, hooks) {
  const text = readGrepText(candidate.canonicalPath, roots, hooks);
  if (text === null || text.includes("\u0000")) return null;
  return text;
}

function grepScanNote(matchCount, scanned, truncated) {
  const notes = [];
  if (matchCount >= GREP_MAX_MATCHES) notes.push(`match limit ${GREP_MAX_MATCHES} reached`);
  if (truncated) notes.push(`scan truncated after ${scanned} file(s) — narrow with path/glob`);
  return notes.length > 0 ? `… ${notes.join("; ")}` : "";
}

function grepCandidateFiles(base, roots, glob) {
  if (statSync(base).isFile()) {
    return {
      files: [{ canonicalPath: base, matchedPath: base }],
      truncatedWalk: false,
    };
  }
  const matches = globSync(glob ?? "**/*", {
    cwd: base,
    exclude: (name) => SKIPPED_DIRS.has(name),
  });
  return confinedGrepCandidates(matches, base, roots);
}

function confinedGrepCandidates(matches, base, roots) {
  const { kept, truncated } = confinedCandidates(matches, base, roots, GREP_MAX_FILES);
  return { files: kept, truncatedWalk: truncated };
}

function readGrepText(path, roots, hooks) {
  try {
    return readConfinedText(path, roots, GREP_MAX_FILE_BYTES, () =>
      hooks.afterFileValidation?.("Grep", path),
    );
  } catch {
    return null;
  }
}

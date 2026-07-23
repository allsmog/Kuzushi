import { globSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join, resolve, sep } from "node:path";
import { tool } from "@langchain/core/tools";
import { z } from "zod";

const READ_MAX_LINES = 2000;
const READ_DEFAULT_LINES = 250;
const READ_MAX_LINE_CHARS = 500;
const LS_MAX_ENTRIES = 500;
const GLOB_MAX_RESULTS = 200;
const GREP_MAX_FILES = 5000;
const GREP_MAX_MATCHES = 100;
const GREP_MAX_FILE_BYTES = 1_000_000;
const SKIPPED_DIRS = new Set([".git", "node_modules", "target", ".kuzushi"]);

/** Local read-only file tools for the agent loop. `toolPolicy.tools` names
 * the built-ins a module grants (e.g. the `whitebox-static` profile grants
 * Read/Glob/Grep/LS); MCP servers cover structured queries but the agent
 * still needs plain source access for languages and paths MCP cannot reach.
 * Every path is canonicalized and confined to `toolPolicy.mcpReadRoots`. */
export function fileToolsForRequest(request) {
  const roots = readRootsFor(request);
  if (roots.length === 0) return [];
  const granted = grantedToolNames(request);
  const available = {
    Read: readTool(roots),
    LS: lsTool(roots),
    Glob: globTool(roots),
    Grep: grepTool(roots),
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

function authorizedPath(candidate, roots) {
  const base = roots[0];
  const absolute = isAbsolute(candidate) ? candidate : resolve(base, candidate);
  const canonical = realpathSync(absolute);
  if (!roots.some((root) => canonical === root || canonical.startsWith(`${root}${sep}`))) {
    throw new Error(`path is outside the workspace read roots: ${candidate}`);
  }
  return canonical;
}

function readTool(roots) {
  return tool(
    ({ file_path, offset, limit }) => renderFileSlice(authorizedPath(file_path, roots), offset, limit),
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

function renderFileSlice(path, offset, limit) {
  const lines = readFileSync(path, "utf8").split("\n");
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

function lsTool(roots) {
  return tool(
    ({ path }) => renderDirectory(authorizedPath(path ?? roots[0], roots)),
    {
      name: "LS",
      description: "List the entries of a workspace directory (directories get a trailing slash).",
      schema: z.object({
        path: z.string().optional().describe("Directory path; defaults to the workspace root"),
      }),
    },
  );
}

function renderDirectory(path) {
  const entries = readdirSync(path, { withFileTypes: true })
    .map((entry) => (entry.isDirectory() ? `${entry.name}/` : entry.name))
    .sort();
  const shown = entries.slice(0, LS_MAX_ENTRIES);
  if (entries.length > shown.length) shown.push(`… ${entries.length - shown.length} more entries omitted`);
  return shown.join("\n") || "(empty directory)";
}

function globTool(roots) {
  return tool(
    ({ pattern, path }) => renderGlob(pattern, authorizedPath(path ?? roots[0], roots)),
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

function renderGlob(pattern, base) {
  const matches = globSync(pattern, { cwd: base, exclude: (name) => SKIPPED_DIRS.has(name) }).sort();
  const shown = matches.slice(0, GLOB_MAX_RESULTS);
  if (matches.length > shown.length) shown.push(`… ${matches.length - shown.length} more matches omitted`);
  return shown.join("\n") || `no files match ${pattern}`;
}

function grepTool(roots) {
  return tool(
    ({ pattern, path, glob }) => renderGrep(pattern, authorizedPath(path ?? roots[0], roots), glob),
    {
      name: "Grep",
      description:
        "Search workspace file contents with a regular expression. Scope the search with path and/or a glob filter — an unscoped search over a huge workspace is truncated.",
      schema: z.object({
        pattern: z.string().describe("Regular expression to search for"),
        path: z.string().optional().describe("File or directory to search; defaults to the workspace root"),
        glob: z.string().optional().describe('Glob filter for files to search, e.g. "**/*.scala"'),
      }),
    },
  );
}

function renderGrep(pattern, base, glob) {
  const regex = new RegExp(pattern);
  const { files, truncatedWalk } = grepCandidateFiles(base, glob);
  const out = [];
  let scanned = 0;
  for (const file of files) {
    scanned += 1;
    appendFileMatches(out, file, base, regex);
    if (out.length >= GREP_MAX_MATCHES) break;
  }
  const notes = [];
  if (out.length >= GREP_MAX_MATCHES) notes.push(`match limit ${GREP_MAX_MATCHES} reached`);
  if (truncatedWalk || scanned < files.length) notes.push(`scan truncated after ${scanned} file(s) — narrow with path/glob`);
  if (notes.length > 0) out.push(`… ${notes.join("; ")}`);
  return out.join("\n") || `no matches for ${pattern}`;
}

function grepCandidateFiles(base, glob) {
  if (statSync(base).isFile()) return { files: [base], truncatedWalk: false };
  const matches = globSync(glob ?? "**/*", {
    cwd: base,
    exclude: (name) => SKIPPED_DIRS.has(name),
  });
  const files = matches.slice(0, GREP_MAX_FILES).map((match) => join(base, match));
  return { files, truncatedWalk: matches.length > GREP_MAX_FILES };
}

function appendFileMatches(out, file, base, regex) {
  let text;
  try {
    if (!statSync(file).isFile() || statSync(file).size > GREP_MAX_FILE_BYTES) return;
    text = readFileSync(file, "utf8");
  } catch {
    return;
  }
  if (text.includes("\u0000")) return;
  const lines = text.split("\n");
  const relative = file.startsWith(`${base}${sep}`) ? file.slice(base.length + 1) : file;
  for (let index = 0; index < lines.length && out.length < GREP_MAX_MATCHES; index += 1) {
    if (regex.test(lines[index])) {
      out.push(`${relative}:${index + 1}:${lines[index].slice(0, READ_MAX_LINE_CHARS)}`);
    }
  }
}

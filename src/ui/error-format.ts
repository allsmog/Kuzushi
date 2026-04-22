/**
 * error-format — Ink-free utilities that classify and structure errors for
 * the UI layer. Upgrades `ErrorCard`'s headline + trace rendering and surfaces
 * an actionable "Next Step" per category.
 *
 * Also hosts the canonical "unknown X" message builders so scattered
 * call sites (`shell.ts`, `core.ts`, `run.ts`, `core-dispatcher.ts`)
 * can share one wording + nearest-match suggestion logic. Pure functions,
 * Ink-free, test-friendly.
 *
 * Plus a `describeEmptyState` helper that produces the (title · reason ·
 * action) triple the `<EmptyState>` component renders. Keeping it pure so
 * the plain-renderer + headless CI path can reach the same copy without
 * importing Ink.
 */

export type ErrorCategory =
  | "rate_limit"
  | "auth"
  | "budget"
  | "transient"
  | "validation"
  | "fatal"
  | "unknown";

export interface FormattedErrorFrame {
  file: string;
  line?: number;
  column?: number;
  source?: string;
}

export interface FormattedError {
  headline: string;
  category: ErrorCategory;
  nextStep?: string;
  frames: ReadonlyArray<FormattedErrorFrame>;
  raw: string;
}

export interface FormatErrorOptions {
  maxFrames?: number;
  includeRaw?: boolean;
}

const HEADLINE_MAX = 200;

function safeMessage(err: unknown): string {
  if (err instanceof Error) return err.message || err.name || "Error";
  if (typeof err === "string") return err;
  if (err == null) return "Unknown error";
  try {
    return JSON.stringify(err);
  } catch {
    return Object.prototype.toString.call(err);
  }
}

function stackOf(err: unknown): string {
  if (err instanceof Error && typeof err.stack === "string") return err.stack;
  return "";
}

const FRAME_RE = /at (?:(?<fn>\S+) \()?(?<file>[^()\s]+?):(?<line>\d+):(?<col>\d+)\)?/;

function parseFrames(stack: string, maxFrames: number): FormattedErrorFrame[] {
  if (!stack) return [];
  const lines = stack.split("\n").slice(1);
  const frames: FormattedErrorFrame[] = [];
  for (const raw of lines) {
    if (frames.length >= maxFrames) break;
    const match = raw.match(FRAME_RE);
    if (!match?.groups) continue;
    const { file, line, col } = match.groups;
    if (!file) continue;
    if (file.startsWith("node:") || file.includes("node_modules/")) continue;
    frames.push({
      file,
      line: line ? Number.parseInt(line, 10) : undefined,
      column: col ? Number.parseInt(col, 10) : undefined,
    });
  }
  return frames;
}

export function classifyError(err: unknown): ErrorCategory {
  const msg = safeMessage(err).toLowerCase();
  const status =
    err && typeof err === "object" && "status" in err
      ? Number((err as { status?: unknown }).status)
      : undefined;
  if (status === 401 || status === 403) return "auth";
  if (status === 429 || /rate ?limit|too many requests/.test(msg)) return "rate_limit";
  if (/budget|spend|quota/.test(msg)) return "budget";
  if (/econnreset|etimedout|enotfound|network|fetch failed/i.test(msg)) return "transient";
  if (/validation|zod|invalid|schema/.test(msg)) return "validation";
  if (err instanceof Error && err.name === "FatalError") return "fatal";
  if (/fatal|panic/.test(msg)) return "fatal";
  return "unknown";
}

export function suggestNextStep(err: unknown, category: ErrorCategory): string | undefined {
  // Check env-var shape first — an auth-category error that mentions a
  // specific env var gets a targeted hint instead of the generic one.
  if (category === "auth") {
    const msg = safeMessage(err);
    const match = msg.match(/([A-Z][A-Z0-9_]{3,})/);
    if (match && /KEY|TOKEN|SECRET/.test(match[1])) {
      return `Set ${match[1]} env var or run /config to paste a fresh credential.`;
    }
    return "Check ANTHROPIC_API_KEY environment variable or --api-key flag.";
  }
  switch (category) {
    case "rate_limit":
      return "Wait ~60s and retry, or lower concurrency via /concurrency <n>.";
    case "budget":
      return "Press c to continue past the cap, or a to abort. Raise --budget to avoid future halts.";
    case "transient":
      return "Network blip — retry the command.";
    case "validation":
      return "Config validation failed — check the field named in the message.";
    default:
      return undefined;
  }
}

export function formatError(err: unknown, options: FormatErrorOptions = {}): FormattedError {
  const { maxFrames = 5, includeRaw = false } = options;
  const message = safeMessage(err);
  const headline = message.split("\n")[0]?.slice(0, HEADLINE_MAX) ?? "Error";
  const category = classifyError(err);
  const frames = parseFrames(stackOf(err), maxFrames);
  const raw = includeRaw ? stackOf(err) || safeMessage(err) : "";
  return {
    headline,
    category,
    nextStep: suggestNextStep(err, category),
    frames,
    raw,
  };
}

// ---------------------------------------------------------------------------
// Nearest-match suggestions + canonical "unknown X" copy
// ---------------------------------------------------------------------------

/**
 * Classic Levenshtein (iterative, two-row buffer) in ~15 lines. Good enough
 * for the handful of modules / tools we compare against — O(m*n) with small
 * constants, and we cap input length to avoid runaway cost on garbage input.
 */
export function editDistance(a: string, b: string): number {
  const s = a.slice(0, 64).toLowerCase();
  const t = b.slice(0, 64).toLowerCase();
  if (s === t) return 0;
  if (s.length === 0) return t.length;
  if (t.length === 0) return s.length;
  let prev = new Array<number>(t.length + 1);
  let curr = new Array<number>(t.length + 1);
  for (let j = 0; j <= t.length; j += 1) prev[j] = j;
  for (let i = 1; i <= s.length; i += 1) {
    curr[0] = i;
    for (let j = 1; j <= t.length; j += 1) {
      const cost = s[i - 1] === t[j - 1] ? 0 : 1;
      curr[j] = Math.min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[t.length] ?? Math.max(s.length, t.length);
}

/**
 * Return the `limit` nearest candidates to `needle` by edit distance,
 * ties broken by original order. Empty haystack → empty result.
 */
export function nearestMatches(
  needle: string,
  haystack: ReadonlyArray<string>,
  limit = 3,
): string[] {
  if (haystack.length === 0 || !needle) return [];
  const scored = haystack.map((cand, i) => ({
    cand,
    i,
    d: editDistance(needle, cand),
  }));
  scored.sort((a, b) => a.d - b.d || a.i - b.i);
  // Cap suggestions at a sensible distance so "xyz" doesn't suggest
  // random modules that share 0 characters.
  const maxD = Math.max(3, Math.floor(needle.length * 0.6));
  return scored
    .filter((s) => s.d <= maxD)
    .slice(0, limit)
    .map((s) => s.cand);
}

function formatSuggestions(matches: ReadonlyArray<string>): string {
  if (matches.length === 0) return "";
  if (matches.length === 1) return ` Did you mean "${matches[0]}"?`;
  return ` Did you mean one of: ${matches.map((m) => `"${m}"`).join(", ")}?`;
}

export function formatUnknownTool(
  name: string,
  availableTools: ReadonlyArray<string>,
): string {
  const suggestions = nearestMatches(name, availableTools, 3);
  const head = `Unknown tool: "${name}".`;
  const tail = `${formatSuggestions(suggestions)} Type /tools to list available.`;
  return `${head}${tail}`;
}

export function formatUnknownModule(
  id: string,
  loadedModules: ReadonlyArray<string>,
): string {
  const suggestions = nearestMatches(id, loadedModules, 3);
  const head = `Unknown module: "${id}".`;
  const tail = `${formatSuggestions(suggestions)} Type /modules to list loaded, or /use <id> to focus.`;
  return `${head}${tail}`;
}

export function formatUnknownVerb(name: string, knownVerbs?: ReadonlyArray<string>): string {
  const base = knownVerbs ?? [];
  const suggestions = nearestMatches(name.replace(/^\//, ""), base, 3);
  const head = `Unknown command: "/${name.replace(/^\//, "")}".`;
  const tail = `${formatSuggestions(suggestions)} Type /help to list verbs.`;
  return `${head}${tail}`;
}

// ---------------------------------------------------------------------------
// Empty-state copy builder — consumed by <EmptyState> and plain-renderer.
// ---------------------------------------------------------------------------

export type EmptyStateKind =
  | "module-none-focused"
  | "module-no-tools"
  | "findings-never-scanned"
  | "findings-zero-after-scan"
  | "findings-filter-empty"
  | "findings-compact-idle"
  | "threat-model-missing"
  | "diff-since-idle"
  | "generic";

export interface EmptyStateContext {
  /** e.g. "dfd" | "stride" | "stories" | "scope" | "summary" */
  threatView?: string;
  /** Module id for module-* kinds. */
  moduleId?: string;
  /** Number of filters active, used to refine filter-empty copy. */
  filterCount?: number;
  /** Is a scan currently running? Shifts the copy to "in progress". */
  scanInProgress?: boolean;
  /** Progress info to surface in the reason line. */
  progress?: { current: number; total: number };
}

export interface EmptyStateCopy {
  /** Bold headline — what's missing. */
  title: string;
  /** One-line muted explanation — why it's missing. */
  reason: string;
  /** Action hint — the exact next verb/keystroke. */
  action: string;
}

const THREAT_VIEW_TITLES: Record<string, string> = {
  dfd: "No data flow diagram",
  stride: "No STRIDE matrix",
  stories: "No attacker stories",
  scope: "No scope & criticality model",
  summary: "No threat summary",
};

/**
 * Resolve the three-line copy for a given empty-state kind + optional
 * context. Pure — no Ink, no color. UI components wrap the strings with
 * tokens; plain-renderer dumps them as-is.
 */
export function describeEmptyState(
  kind: EmptyStateKind,
  ctx: EmptyStateContext = {},
): EmptyStateCopy {
  switch (kind) {
    case "module-none-focused":
      return {
        title: "No module focused",
        reason: "The shell isn't scoped to a module yet.",
        action: "/use <module> to focus · /modules to list loaded",
      };
    case "module-no-tools":
      return {
        title: "No tools declared",
        reason: `${ctx.moduleId ?? "This module"} registers zero tools.`,
        action: "Load another module with --load <spec> · /modules to list",
      };
    case "findings-never-scanned":
      return {
        title: "No scan has run yet",
        reason: "Nothing has been triaged for this workspace.",
        action: "Type /scan to kick a pipeline · /use <module> to pick a surface",
      };
    case "findings-zero-after-scan":
      return {
        title: "Scan complete · no findings",
        reason: "The last run produced zero actionable findings at the current severity threshold.",
        action: "/since <ref> for diff-scoped view · /tune to lower severity floor",
      };
    case "findings-filter-empty":
      return {
        title: "No findings match current filter",
        reason:
          ctx.filterCount && ctx.filterCount > 0
            ? `${ctx.filterCount} filter${ctx.filterCount === 1 ? "" : "s"} active.`
            : "Filters are excluding every result.",
        action: "Press c to clear · /findings to reset",
      };
    case "findings-compact-idle": {
      if (ctx.scanInProgress && ctx.progress) {
        return {
          title: "Triage in progress",
          reason: `Scanned ${ctx.progress.current}/${ctx.progress.total} findings so far.`,
          action: "Results stream in as each worker finishes · Ctrl+C to abort",
        };
      }
      return {
        title: "No findings triaged yet",
        reason: "Waiting on the first worker result.",
        action: "Runs update live · Ctrl+C to abort",
      };
    }
    case "threat-model-missing": {
      const title = THREAT_VIEW_TITLES[ctx.threatView ?? ""] ?? "No threat model loaded";
      return {
        title,
        reason: "No `.kuzushi/threat-model.json` exists for this workspace.",
        action: "Run /scan with threat modelling enabled, or /threats edit to author one",
      };
    }
    case "diff-since-idle":
      return {
        title: "No diff scope set",
        reason: "Findings aren't currently narrowed to a git range.",
        action: "/since <git-ref> to scope (e.g. /since main, /since HEAD~5)",
      };
    default:
      return {
        title: "No data",
        reason: "This view has nothing to show.",
        action: "/back to return · /help for verbs",
      };
  }
}

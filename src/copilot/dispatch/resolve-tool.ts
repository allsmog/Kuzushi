/**
 * Shared tool-name resolver.
 *
 * Before this module existed, four layers each implemented their own
 * "user typed X, which tool does that mean?" logic with subtle divergences:
 *
 *   - `resolveToolName` in `copilot/shell.ts` (shell bare words / shorthand)
 *   - `resolveDirectToolDispatch` in `copilot/shell.ts` (dispatch routing)
 *   - `ModuleDispatcher.cmd_run` in `copilot/dispatcher/module-dispatcher.ts`
 *   - `executeRun` in `copilot/run.ts` (headless CLI, qualified only)
 *
 * Divergence bit operators in concrete ways:
 *   - `scan .` at top level fell through to the NL agent because no layer
 *     preferred `sast:scan` when multiple modules exposed `scan`.
 *   - `run .` inside a focused module resolved to "Unknown tool: ." because
 *     the positional `.` wasn't recognized as a path.
 *
 * This module owns the rules; callers pick which result kinds they act on.
 */

import { existsSync } from "node:fs";
import type { CopilotModule, ModuleTool } from "../../modules/types.js";

/**
 * The subset of `ModuleRegistry` we actually need — kept narrow so tests can
 * supply a fixture without a full registry setup.
 */
export interface ToolIndex {
  resolveTool(qualifiedName: string): { module: CopilotModule; tool: ModuleTool } | undefined;
  allTools(opts?: { headlessOnly?: boolean }): Array<{ module: CopilotModule; tool: ModuleTool }>;
}

export interface ResolveToolInput {
  /** A single input token: "scan", "sast:scan", "semgrep", ".", "cluade". */
  input: string;
  /**
   * The currently focused module (if any). Shell callers pass `opts.focusedModule`;
   * the headless CLI / internal callers pass `null`.
   */
  focusedModule?: string | null;
  registry: ToolIndex;
}

export type ResolveToolResult =
  /** Resolved to a single fully-qualified tool (e.g. `sast:scan`). */
  | { kind: "tool"; toolName: string }
  /** Token looks like a filesystem path; caller decides whether to accept it. */
  | { kind: "path"; value: string }
  /** Multiple tools share the same action name and no `sast:` preference applied. */
  | { kind: "ambiguous"; action: string; matches: string[] }
  /** Could not resolve and does not look like a path. */
  | { kind: "unknown" };

/**
 * Action-name suffixes preferred when a bare word matches a module id rather
 * than an action. Mirrors `pickDefaultTool` in `module-dispatcher.ts`.
 */
const PREFERRED_ACTION_SUFFIXES = ["scan", "run", "audit", "hunt", "exploit", "build", "list"];

/** Action portion of `module:action` (everything after the first colon). */
export function toolActionName(toolName: string): string {
  return toolName.split(":")[1] ?? toolName;
}

/**
 * True when `value` is plausibly a path the user typed as a positional
 * (`.`, `./x`, `/abs`, `~/foo`, `sub/dir`) or an existing filesystem entry.
 * Used to distinguish a positional `run .` from a mistyped tool name.
 */
export function looksLikePath(value: string): boolean {
  if (!value) return false;
  if (value === "." || value === "..") return true;
  if (value.startsWith("./") || value.startsWith("../")) return true;
  if (value.startsWith("/") || value.startsWith("~")) return true;
  if (value.includes("/")) return true;
  try {
    return existsSync(value);
  } catch {
    return false;
  }
}

/**
 * Core resolver. See `ResolveToolResult` for how callers act on each kind.
 *
 * Resolution order (first match wins):
 *   1. Fully-qualified `module:action` → direct registry lookup.
 *   2. Focused-module shorthand `<focused>:<input>`.
 *   3. Unique action-name match across all modules.
 *   4. Multiple action matches → prefer `sast:<action>` (CLI-equivalent path)
 *      or return `ambiguous` with the full match list.
 *   5. Input matches a module id → pick its preferred action, or the only
 *      tool if the module has exactly one.
 *   6. Input looks like a path → `{ kind: "path" }` so callers can map it
 *      to a positional argument.
 *   7. Otherwise → `{ kind: "unknown" }`.
 */
export function resolveTool(opts: ResolveToolInput): ResolveToolResult {
  const token = opts.input.trim();
  if (!token) return { kind: "unknown" };

  if (token.includes(":")) {
    const hit = opts.registry.resolveTool(token);
    if (hit) return { kind: "tool", toolName: hit.tool.name };
    return { kind: "unknown" };
  }

  if (opts.focusedModule) {
    const qualified = `${opts.focusedModule}:${token}`;
    if (opts.registry.resolveTool(qualified)) {
      return { kind: "tool", toolName: qualified };
    }
  }

  const lowered = token.toLowerCase();
  const actionMatches = opts.registry.allTools().filter(({ tool }) => {
    return toolActionName(tool.name).toLowerCase() === lowered;
  });

  if (actionMatches.length === 1) {
    return { kind: "tool", toolName: actionMatches[0]!.tool.name };
  }

  if (actionMatches.length > 1) {
    const sastMatch = actionMatches.find(({ module }) => module.id === "sast");
    if (sastMatch) return { kind: "tool", toolName: sastMatch.tool.name };
    return {
      kind: "ambiguous",
      action: token,
      matches: actionMatches.map(({ tool }) => tool.name),
    };
  }

  const modMatches = opts.registry.allTools().filter(({ module }) => {
    return module.id.toLowerCase() === lowered;
  });
  if (modMatches.length > 0) {
    for (const suffix of PREFERRED_ACTION_SUFFIXES) {
      const hit = modMatches.find(({ tool }) => toolActionName(tool.name) === suffix);
      if (hit) return { kind: "tool", toolName: hit.tool.name };
    }
    const uniqueTools = new Set(modMatches.map((m) => m.tool.name));
    if (uniqueTools.size === 1) {
      return { kind: "tool", toolName: modMatches[0]!.tool.name };
    }
  }

  if (looksLikePath(token)) {
    return { kind: "path", value: token };
  }

  return { kind: "unknown" };
}

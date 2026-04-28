/**
 * CommandDispatcher pattern — adapted from Metasploit's
 * `Rex::Ui::Text::DispatcherShell` (lib/rex/ui/text/dispatcher_shell.rb).
 *
 * Each dispatcher exposes a name, a `commands` map (`{ "use": "Select a module" }`),
 * a `cmd_<name>` handler, optional `cmd_<name>_help()` and `cmd_<name>_tabs()`.
 *
 * The `Driver` maintains a stack of dispatchers — pushing/popping enables
 * context like `use sast` (descend into a module command set) → `back` (pop).
 *
 * Anything that isn't a known command is a candidate for fallback handling
 * (e.g. routing to the LLM agent or printing "unknown command").
 */

import type { JobManager } from "../../jobs/manager.js";
import type { PrintSink } from "../print.js";

/** Result returned by a command handler. */
export interface CommandResult {
  /** Optional rendered output (already printed via ctx.print, or returned for display). */
  output?: string;
  /** Push a new dispatcher onto the stack (used by `use <module>`). */
  push?: CommandDispatcher;
  /** Pop the current dispatcher (used by `back`). */
  pop?: boolean;
  /** Exit the shell entirely. */
  exit?: boolean;
  /**
   * Whether a dispatcher on the stack actually owned the command.
   * `true` when a `commands` entry matched; `false` when the driver fell
   * through to the "Unknown command" default. Callers use this to decide
   * whether to invoke a downstream router (e.g. the LLM agent fallback).
   */
  matched?: boolean;
}

export interface CommandContext {
  /** msfconsole-style print helpers — prefer these over console.log. */
  print: PrintSink;
  /** Cwd for filesystem-relative commands (resource scripts, etc.). */
  cwd: string;
  /** Optional abort signal so long-running commands can be cancelled. */
  signal?: AbortSignal;
  /** Driver-level escape hatch for commands that need to inspect the stack. */
  driver: Driver;
}

export interface CommandDispatcher {
  /** Display name (e.g. "core", "module(sast)"). Shown in prompt. */
  readonly name: string;
  /** Map of command name → one-line help text. */
  readonly commands: Readonly<Record<string, string>>;
  /** Execute a command. Returns a CommandResult or undefined. */
  execute(cmd: string, args: string[], ctx: CommandContext): Promise<CommandResult | undefined>;
  /** Optional per-command help. */
  help?(cmd: string): string | undefined;
  /** Optional per-command tab completion. Receives the partial token + prior words. */
  complete?(cmd: string, partial: string, words: string[]): string[];
}

/** A driver owns the dispatcher stack and routes input lines. */
export interface Driver {
  readonly print: PrintSink;
  /** Current top-of-stack. */
  current(): CommandDispatcher;
  /** Whole stack from base → top. */
  stack(): CommandDispatcher[];
  push(d: CommandDispatcher): void;
  pop(): CommandDispatcher | undefined;
  /** Generate the rendered prompt prefix (e.g. "kuzushi/sast> "). */
  prompt(): string;
  /** Run a single input line through the dispatch chain. */
  handle(line: string, signal?: AbortSignal): Promise<CommandResult>;
  /** Flat list of every visible command across the stack. */
  allCommands(): Array<{ dispatcher: CommandDispatcher; cmd: string; help: string }>;
  /** Tab completion for the entire input line. */
  complete(line: string): string[];
  /**
   * Optional peek at the host's ShellState. Module dispatchers use this to
   * check `requires` preflight constraints (e.g. threat-hunt needs a fresh
   * ContextSnapshot with appModel). Omit in non-shell contexts.
   */
  getShellState?(): { contextSnapshot?: unknown; threatModel?: unknown } | undefined;
  /**
   * Optional finding-count lookup. Used by modules that declare a
   * `kind: "findings"` requirement (triage / verify / patch).
   */
  getFindingCount?(): number | undefined;
  /** Host-count lookup (blackbox / lateral-movement modules). */
  getHostCount?(): number | undefined;
  /**
   * Live-session-count lookup. When `kind` is set, counts only sessions of
   * that kind (e.g. "ssh"). Omit to count all open sessions.
   */
  getLiveSessionCount?(kind?: string): number | undefined;
  /**
   * Optional JobManager accessor. Module dispatchers call this to register
   * `run --bg` tool invocations as background jobs; the core dispatcher's
   * `jobs` command uses the same manager to list/kill/tail jobs.
   *
   * Omitted when the host shell doesn't enable backgrounding (tests, run-mode).
   */
  jobManager?(): JobManager | undefined;
}

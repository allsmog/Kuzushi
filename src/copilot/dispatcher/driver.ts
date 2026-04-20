/**
 * The Driver routes input lines through a stack of CommandDispatchers.
 *
 * The bottom of the stack is typically the `core` dispatcher (help/exit/etc.);
 * pushing a new dispatcher (e.g. via `use <module>`) layers a module command
 * set on top. `back` pops back to the previous level.
 */

import type { PrintSink } from "../print.js";
import type { CommandContext, CommandDispatcher, CommandResult, Driver } from "./types.js";

export interface DriverOptions {
  print: PrintSink;
  cwd: string;
  /** Initial dispatcher (typically the core dispatcher). */
  base: CommandDispatcher;
  /** Promptbase, e.g. "kuzushi". */
  promptBase?: string;
  /** Optional ShellState accessor — powers module requires preflight. */
  getShellState?: () => { contextSnapshot?: unknown } | undefined;
  /** Optional finding-count accessor — powers triage/verify/patch requires. */
  getFindingCount?: () => number | undefined;
}

export class DispatcherDriver implements Driver {
  readonly print: PrintSink;
  private readonly _stack: CommandDispatcher[];
  private readonly cwd: string;
  private readonly promptBase: string;
  readonly getShellState?: () => { contextSnapshot?: unknown } | undefined;
  readonly getFindingCount?: () => number | undefined;

  constructor(opts: DriverOptions) {
    this.print = opts.print;
    this._stack = [opts.base];
    this.cwd = opts.cwd;
    this.promptBase = opts.promptBase ?? "kuzushi";
    if (opts.getShellState) this.getShellState = opts.getShellState;
    if (opts.getFindingCount) this.getFindingCount = opts.getFindingCount;
  }

  current(): CommandDispatcher {
    return this._stack[this._stack.length - 1] as CommandDispatcher;
  }

  stack(): CommandDispatcher[] {
    return [...this._stack];
  }

  push(d: CommandDispatcher): void {
    this._stack.push(d);
  }

  pop(): CommandDispatcher | undefined {
    if (this._stack.length <= 1) return undefined;
    return this._stack.pop();
  }

  prompt(): string {
    const top = this.current();
    return top.name === "core" ? `${this.promptBase}> ` : `${this.promptBase}/${top.name}> `;
  }

  allCommands(): Array<{ dispatcher: CommandDispatcher; cmd: string; help: string }> {
    const seen = new Set<string>();
    const out: Array<{ dispatcher: CommandDispatcher; cmd: string; help: string }> = [];
    // Top of stack wins on duplicate command names.
    for (let i = this._stack.length - 1; i >= 0; i--) {
      const d = this._stack[i] as CommandDispatcher;
      for (const [cmd, help] of Object.entries(d.commands)) {
        if (seen.has(cmd)) continue;
        seen.add(cmd);
        out.push({ dispatcher: d, cmd, help });
      }
    }
    return out.sort((a, b) => a.cmd.localeCompare(b.cmd));
  }

  async handle(line: string, signal?: AbortSignal): Promise<CommandResult> {
    const trimmed = line.trim();
    if (trimmed === "") return { matched: false };
    const tokens = tokenize(trimmed);
    const cmd = tokens[0] ?? "";
    const args = tokens.slice(1);

    // Walk top-down so module-level commands shadow base-level ones.
    for (let i = this._stack.length - 1; i >= 0; i--) {
      const d = this._stack[i] as CommandDispatcher;
      if (cmd in d.commands) {
        const ctx: CommandContext = signal
          ? { print: this.print, cwd: this.cwd, driver: this, signal }
          : { print: this.print, cwd: this.cwd, driver: this };
        const result = (await d.execute(cmd, args, ctx)) ?? {};
        if (result.push) this.push(result.push);
        if (result.pop) this.pop();
        return { matched: true, ...result };
      }
    }
    return { matched: false, output: `Unknown command: ${cmd}` };
  }

  complete(line: string): string[] {
    const tokens = tokenize(line);
    if (tokens.length === 0) return Object.keys(this.allCommandsAsMap()).sort();

    // Completing the command name itself.
    if (tokens.length === 1 && !line.endsWith(" ")) {
      const partial = tokens[0] ?? "";
      return Object.keys(this.allCommandsAsMap())
        .filter((c) => c.startsWith(partial))
        .sort();
    }

    // Completing an argument — dispatch to the owning dispatcher's `complete`.
    const cmd = tokens[0] ?? "";
    const partial = line.endsWith(" ") ? "" : (tokens[tokens.length - 1] ?? "");
    const words = line.endsWith(" ") ? tokens : tokens.slice(0, -1);
    for (let i = this._stack.length - 1; i >= 0; i--) {
      const d = this._stack[i] as CommandDispatcher;
      if (cmd in d.commands) {
        return d.complete?.(cmd, partial, words) ?? [];
      }
    }
    return [];
  }

  private allCommandsAsMap(): Record<string, string> {
    const map: Record<string, string> = {};
    for (const c of this.allCommands()) map[c.cmd] = c.help;
    return map;
  }
}

/**
 * Minimal POSIX-ish tokenizer: splits on whitespace, respects single+double
 * quoted strings. Sufficient for shell commands; not a full shell parser.
 */
export function tokenize(input: string): string[] {
  const out: string[] = [];
  let buf = "";
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < input.length; i++) {
    const ch = input[i] as string;
    if (quote) {
      if (ch === quote) {
        quote = null;
        continue;
      }
      buf += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch as '"' | "'";
    } else if (/\s/.test(ch)) {
      if (buf) {
        out.push(buf);
        buf = "";
      }
    } else {
      buf += ch;
    }
  }
  if (buf) out.push(buf);
  return out;
}

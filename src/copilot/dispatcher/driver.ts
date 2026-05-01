/**
 * The Driver routes input lines through a stack of CommandDispatchers.
 *
 * The bottom of the stack is typically the `core` dispatcher (help/exit/etc.);
 * pushing a new dispatcher (e.g. via `use <module>`) layers a module command
 * set on top. `back` pops back to the previous level.
 */

import type { JobManager } from "../../jobs/manager.js";
import { toErrorMessage } from "../../utils.js";
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
  getShellState?: () => { contextSnapshot?: unknown; threatModel?: unknown } | undefined;
  /** Optional finding-count accessor — powers triage/verify/patch requires. */
  getFindingCount?: () => number | undefined;
  /** Optional host-count accessor — powers blackbox/lateral requires. */
  getHostCount?: () => number | undefined;
  /** Optional live-session count accessor — powers session requires. */
  getLiveSessionCount?: (kind?: string) => number | undefined;
  /** Optional JobManager — enables `run --bg` and the `jobs` command family. */
  jobManager?: JobManager;
}

export class DispatcherDriver implements Driver {
  readonly print: PrintSink;
  private readonly _stack: CommandDispatcher[];
  private readonly cwd: string;
  private readonly promptBase: string;
  readonly getShellState?: () => { contextSnapshot?: unknown } | undefined;
  readonly getFindingCount?: () => number | undefined;
  readonly getHostCount?: () => number | undefined;
  readonly getLiveSessionCount?: (kind?: string) => number | undefined;
  private readonly _jobManager?: JobManager;

  constructor(opts: DriverOptions) {
    this.print = opts.print;
    this._stack = [opts.base];
    this.cwd = opts.cwd;
    this.promptBase = opts.promptBase ?? "kuzushi";
    if (opts.getShellState) this.getShellState = opts.getShellState;
    if (opts.getFindingCount) this.getFindingCount = opts.getFindingCount;
    if (opts.getHostCount) this.getHostCount = opts.getHostCount;
    if (opts.getLiveSessionCount) this.getLiveSessionCount = opts.getLiveSessionCount;
    if (opts.jobManager) this._jobManager = opts.jobManager;
    // Back-ref: let the base dispatcher peek at the active module for completion.
    const maybeSetDriver = (opts.base as unknown as { setDriver?: (d: unknown) => void }).setDriver;
    if (typeof maybeSetDriver === "function") {
      maybeSetDriver.call(opts.base, this);
    }
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

  jobManager(): JobManager | undefined {
    return this._jobManager;
  }

  // Command observers (for macros + audit)

  private readonly commandObservers: Array<(line: string) => void> = [];

  /** Register a post-handle callback fired for every non-empty input. */
  onCommand(observer: (line: string) => void): () => void {
    this.commandObservers.push(observer);
    return () => {
      const idx = this.commandObservers.indexOf(observer);
      if (idx >= 0) this.commandObservers.splice(idx, 1);
    };
  }

  private notifyObservers(line: string): void {
    for (const obs of this.commandObservers) {
      try {
        obs(line);
      } catch {
        // A broken observer shouldn't affect the command path.
      }
    }
  }

  // Prompt status providers (msfconsole PROMPT-format equivalent)

  /** Registry of `() => string | undefined` closures that decorate `prompt()`. */
  private readonly statusProviders: Array<() => string | undefined> = [];

  /**
   * Register a status provider. Each provider is called on every prompt()
   * and its non-empty return value is joined with ` · ` inside a
   * `[ ... ]` bracket before the trailing `> `. Order of registration is
   * preserved.
   */
  addStatusProvider(fn: () => string | undefined): void {
    this.statusProviders.push(fn);
  }

  /** Clear all registered providers (test helper). */
  clearStatusProviders(): void {
    this.statusProviders.length = 0;
  }

  prompt(): string {
    const top = this.current();
    const head = top.name === "core" ? `${this.promptBase}` : `${this.promptBase}/${top.name}`;
    const status = this.renderStatus();
    return status ? `${head} [${status}]> ` : `${head}> `;
  }

  private renderStatus(): string | undefined {
    if (this.statusProviders.length === 0) return undefined;
    const parts: string[] = [];
    for (const fn of this.statusProviders) {
      try {
        const out = fn();
        if (out && out.trim().length > 0) parts.push(out.trim());
      } catch {
        // A provider throwing should never break the prompt.
      }
    }
    return parts.length === 0 ? undefined : parts.join(" · ");
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

    // Split on unquoted pipes so `modules | grep offense | head 5` routes the
    // first segment through the dispatch chain and the rest through output
    // filters. `save <file>` is the one "sink" filter that writes to disk.
    const segments = splitPipeline(trimmed);
    const primary = segments[0] ?? trimmed;
    const filters = segments.slice(1);

    const tokens = tokenize(primary);
    let cmd = tokens[0] ?? "";
    let args = tokens.slice(1);

    // Alias expansion: if the head token is a registered alias, substitute
    // its value and re-tokenize. Aliases live on the driver instance.
    const expanded = this.expandAlias(cmd, args);
    if (expanded) {
      cmd = expanded.cmd;
      args = expanded.args;
    }

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
        const filtered = await this.applyFilters(result.output, filters);
        this.notifyObservers(trimmed);
        return {
          matched: true,
          ...result,
          ...(filtered !== undefined ? { output: filtered } : {}),
        };
      }
    }

    // Before giving up, let the top dispatcher claim the line via fallback().
    // This is how the InteractiveSessionDispatcher forwards free-form input
    // to session.interact() — its `commands` only lists control verbs.
    const top = this._stack[this._stack.length - 1] as CommandDispatcher & {
      fallback?: (line: string, ctx: CommandContext) => Promise<CommandResult | undefined>;
    };
    if (typeof top.fallback === "function") {
      const ctx: CommandContext = signal
        ? { print: this.print, cwd: this.cwd, driver: this, signal }
        : { print: this.print, cwd: this.cwd, driver: this };
      const result = (await top.fallback(primary, ctx)) ?? {};
      if (result.push) this.push(result.push);
      if (result.pop) this.pop();
      const filtered = await this.applyFilters(result.output, filters);
      this.notifyObservers(trimmed);
      return {
        matched: true,
        ...result,
        ...(filtered !== undefined ? { output: filtered } : {}),
      };
    }

    // Unknown command — suggest a near-match if one exists.
    const suggestion = this.nearestCommand(cmd);
    const hint = suggestion ? `\n    Did you mean: ${suggestion}?` : "";
    return { matched: false, output: `Unknown command: ${cmd}${hint}` };
  }

  // Aliases

  private readonly aliases = new Map<string, string>();

  /** Register an alias: first token `name` expands to the string `value`. */
  registerAlias(name: string, value: string): void {
    this.aliases.set(name, value);
  }

  /** Remove an alias. Returns true if present. */
  unregisterAlias(name: string): boolean {
    return this.aliases.delete(name);
  }

  /** Snapshot of all registered aliases (sorted). */
  listAliases(): Array<{ name: string; value: string }> {
    return [...this.aliases.entries()]
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  private expandAlias(cmd: string, args: string[]): { cmd: string; args: string[] } | undefined {
    const expansion = this.aliases.get(cmd);
    if (expansion === undefined) return undefined;
    const expandedTokens = tokenize(expansion);
    if (expandedTokens.length === 0) return undefined;
    return {
      cmd: expandedTokens[0] as string,
      args: [...expandedTokens.slice(1), ...args],
    };
  }

  // Typo suggestions (Levenshtein-based)

  /** Nearest command name within edit-distance 2, or undefined. */
  private nearestCommand(cmd: string): string | undefined {
    if (!cmd) return undefined;
    const commands = Object.keys(this.allCommandsAsMap());
    let best: { name: string; dist: number } | undefined;
    const threshold = cmd.length <= 4 ? 1 : 2;
    for (const c of commands) {
      const d = levenshtein(cmd.toLowerCase(), c.toLowerCase());
      if (d <= threshold && (!best || d < best.dist)) best = { name: c, dist: d };
    }
    return best?.name;
  }

  // Output filters (shell-style pipe segments)

  private async applyFilters(
    output: string | undefined,
    filters: string[],
  ): Promise<string | undefined> {
    if (!output || filters.length === 0) return undefined;
    let current = output;
    for (const filter of filters) {
      current = await applyOneFilter(current, filter);
    }
    return current;
  }

  /**
   * The top-most dispatcher that behaves like a ModuleDispatcher (has a
   * `.datastore` field). Used by CoreDispatcher's tab-completion to offer
   * option names / values for `set`/`unset`.
   */
  activeModuleLike(): { datastore?: unknown } | undefined {
    for (let i = this._stack.length - 1; i >= 0; i--) {
      const d = this._stack[i] as unknown as { datastore?: unknown };
      if (d && "datastore" in d && d.datastore) return d;
    }
    return undefined;
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

// Pipeline splitting + filters

/**
 * Split an input line on unquoted `|` characters. Segments are returned as
 * whitespace-trimmed strings. Quotes ("..." or '...') are respected so pipes
 * inside quoted regions stay literal.
 */
export function splitPipeline(input: string): string[] {
  const segments: string[] = [];
  let buf = "";
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < input.length; i++) {
    const ch = input[i] as string;
    if (quote) {
      if (ch === quote) quote = null;
      buf += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch as '"' | "'";
      buf += ch;
    } else if (ch === "|") {
      segments.push(buf.trim());
      buf = "";
    } else {
      buf += ch;
    }
  }
  if (buf.length > 0) segments.push(buf.trim());
  return segments.filter((s) => s.length > 0);
}

async function applyOneFilter(input: string, filter: string): Promise<string> {
  const tokens = tokenize(filter);
  const head = tokens[0] ?? "";
  const rest = tokens.slice(1);
  switch (head) {
    case "grep": {
      if (rest.length === 0) return input;
      // Parse grep-style flags from the front: -v (invert), -c (count),
      // -A <n> (after), -B <n> (before), -C <n> (both). Remaining tokens
      // are joined into the pattern.
      let invert = false;
      let countOnly = false;
      let after = 0;
      let before = 0;
      const tokens = [...rest];
      while (tokens.length > 0 && tokens[0]?.startsWith("-")) {
        const flag = tokens.shift() as string;
        if (flag === "-v") {
          invert = true;
        } else if (flag === "-c") {
          countOnly = true;
        } else if (flag === "-A" || flag === "-B" || flag === "-C") {
          const n = Number.parseInt(tokens.shift() ?? "", 10);
          if (!Number.isFinite(n) || n < 0) return `[-] grep: ${flag} needs a non-negative int`;
          if (flag === "-A") after = n;
          else if (flag === "-B") before = n;
          else {
            after = n;
            before = n;
          }
        } else if (flag === "--") {
          break;
        } else {
          // Unknown flag — treat as part of the pattern (grep compat).
          tokens.unshift(flag);
          break;
        }
      }
      if (tokens.length === 0) return "[-] grep: missing pattern";
      const needle = tokens.join(" ");
      let regex: RegExp;
      try {
        regex = new RegExp(needle, "i");
      } catch {
        return `[-] grep: invalid pattern: ${needle}`;
      }
      const lines = input.split("\n");
      const matches = lines.map((line) => {
        const hit = regex.test(line);
        return invert ? !hit : hit;
      });
      if (countOnly) return `${matches.filter(Boolean).length}`;
      if (after === 0 && before === 0) {
        return lines.filter((_, i) => matches[i]).join("\n");
      }
      // Context mode: include N lines before/after each match.
      const keep = new Array<boolean>(lines.length).fill(false);
      for (let i = 0; i < lines.length; i++) {
        if (!matches[i]) continue;
        const lo = Math.max(0, i - before);
        const hi = Math.min(lines.length - 1, i + after);
        for (let j = lo; j <= hi; j++) keep[j] = true;
      }
      return lines.filter((_, i) => keep[i]).join("\n");
    }
    case "head": {
      const n = Number.parseInt(rest[0] ?? "10", 10);
      if (!Number.isFinite(n) || n <= 0) return input;
      return input.split("\n").slice(0, n).join("\n");
    }
    case "tail": {
      const n = Number.parseInt(rest[0] ?? "10", 10);
      if (!Number.isFinite(n) || n <= 0) return input;
      return input.split("\n").slice(-n).join("\n");
    }
    case "count":
    case "wc": {
      return `${input.split("\n").length} lines`;
    }
    case "save": {
      const target = rest[0];
      if (!target) return "[-] save: missing filename";
      try {
        const { writeFile } = await import("node:fs/promises");
        await writeFile(target, input.endsWith("\n") ? input : `${input}\n`, "utf8");
        return `[+] Wrote ${input.split("\n").length} lines to ${target}`;
      } catch (err) {
        return `[-] save: ${toErrorMessage(err)}`;
      }
    }
    case "page": {
      // `| page` pipes the output through $PAGER (default: less -R -F -X).
      // Non-TTY shells don't have a pager to hand off to, so we just
      // return the text unchanged — pipes still compose.
      return pageOutput(input);
    }
    default:
      return `${input}\n[!] unknown filter: ${head}`;
  }
}

async function pageOutput(text: string): Promise<string> {
  if (!process.stdout.isTTY) return text;
  const pagerSpec = process.env["PAGER"] ?? "less -R -F -X";
  const [cmd, ...args] = pagerSpec.split(" ").filter(Boolean);
  if (!cmd) return text;
  const { spawn } = await import("node:child_process");
  return await new Promise<string>((resolve) => {
    try {
      const child = spawn(cmd, args, { stdio: ["pipe", "inherit", "inherit"] });
      child.on("error", () => resolve(text));
      child.on("exit", () => resolve(""));
      child.stdin.end(text.endsWith("\n") ? text : `${text}\n`);
    } catch {
      resolve(text);
    }
  });
}

// Levenshtein (small, iterative)

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  let prev = new Array<number>(b.length + 1);
  let curr = new Array<number>(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min((prev[j] ?? 0) + 1, (curr[j - 1] ?? 0) + 1, (prev[j - 1] ?? 0) + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[b.length] ?? 0;
}

/**
 * Core dispatcher — the always-loaded base layer providing
 * help / set / setg / unset / show / info / search / use / back / history /
 * resource / makerc / exit / banner / quit.
 *
 * Most commands operate against the layered Datastore + ModuleRegistry.
 *
 * `use <module>` pushes a per-module dispatcher (see ./module-dispatcher.ts);
 * `back` pops it.
 */

import type { AgentRuntimeBackend } from "../../contracts.js";
import type { ModuleRegistry } from "../../modules/registry.js";
import type { CopilotModule } from "../../modules/types.js";
import { wrapToWidth } from "../../ui/format.js";
import { type Datastore, formatOptionsTable } from "../options.js";
import { formatSearchResult, searchCatalog } from "../search.js";
import { randomTip } from "../tips.js";
import { ModuleDispatcher, type ModuleToolRunner, modelOptionSpec } from "./module-dispatcher.js";
import type { CommandContext, CommandDispatcher, CommandResult } from "./types.js";

export interface CoreDispatcherOptions {
  registry: ModuleRegistry;
  /** Global datastore — stores `setg`-set keys. */
  globals: Datastore;
  /** Active agent runtime backend, used to validate universal model overrides. */
  agentRuntimeBackend?: AgentRuntimeBackend;
  /** Source of command history (for `history`). */
  history: () => string[];
  /** Sink to mutate history (for `history -c`). */
  clearHistory?: () => void;
  /** Resource-script runner (replays commands from a .kzrc.yaml). */
  runResource?: (path: string, signal?: AbortSignal) => Promise<void>;
  /** "make rc" — write recent commands as a resource script. */
  makeResource?: (path: string) => Promise<void>;
  /**
   * Optional tool runner — when present, every `ModuleDispatcher` pushed by
   * `use <module>` receives this so `run`/`exploit` actually invoke the tool.
   * Without it, `run` just prints "[*] Would invoke ..." (useful for tests).
   */
  runTool?: ModuleToolRunner;
  /**
   * Optional recipe resolver — returns an absolute path to `<name>.kzrc.yaml`
   * or undefined if no recipe with that name exists. When present, enables the
   * `recipes` dispatcher command.
   */
  resolveRecipePath?: (name: string) => string | undefined;
  /** Optional recipe listing — returns an array of {name, path, description?}. */
  listRecipes?: () => Array<{ name: string; path: string; description?: string }>;
  /**
   * Optional editor launcher — when present, `edit <NAME>` opens $EDITOR on
   * a scratch file pre-seeded with the current value of NAME and, on save,
   * writes the contents back to the active Datastore.
   *
   * The host wires this (shell.ts), because suspending the Ink render surface
   * during $EDITOR is a host-level concern. Returns the new value or null on
   * cancel.
   */
  openEditor?: (initial: string) => Promise<string | null>;
  /**
   * Optional JobManager — when present, enables the `jobs` command and
   * ModuleDispatcher's `run --bg` path (see that file). Without it, all
   * runs are foreground and `jobs` reports "not enabled".
   */
  jobManager?: import("../../jobs/manager.js").JobManager;
  /**
   * Optional REPL launcher — when present, `repl` drops into an interactive
   * Node REPL with framework objects bound. Host wires this so TTY suspension
   * (Ink) stays a host-level concern.
   */
  openRepl?: () => Promise<void>;
  /**
   * Optional spool controller — enables the `spool` command. The host wires
   * the same controller's `tap(line)` into the print sink's onPrint hook so
   * every rendered line is mirrored to the active spool file (if any).
   */
  spool?: import("../spool.js").SpoolController;
  /**
   * Optional ModuleEventBus — powers the `wait_for` command. Host wires
   * `core.events` here so operators can block on framework events from
   * resource scripts.
   */
  events?: import("../../bus/module-events.js").ModuleEventBus;
  /** Version string for the `version` command. Typically the package.json version. */
  frameworkVersion?: string;
  /** Audit log path resolver for the `logs` command. */
  getLogPath?: () => string | undefined;
  /**
   * Optional Scheduler accessor — lazily resolved to accommodate the
   * circular build order in shell.ts (Scheduler needs the Driver, the
   * Driver contains the CoreDispatcher). When unset, the `schedule`
   * command reports "not enabled."
   */
  scheduler?: () => import("../../scheduler/core.js").Scheduler | undefined;
}

const COMMANDS: Record<string, string> = {
  help: "Show help (alias: ?)",
  "?": "Show help",
  banner: "Print the Kuzushi banner",
  modules: "List loaded modules",
  use: "Select a module (descend into its command set)",
  back: "Return to the previous dispatcher",
  set: "Set a variable in the current module datastore",
  setg: "Set a variable globally (inherited by every module)",
  unset: "Unset a variable in the current module",
  unsetg: "Unset a global variable",
  show: "Show options/advanced/missing/modules",
  info: "Show detailed info for a module or tool",
  search: "Search the module/tool catalog",
  history: "Show or clear command history",
  resource: "Replay commands from a resource script",
  makerc: "Save recent commands as a resource script",
  recipes: "List or run a bundled recipe (e.g. `recipes run quick-scan`)",
  edit: "Open $EDITOR on a Datastore value (typically an agent prompt)",
  tip: "Print a random tip of the day",
  examples: "Show canonical usage examples for a module (`examples semgrep`)",
  why: "Explain why the active module's `run` preflight would fail",
  alias: "Define a command alias (`alias qs = recipes run quick-scan`)",
  unalias: "Remove a previously-defined alias",
  favorite: "Star a module or tool for quick recall",
  favorites: "List starred modules/tools (prefix with ! to run, e.g. !1)",
  unfavorite: "Remove a star",
  pushm: "Push the current module onto the module stack",
  popm: "Pop the last-pushed module back onto the dispatcher stack",
  listm: "List the module stack",
  jobs: "List / tail / kill background jobs (jobs, jobs -i <id>, jobs -k <id>)",
  repl: "Drop into a Node REPL with core/registry/workspace bound",
  spool: "Tee shell output to a file: `spool <file>` / `spool off` / `spool status`",
  sleep: "Pause for N seconds (honors ^C)",
  wait_for: "Block until a ModuleEventBus event fires (`wait_for scan:finding 30`)",
  time: "Time another shell command (`time modules`)",
  clear: "Clear the terminal screen",
  version: "Show Kuzushi version + loaded module summary",
  logs: "Tail the audit log (`logs` for last 50 lines, `logs -f` to follow)",
  connect: "Open a raw TCP socket to <host> <port> (interactive)",
  schedule: "Interval-based job runner (`schedule every <n>m|h|d <cmd...>` / list / remove)",
  macro:
    "Record / replay / list / delete command macros (`macro record <name>` / stop / play / list / delete)",
  exit: "Exit the shell",
  quit: "Exit the shell (alias for exit)",
};

export class CoreDispatcher implements CommandDispatcher {
  readonly name = "core";
  readonly commands = COMMANDS;

  constructor(private readonly opts: CoreDispatcherOptions) {
    if (!opts.globals.spec("MODEL")) {
      opts.globals.registerOption(modelOptionSpec("MODEL", opts.agentRuntimeBackend));
    }
  }

  async execute(
    cmd: string,
    args: string[],
    ctx: CommandContext,
  ): Promise<CommandResult | undefined> {
    switch (cmd) {
      case "help":
      case "?":
        return this.cmd_help(ctx);
      case "banner":
        return this.cmd_banner(ctx);
      case "exit":
      case "quit":
        return { exit: true };
      case "modules":
        return this.cmd_modules(ctx);
      case "use":
        return this.cmd_use(args, ctx);
      case "back":
        return { pop: true };
      case "set":
        return this.cmd_set(args, ctx, "module");
      case "setg":
        return this.cmd_set(args, ctx, "global");
      case "unset":
        return this.cmd_unset(args, ctx, "module");
      case "unsetg":
        return this.cmd_unset(args, ctx, "global");
      case "show":
        return this.cmd_show(args, ctx);
      case "info":
        return this.cmd_info(args, ctx);
      case "search":
        return this.cmd_search(args, ctx);
      case "history":
        return this.cmd_history(args, ctx);
      case "resource":
        return this.cmd_resource(args, ctx);
      case "makerc":
        return this.cmd_makerc(args, ctx);
      case "recipes":
        return this.cmd_recipes(args, ctx);
      case "edit":
        return this.cmd_edit(args, ctx);
      case "tip":
        return this.cmd_tip();
      case "examples":
        return this.cmd_examples(args);
      case "why":
        return this.cmd_why(ctx);
      case "alias":
        return this.cmd_alias(args, ctx);
      case "unalias":
        return this.cmd_unalias(args, ctx);
      case "favorite":
        return this.cmd_favorite(args, ctx);
      case "favorites":
        return this.cmd_favorites(ctx);
      case "unfavorite":
        return this.cmd_unfavorite(args, ctx);
      case "pushm":
        return this.cmd_pushm(ctx);
      case "popm":
        return this.cmd_popm(ctx);
      case "listm":
        return this.cmd_listm(ctx);
      case "jobs":
        return this.cmd_jobs(args, ctx);
      case "repl":
        return this.cmd_repl(ctx);
      case "spool":
        return this.cmd_spool(args, ctx);
      case "sleep":
        return this.cmd_sleep(args, ctx);
      case "wait_for":
        return this.cmd_wait_for(args, ctx);
      case "time":
        return this.cmd_time(args, ctx);
      case "clear":
        return this.cmd_clear();
      case "version":
        return this.cmd_version();
      case "logs":
        return this.cmd_logs(args);
      case "connect":
        return this.cmd_connect(args, ctx);
      case "schedule":
        return this.cmd_schedule(args);
      case "macro":
        return this.cmd_macro(args, ctx);
      default:
        return { output: `Unknown command: ${cmd}` };
    }
  }

  /** Driver ref threaded in by the DispatcherDriver so completion can peek
   * at the active module's datastore. Null until wired. */
  private driverRef: { activeModuleLike?: () => { datastore?: unknown } | undefined } | undefined;

  /** Called by DispatcherDriver post-construction so complete() can reach the active module. */
  setDriver(driver: { activeModuleLike?: () => { datastore?: unknown } | undefined }): void {
    this.driverRef = driver;
  }

  complete(cmd: string, partial: string, words: string[]): string[] {
    if (cmd === "use" || cmd === "info") {
      const ids = this.opts.registry.ids();
      return ids.filter((id) => id.startsWith(partial));
    }
    if (cmd === "show") {
      return ["options", "advanced", "evasion", "missing", "modules", "globals"].filter((s) =>
        s.startsWith(partial),
      );
    }
    if (cmd === "search") {
      // Partial is the token being typed. If it doesn't contain a colon, it
      // might be a key (type:, category:, rank:...); offer those.
      if (!partial.includes(":")) {
        const keys = ["type:", "category:", "rank:", "cve:", "cwe:", "author:", "module:", "tool:"];
        return keys.filter((k) => k.startsWith(partial));
      }
      const [key, valuePartial] = partial.split(":", 2);
      if (key === "type") return ["module", "tool"].filter((v) => v.startsWith(valuePartial ?? ""));
      if (key === "category") {
        return ["offense", "defense", "governance", "intel"].filter((v) =>
          v.startsWith(valuePartial ?? ""),
        );
      }
      if (key === "rank") {
        return ["manual", "low", "normal", "good", "great", "excellent"].filter((v) =>
          v.startsWith(valuePartial ?? ""),
        );
      }
      return [];
    }
    if (cmd === "set" || cmd === "unset" || cmd === "setg" || cmd === "unsetg") {
      // `words` always includes the command itself. argPosition is 1-based:
      //   words=[cmd]          → completing arg 1 (option name)
      //   words=[cmd, NAME]    → completing arg 2 (value)
      const argPosition = words.length;
      if (argPosition <= 1) {
        // Completing the option name.
        const storeModule = this.activeModuleDispatcherFromRegistry();
        const specs = storeModule?.datastore.allSpecs() ?? this.opts.globals.allSpecs();
        return specs
          .filter((s) => !s.advanced && !s.evasion)
          .map((s) => s.name)
          .filter((n) => n.toUpperCase().startsWith(partial.toUpperCase()));
      }
      if (argPosition === 2) {
        // Completing a value. Look up the option by name (words[1]).
        const optName = (words[1] ?? "").toUpperCase();
        const storeModule = this.activeModuleDispatcherFromRegistry();
        const spec = storeModule?.datastore.spec(optName) ?? this.opts.globals.spec(optName);
        if (!spec) return [];
        if (spec.type === "enum" && spec.choices) {
          return (spec.choices as readonly string[]).filter((c) => c.startsWith(partial));
        }
        if (spec.type === "bool") {
          return ["true", "false", "yes", "no"].filter((c) => c.startsWith(partial));
        }
      }
      return [];
    }
    if (cmd === "recipes" && words.length <= 1) {
      return ["list", "run"].filter((s) => s.startsWith(partial));
    }
    if (cmd === "recipes" && words[1] === "run") {
      const recipes = this.opts.listRecipes?.() ?? [];
      return recipes.map((r) => r.name).filter((n) => n.startsWith(partial));
    }
    return [];
  }

  /** Peek at the active ModuleDispatcher via the Driver back-ref, if set. */
  private activeModuleDispatcherFromRegistry(): ModuleDispatcher | undefined {
    const peek = this.driverRef?.activeModuleLike?.();
    if (peek && peek instanceof ModuleDispatcher) return peek;
    return undefined;
  }

  // Handlers

  private cmd_help(ctx: CommandContext): CommandResult {
    const all = ctx.driver.allCommands();
    const width = Math.max(...all.map((c) => c.cmd.length));
    const lines = all.map((c) => `  ${c.cmd.padEnd(width)}  ${c.help}`);
    return { output: ["Available commands:", ...lines].join("\n") };
  }

  private cmd_banner(ctx: CommandContext): CommandResult {
    void ctx;
    return {
      output: [
        "       _                       _     _ ",
        "  _  _| | _   _ ___ _   _ ___| |__ (_)",
        " | |/ / |/ | | |_  / | | / __| '_ \\| |",
        " |   <| ||  |_| |/ /| |_| \\__ \\ | | | |",
        " |_|\\_\\_||_____/___|\\__,_|___/_| |_|_|",
        "",
        "      Type ? for help, modules to list capabilities.",
      ].join("\n"),
    };
  }

  private cmd_modules(_ctx: CommandContext): CommandResult {
    const list = this.opts.registry.list();
    if (list.length === 0) return { output: "  (no modules loaded)" };
    const pad = (s: string, w: number) => s + " ".repeat(Math.max(0, w - s.length));
    const widths = {
      id: Math.max(2, ...list.map((m) => m.id.length)),
      cat: Math.max(8, ...list.map((m) => m.category.length)),
      ver: Math.max(7, ...list.map((m) => m.version.length)),
      tools: 5,
    };
    // Column start for the Description cell: 2-space indent + each leader cell
    // followed by a 2-space gap.
    const descStart = 2 + widths.id + 2 + widths.cat + 2 + widths.ver + 2 + widths.tools + 2;
    const availableWidth = process.stdout?.columns ?? 100;
    const descWidth = Math.max(20, availableWidth - descStart - 1);
    const contPad = " ".repeat(descStart);

    const header = `  ${pad("Id", widths.id)}  ${pad("Category", widths.cat)}  ${pad("Version", widths.ver)}  Tools  Description`;
    const sep = `  ${"-".repeat(widths.id)}  ${"-".repeat(widths.cat)}  ${"-".repeat(widths.ver)}  -----  -----------`;
    const body = list
      .map((m) => {
        const descLines = wrapToWidth(m.description, descWidth);
        const first = descLines[0] ?? "";
        const rest = descLines.slice(1);
        const leader = `  ${pad(m.id, widths.id)}  ${pad(m.category, widths.cat)}  ${pad(m.version, widths.ver)}  ${String(m.toolCount).padStart(5)}  ${first}`;
        return [leader, ...rest.map((l) => `${contPad}${l}`)].join("\n");
      })
      .join("\n");
    return { output: [header, sep, body].join("\n") };
  }

  private cmd_use(args: string[], _ctx: CommandContext): CommandResult {
    const id = args[0];
    if (!id) return { output: "Usage: use <module-id>" };
    if (!this.opts.registry.has(id)) {
      const all = this.opts.registry.ids();
      const suggestions = suggestMatches(id, all, 3);
      const hint =
        suggestions.length > 0
          ? `Did you mean: ${suggestions.join(", ")}?`
          : "Run `modules` to list all loaded modules.";
      return { output: `Unknown module: ${id}. ${hint}` };
    }
    const mod = this.opts.registry.get(id);
    const dispatcher = new ModuleDispatcher({
      module: mod,
      globals: this.opts.globals,
      agentRuntimeBackend: this.opts.agentRuntimeBackend,
      ...(this.opts.runTool ? { runTool: this.opts.runTool } : {}),
    });
    return { push: dispatcher, output: `Selected module: ${mod.id}` };
  }

  private cmd_set(args: string[], ctx: CommandContext, scope: "module" | "global"): CommandResult {
    if (args.length < 2) {
      return { output: scope === "global" ? "Usage: setg NAME VALUE" : "Usage: set NAME VALUE" };
    }
    const [name, ...rest] = args as [string, ...string[]];
    const value = rest.join(" ");
    const target = scope === "global" ? this.opts.globals : this.findModuleStore(ctx);
    if (!target) {
      return {
        output: "No module selected. Use `use <module>` first, or use `setg` for globals.",
      };
    }
    const err = target.set(name, value, scope);
    if (err) return { output: `[-] Invalid value for ${name}: ${err}` };
    return { output: `${name} => ${value}` };
  }

  private cmd_unset(
    args: string[],
    ctx: CommandContext,
    scope: "module" | "global",
  ): CommandResult {
    const name = args[0];
    if (!name) return { output: scope === "global" ? "Usage: unsetg NAME" : "Usage: unset NAME" };
    const target = scope === "global" ? this.opts.globals : this.findModuleStore(ctx);
    target?.unset(name, scope);
    return { output: `Unset ${name}` };
  }

  private cmd_show(args: string[], ctx: CommandContext): CommandResult {
    const what = (args[0] ?? "options").toLowerCase();
    const moduleStore = this.findModuleStore(ctx);
    switch (what) {
      case "options":
        if (!moduleStore) return { output: "No module selected. Use `use <module>` first." };
        return { output: formatOptionsTable(moduleStore, { highlightMissing: true }) };
      case "advanced":
        if (!moduleStore) return { output: "No module selected." };
        return { output: formatOptionsTable(moduleStore, { advanced: true }) };
      case "evasion":
        if (!moduleStore) return { output: "No module selected." };
        return { output: formatOptionsTable(moduleStore, { evasion: true }) };
      case "missing": {
        if (!moduleStore) return { output: "No module selected." };
        const missing = moduleStore.missingRequired();
        return {
          output:
            missing.length === 0
              ? "All required options are set."
              : `Missing: ${missing.join(", ")}`,
        };
      }
      case "globals":
        return { output: formatOptionsTable(this.opts.globals) };
      case "modules":
        return this.cmd_modules(ctx);
      default: {
        const validTargets = ["options", "advanced", "evasion", "missing", "globals", "modules"];
        const suggestions = suggestMatches(what, validTargets, 3);
        const suggestLine =
          suggestions.length > 0
            ? `Did you mean: ${suggestions.join(", ")}?`
            : `Try: ${validTargets.join(", ")}.`;
        const lines = [`Unknown show target: "${what}". ${suggestLine}`];
        const active = this.activeModuleDispatcher(ctx);
        if (active) {
          lines.push(
            `(You're in the ${active.module.id} module — run \`tools\` to list its actions, or \`run <verb>\` to invoke one.)`,
          );
        }
        return { output: lines.join("\n") };
      }
    }
  }

  private cmd_info(args: string[], _ctx: CommandContext): CommandResult {
    const ref = args[0];
    if (!ref) return { output: "Usage: info <module-or-tool>" };
    if (ref.includes(":")) {
      const resolved = this.opts.registry.resolveTool(ref);
      if (!resolved) return { output: `Unknown tool: ${ref}` };
      return { output: formatToolInfo(resolved.module, resolved.tool) };
    }
    if (!this.opts.registry.has(ref)) return { output: `Unknown module: ${ref}` };
    return { output: formatModuleInfo(this.opts.registry.get(ref)) };
  }

  private cmd_search(args: string[], _ctx: CommandContext): CommandResult {
    const list = this.opts.registry.ids().map((id) => this.opts.registry.get(id));
    const result = searchCatalog(list, args.join(" "));
    return { output: formatSearchResult(result) };
  }

  private cmd_history(args: string[], _ctx: CommandContext): CommandResult {
    const arg = args[0] ?? "";
    if (arg === "-c") {
      this.opts.clearHistory?.();
      return { output: "Cleared command history." };
    }
    const limit =
      arg === "-n" && args[1] && /^\d+$/.test(args[1])
        ? Number.parseInt(args[1] as string, 10)
        : undefined;
    const lines = this.opts.history();
    const slice = limit ? lines.slice(-limit) : lines;
    return {
      output:
        slice.length === 0 ? "  (no history)" : slice.map((s, i) => `  ${i + 1}  ${s}`).join("\n"),
    };
  }

  private async cmd_resource(args: string[], ctx: CommandContext): Promise<CommandResult> {
    const file = args[0];
    if (!file) return { output: "Usage: resource <path-to-rc>" };
    if (!this.opts.runResource)
      return { output: "[-] Resource scripts are not enabled in this driver." };
    try {
      await this.opts.runResource(file, ctx.signal);
      return {};
    } catch (err) {
      return { output: `[-] Resource failed: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  private async cmd_makerc(args: string[], _ctx: CommandContext): Promise<CommandResult> {
    const file = args[0];
    if (!file) return { output: "Usage: makerc <path-to-rc>" };
    if (!this.opts.makeResource) return { output: "[-] makerc is not enabled in this driver." };
    try {
      await this.opts.makeResource(file);
      return { output: `Saved resource script to ${file}` };
    } catch (err) {
      return { output: `[-] makerc failed: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  /**
   * `recipes` — list available recipes (no args) or run one (`recipes run <name>`).
   * A recipe is a .kzrc.yaml file under the repo's `recipes/` directory,
   * resolved via `opts.resolveRecipePath`.
   */
  private async cmd_recipes(args: string[], ctx: CommandContext): Promise<CommandResult> {
    const sub = args[0];
    if (!sub || sub === "list") {
      if (!this.opts.listRecipes) {
        return { output: "[-] Recipes are not enabled in this driver." };
      }
      const recipes = this.opts.listRecipes();
      if (recipes.length === 0) return { output: "  (no recipes available)" };
      const pad = (s: string, w: number) => s + " ".repeat(Math.max(0, w - s.length));
      const width = Math.max(...recipes.map((r) => r.name.length));
      const lines = recipes.map((r) => `  ${pad(r.name, width)}  ${r.description ?? r.path}`);
      return { output: ["Available recipes:", ...lines].join("\n") };
    }
    if (sub === "run") {
      const name = args[1];
      if (!name) return { output: "Usage: recipes run <name>" };
      if (!this.opts.resolveRecipePath || !this.opts.runResource) {
        return { output: "[-] Recipes are not enabled in this driver." };
      }
      const file = this.opts.resolveRecipePath(name);
      if (!file) return { output: `[-] Unknown recipe: ${name}. Try: recipes` };
      ctx.print.status(`Running recipe: ${name}`);
      try {
        await this.opts.runResource(file, ctx.signal);
        return {};
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { output: `[-] Recipe failed: ${msg}` };
      }
    }
    return { output: `Usage: recipes [list] | recipes run <name>` };
  }

  /**
   * `edit <NAME>` — open $EDITOR on a scratch file pre-seeded with the current
   * Datastore value, then store the edited contents back on save.
   */
  private async cmd_edit(args: string[], ctx: CommandContext): Promise<CommandResult> {
    const name = args[0];
    if (!name) return { output: "Usage: edit <NAME>" };
    if (!this.opts.openEditor) return { output: "[-] `edit` is not enabled in this driver." };

    const moduleStore = this.findModuleStore(ctx);
    const target = moduleStore ?? this.opts.globals;
    const scope: "module" | "global" = moduleStore ? "module" : "global";
    const current = target.get<string>(name);
    const initial = typeof current === "string" ? current : "";

    let updated: string | null;
    try {
      updated = await this.opts.openEditor(initial);
    } catch (err) {
      return { output: `[-] edit failed: ${err instanceof Error ? err.message : String(err)}` };
    }
    if (updated == null) return { output: "[*] Edit cancelled — value unchanged." };

    const err = target.set(name, updated, scope);
    if (err) return { output: `[-] Invalid value: ${err}` };
    return { output: `[+] Updated ${name} (${updated.length} chars, scope=${scope}).` };
  }

  // Discovery & learning-curve commands

  private cmd_tip(): CommandResult {
    return { output: `[*] Tip: ${randomTip()}` };
  }

  private cmd_examples(args: string[]): CommandResult {
    const id = args[0];
    if (!id) return { output: "Usage: examples <module>" };
    if (!this.opts.registry.has(id)) return { output: `Unknown module: ${id}` };
    const mod = this.opts.registry.get(id);
    const examples = mod.examples;
    if (!examples || examples.length === 0) {
      return { output: `  (${id} has no examples registered)` };
    }
    const lines: string[] = [`Common invocations for module: ${id}`, ""];
    for (const ex of examples) {
      for (const line of ex.split("\n")) lines.push(`  ${line}`);
      lines.push("");
    }
    return { output: lines.join("\n") };
  }

  private cmd_why(ctx: CommandContext): CommandResult {
    const topModule = this.activeModuleDispatcher(ctx);
    if (!topModule) {
      return { output: "[*] No module selected — `why` explains preflight failures." };
    }
    const mod = topModule.module;
    const reqs = mod.requires ?? [];
    if (reqs.length === 0) {
      return {
        output: `[*] ${mod.id} declares no preflight requirements — any failure was a runtime error.`,
      };
    }
    const shell = ctx.driver.getShellState?.();
    const snapshot = (shell?.contextSnapshot ?? undefined) as Record<string, unknown> | undefined;
    const threatModel = shell?.threatModel;
    const lines: string[] = [`Why ${mod.id}'s preflight cares:`];
    for (const req of reqs) {
      if (req.kind === "snapshot") {
        const present =
          req.moduleId === "threat-model" && req.field === "threatModel"
            ? threatModel != null
            : !!snapshot && snapshot[req.field] != null;
        lines.push(
          `  ${present ? "✓" : "✗"} ${req.moduleId}.${req.field}   (produced by: ${req.moduleId})`,
        );
        if (!present) {
          lines.push(
            req.moduleId === "threat-model"
              ? "      Fix: run '/threats regen dfd'"
              : `      Fix: 'use ${req.moduleId}' then 'run'`,
          );
        }
      } else if (req.kind === "findings") {
        const count = ctx.driver.getFindingCount?.() ?? 0;
        const need = req.minCount ?? 1;
        lines.push(`  ${count >= need ? "✓" : "✗"} findings   (have ${count}, need ${need}+)`);
        if (count < need) {
          lines.push(`      Fix: run a scanner first (e.g. 'use semgrep' then 'run')`);
        }
      } else if (req.kind === "hosts") {
        const count = ctx.driver.getHostCount?.() ?? 0;
        const need = req.minCount ?? 1;
        lines.push(`  ${count >= need ? "✓" : "✗"} hosts   (have ${count}, need ${need}+)`);
        if (count < need) lines.push("      Fix: add hosts to the active workspace first");
      } else if (req.kind === "session") {
        const count = ctx.driver.getLiveSessionCount?.(req.sessionKind) ?? 0;
        const label = req.sessionKind ? `'${req.sessionKind}'` : "any";
        lines.push(`  ${count > 0 ? "✓" : "✗"} ${label} live session   (have ${count})`);
      } else if (req.kind === "env") {
        const present = !!process.env[req.name];
        lines.push(`  ${present ? "✓" : "✗"} env ${req.name}`);
      }
    }
    lines.push("");
    lines.push(`  Or run the full DAG: 'use sast' then 'run'`);
    return { output: lines.join("\n") };
  }

  // Aliases

  private cmd_alias(args: string[], ctx: CommandContext): CommandResult {
    const driver = ctx.driver as unknown as {
      registerAlias?: (n: string, v: string) => void;
      listAliases?: () => Array<{ name: string; value: string }>;
    };
    if (args.length === 0) {
      const aliases = driver.listAliases?.() ?? [];
      if (aliases.length === 0) return { output: "  (no aliases)" };
      const pad = (s: string, w: number) => s + " ".repeat(Math.max(0, w - s.length));
      const width = Math.max(...aliases.map((a) => a.name.length));
      return {
        output: aliases.map((a) => `  ${pad(a.name, width)}  =>  ${a.value}`).join("\n"),
      };
    }
    // Parse `name = value...` or `name value...`
    const eqIdx = args.indexOf("=");
    const name = args[0];
    const value = eqIdx > 0 ? args.slice(eqIdx + 1).join(" ") : args.slice(1).join(" ");
    if (!name || !value) return { output: "Usage: alias <name> = <command...>" };
    driver.registerAlias?.(name, value);
    return { output: `[+] Alias set: ${name} => ${value}` };
  }

  private cmd_unalias(args: string[], ctx: CommandContext): CommandResult {
    const name = args[0];
    if (!name) return { output: "Usage: unalias <name>" };
    const driver = ctx.driver as unknown as { unregisterAlias?: (n: string) => boolean };
    const removed = driver.unregisterAlias?.(name) ?? false;
    return { output: removed ? `[+] Removed alias: ${name}` : `[-] No such alias: ${name}` };
  }

  // Favorites (numeric-recall aliases)

  private readonly favorites: string[] = [];

  private cmd_favorite(args: string[], ctx: CommandContext): CommandResult {
    const target = args.join(" ").trim();
    if (!target) {
      const top = this.activeModuleDispatcher(ctx);
      if (!top) return { output: "Usage: favorite <module|tool|command>" };
      if (!this.favorites.includes(top.module.id)) this.favorites.push(top.module.id);
      return { output: `[+] Starred ${top.module.id}` };
    }
    if (!this.favorites.includes(target)) this.favorites.push(target);
    const driver = ctx.driver as unknown as { registerAlias?: (n: string, v: string) => void };
    // Register `!<idx>` shortcut for each favorite.
    const idx = this.favorites.indexOf(target) + 1;
    driver.registerAlias?.(`!${idx}`, target);
    return { output: `[+] Starred ${target}  (recall: !${idx})` };
  }

  private cmd_favorites(_ctx: CommandContext): CommandResult {
    if (this.favorites.length === 0) return { output: "  (no favorites yet)" };
    return {
      output: this.favorites.map((f, i) => `  !${i + 1}  ${f}`).join("\n"),
    };
  }

  private cmd_unfavorite(args: string[], ctx: CommandContext): CommandResult {
    const target = args.join(" ").trim();
    const idx = this.favorites.indexOf(target);
    if (idx < 0) return { output: `[-] Not in favorites: ${target}` };
    this.favorites.splice(idx, 1);
    const driver = ctx.driver as unknown as { unregisterAlias?: (n: string) => boolean };
    driver.unregisterAlias?.(`!${idx + 1}`);
    return { output: `[+] Unstarred ${target}` };
  }

  // Module stack (pushm / popm / listm)

  private readonly savedModules: string[] = [];

  private cmd_pushm(ctx: CommandContext): CommandResult {
    const top = this.activeModuleDispatcher(ctx);
    if (!top) return { output: "[-] No module to push. Use `use <module>` first." };
    this.savedModules.push(top.module.id);
    return {
      output: `[+] Saved ${top.module.id} on the module stack (depth ${this.savedModules.length}).`,
    };
  }

  private cmd_popm(ctx: CommandContext): CommandResult {
    const id = this.savedModules.pop();
    if (!id) return { output: "[-] Module stack is empty." };
    if (!this.opts.registry.has(id)) return { output: `[-] Module '${id}' is no longer loaded.` };
    // Pop any currently-focused module first so `use` doesn't stack.
    const driver = ctx.driver;
    while (driver.current() instanceof ModuleDispatcher) driver.pop();
    const mod = this.opts.registry.get(id);
    const newDispatcher = new ModuleDispatcher({
      module: mod,
      globals: this.opts.globals,
      ...(this.opts.runTool ? { runTool: this.opts.runTool } : {}),
    });
    return { push: newDispatcher, output: `[+] Popped ${id} back.` };
  }

  private cmd_listm(_ctx: CommandContext): CommandResult {
    if (this.savedModules.length === 0) return { output: "  (module stack empty)" };
    return {
      output: this.savedModules.map((id, i) => `  ${i}  ${id}`).join("\n"),
    };
  }

  // Background jobs

  private async cmd_jobs(args: string[], _ctx: CommandContext): Promise<CommandResult> {
    const mgr = this.opts.jobManager;
    if (!mgr) return { output: "[-] Background jobs are not enabled in this driver." };

    const sub = args[0];
    if (sub === "-k") {
      const id = args[1];
      if (!id) return { output: "Usage: jobs -k <id>" };
      const killed = mgr.kill(id);
      return {
        output: killed ? `[*] Cancelled job ${id}` : `[-] Job ${id} not running.`,
      };
    }
    if (sub === "-i") {
      const id = args[1];
      if (!id) return { output: "Usage: jobs -i <id>" };
      const job = mgr.get(id);
      if (!job) return { output: `[-] Unknown job: ${id}` };
      // One-shot snapshot of the buffered output — the prompt status line
      // and the `log` event cover live-tailing in the Ink UI.
      const lines = [
        `[*] Job ${id} (${job.label}) — ${job.state}`,
        ...job.output.map((l) => `    ${l}`),
      ];
      if (job.state !== "running") {
        const elapsed = ((job.endedAt ?? Date.now()) - job.startedAt) / 1000;
        lines.push(`    ${job.state} after ${elapsed.toFixed(1)}s`);
        if (job.result) lines.push(`    ${job.result}`);
        if (job.error) lines.push(`    error: ${job.error}`);
      }
      return { output: lines.join("\n") };
    }
    if (sub === "-c" || sub === "--clear") {
      const removed = mgr.clearCompleted();
      return { output: `[*] Cleared ${removed} completed job(s).` };
    }

    // Default: list.
    const jobs = mgr.list();
    if (jobs.length === 0) return { output: "  (no jobs)" };
    const pad = (s: string, w: number) => s + " ".repeat(Math.max(0, w - s.length));
    const widths = {
      id: Math.max(2, ...jobs.map((j) => j.id.length)),
      state: Math.max(5, ...jobs.map((j) => j.state.length)),
      elapsed: 7,
      label: Math.max(5, ...jobs.map((j) => j.label.length)),
    };
    const header = `  ${pad("Id", widths.id)}  ${pad("State", widths.state)}  ${pad("Elapsed", widths.elapsed)}  Label`;
    const sep = `  ${"-".repeat(widths.id)}  ${"-".repeat(widths.state)}  ${"-".repeat(widths.elapsed)}  -----`;
    const rows = jobs.map((j) => {
      const elapsed = `${(((j.endedAt ?? Date.now()) - j.startedAt) / 1000).toFixed(1)}s`;
      return `  ${pad(j.id, widths.id)}  ${pad(j.state, widths.state)}  ${pad(elapsed, widths.elapsed)}  ${j.label}`;
    });
    return { output: [header, sep, ...rows].join("\n") };
  }

  // Dev REPL

  private async cmd_repl(_ctx: CommandContext): Promise<CommandResult> {
    if (!this.opts.openRepl) {
      return { output: "[-] REPL is not enabled in this driver." };
    }
    try {
      await this.opts.openRepl();
      return { output: "[*] REPL session ended." };
    } catch (err) {
      return { output: `[-] REPL failed: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  // Spool — tee shell output to a file

  private cmd_spool(args: string[], ctx: CommandContext): CommandResult {
    const spool = this.opts.spool;
    if (!spool) return { output: "[-] Spool is not enabled in this driver." };
    const sub = args[0];
    if (!sub || sub === "status") {
      const active = spool.path();
      return {
        output: active ? `[*] Spooling to ${active}` : "[*] Spool is off.",
      };
    }
    if (sub === "off" || sub === "-c") {
      const closed = spool.stop();
      return {
        output: closed ? `[+] Stopped spool (was ${closed}).` : "[-] Spool was not active.",
      };
    }
    try {
      const resolved = spool.start(sub, ctx.cwd);
      return { output: `[+] Spooling to ${resolved}` };
    } catch (err) {
      return { output: `[-] spool failed: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  // Utility primitives — sleep / wait_for / time / clear / version / logs / connect

  private async cmd_sleep(args: string[], ctx: CommandContext): Promise<CommandResult> {
    const secs = Number.parseFloat(args[0] ?? "");
    if (!Number.isFinite(secs) || secs < 0) return { output: "Usage: sleep <seconds>" };
    await new Promise<void>((resolve) => {
      const t = setTimeout(resolve, secs * 1000);
      ctx.signal?.addEventListener("abort", () => {
        clearTimeout(t);
        resolve();
      });
    });
    return { output: `[*] Slept ${secs}s` };
  }

  private async cmd_wait_for(args: string[], ctx: CommandContext): Promise<CommandResult> {
    const event = args[0];
    if (!event) return { output: "Usage: wait_for <event-type> [timeout-seconds]" };
    const timeout = Number.parseFloat(args[1] ?? "30");
    const mgr = this.opts.events;
    if (!mgr) return { output: "[-] ModuleEventBus is not exposed to this driver." };
    const started = Date.now();
    const payload = await new Promise<unknown | null>((resolve) => {
      const scope = mgr.scope(`wait_for:${started}`);
      let settled = false;
      const finish = (value: unknown | null) => {
        if (settled) return;
        settled = true;
        scope.disposeAll();
        clearTimeout(timer);
        resolve(value);
      };
      const timer = setTimeout(() => finish(null), timeout * 1000);
      scope.once(event, (p) => finish(p ?? true));
      ctx.signal?.addEventListener("abort", () => finish(null));
    });
    const elapsed = ((Date.now() - started) / 1000).toFixed(2);
    if (payload === null) return { output: `[-] wait_for ${event} timed out after ${elapsed}s` };
    return {
      output: `[+] ${event} fired after ${elapsed}s\n${JSON.stringify(payload, null, 2)}`,
    };
  }

  private async cmd_time(args: string[], ctx: CommandContext): Promise<CommandResult> {
    if (args.length === 0) return { output: "Usage: time <command...>" };
    const line = args.join(" ");
    const started = process.hrtime.bigint();
    const inner = await ctx.driver.handle(line, ctx.signal);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1_000_000;
    const existingOutput = inner.output ?? "";
    const footer = `\n[*] ${line} — ${elapsedMs.toFixed(1)}ms`;
    return {
      ...inner,
      output: existingOutput ? `${existingOutput}${footer}` : footer.trimStart(),
    };
  }

  private cmd_clear(): CommandResult {
    if (process.stdout.isTTY) process.stdout.write("\x1b[2J\x1b[H");
    return {};
  }

  private cmd_version(): CommandResult {
    const version = this.opts.frameworkVersion ?? "dev";
    const modules = this.opts.registry.list();
    const counts = {
      modules: modules.length,
      tools: modules.reduce((n, m) => n + m.toolCount, 0),
    };
    const lines = [
      `Kuzushi ${version}`,
      `  Node: ${process.versions.node}`,
      `  Modules loaded: ${counts.modules}`,
      `  Tools: ${counts.tools}`,
    ];
    return { output: lines.join("\n") };
  }

  private async cmd_logs(args: string[]): Promise<CommandResult> {
    const getLogPath = this.opts.getLogPath;
    if (!getLogPath) return { output: "[-] Audit log not enabled in this driver." };
    const logPath = getLogPath();
    if (!logPath) return { output: "[-] Audit log path unavailable." };
    const { existsSync, readFileSync } = await import("node:fs");
    if (!existsSync(logPath)) return { output: `[*] No audit log yet at ${logPath}` };
    const raw = readFileSync(logPath, "utf8");
    const lines = raw.split("\n").filter(Boolean);
    const limitArg = args.find((a) => /^\d+$/.test(a));
    const limit = limitArg ? Number.parseInt(limitArg, 10) : 50;
    const tail = lines.slice(-limit);
    return {
      output: tail.length === 0 ? "  (empty log)" : tail.join("\n"),
    };
  }

  // Macros — record / replay a sequence of commands

  private readonly macros = new Map<string, string[]>();
  private recordingTarget: string | null = null;
  private recordingBuffer: string[] = [];
  private recordingUnsub: (() => void) | null = null;

  private async cmd_macro(args: string[], ctx: CommandContext): Promise<CommandResult> {
    const sub = args[0];
    const driver = ctx.driver as unknown as {
      onCommand?: (o: (line: string) => void) => () => void;
      handle: (line: string, signal?: AbortSignal) => Promise<CommandResult>;
    };
    switch (sub) {
      case "record": {
        const name = args[1];
        if (!name) return { output: "Usage: macro record <name>" };
        if (this.recordingTarget) {
          return { output: `[-] Already recording '${this.recordingTarget}' — stop first.` };
        }
        if (typeof driver.onCommand !== "function") {
          return { output: "[-] Driver does not expose onCommand() — macros disabled." };
        }
        this.recordingTarget = name;
        this.recordingBuffer = [];
        this.recordingUnsub = driver.onCommand((line) => {
          // Skip lines that are themselves `macro …` commands so a recorder
          // doesn't loop on the `macro stop` that ends it.
          if (line.startsWith("macro ")) return;
          this.recordingBuffer.push(line);
        });
        return { output: `[*] Recording macro '${name}'. Type 'macro stop' to save.` };
      }
      case "stop": {
        if (!this.recordingTarget) return { output: "[-] No active recording." };
        const name = this.recordingTarget;
        this.macros.set(name, [...this.recordingBuffer]);
        this.recordingUnsub?.();
        this.recordingUnsub = null;
        this.recordingTarget = null;
        this.recordingBuffer = [];
        return { output: `[+] Saved macro '${name}' (${this.macros.get(name)!.length} lines)` };
      }
      case "list": {
        if (this.macros.size === 0) return { output: "  (no macros)" };
        const rows = [...this.macros.entries()].map(
          ([name, lines]) => `  ${name.padEnd(20)} ${lines.length} lines`,
        );
        return { output: ["Macros:", ...rows].join("\n") };
      }
      case "delete": {
        const name = args[1];
        if (!name) return { output: "Usage: macro delete <name>" };
        return {
          output: this.macros.delete(name)
            ? `[+] Deleted macro '${name}'`
            : `[-] No macro '${name}'`,
        };
      }
      case "play": {
        const name = args[1];
        if (!name) return { output: "Usage: macro play <name>" };
        const lines = this.macros.get(name);
        if (!lines) return { output: `[-] No macro '${name}'` };
        const outLines: string[] = [`[*] Playing macro '${name}' (${lines.length} lines)`];
        for (const line of lines) {
          const r = await driver.handle(line, ctx.signal);
          if (r.output) outLines.push(r.output);
        }
        return { output: outLines.join("\n") };
      }
      case "show": {
        const name = args[1];
        if (!name) return { output: "Usage: macro show <name>" };
        const lines = this.macros.get(name);
        if (!lines) return { output: `[-] No macro '${name}'` };
        return { output: lines.map((l, i) => `  ${i + 1}  ${l}`).join("\n") };
      }
      default:
        return {
          output:
            "Usage: macro record <name> | stop | list | show <name> | play <name> | delete <name>",
        };
    }
  }

  private cmd_schedule(args: string[]): CommandResult {
    const sched = this.opts.scheduler?.();
    if (!sched) return { output: "[-] Scheduler is not enabled in this driver." };
    const sub = args[0];
    if (!sub || sub === "list") {
      const rows = sched.list();
      if (rows.length === 0) return { output: "  (no schedules)" };
      const pad = (s: string, w: number) => s + " ".repeat(Math.max(0, w - s.length));
      const lines = rows.map((r) => {
        const eta = Math.max(0, (r.nextFireAt - Date.now()) / 1000).toFixed(0);
        return `  ${pad(r.label, 20)}  every ${pad(r.interval, 6)}  next in ${pad(`${eta}s`, 8)}  ${r.command}`;
      });
      return { output: ["Schedules:", ...lines].join("\n") };
    }
    if (sub === "remove" && args[1]) {
      const ok = sched.remove(args[1] as string);
      return { output: ok ? `[+] Removed schedule '${args[1]}'` : `[-] No schedule '${args[1]}'` };
    }
    if (sub === "every" && args[1] && args[2]) {
      const interval = args[1] as string;
      const rest = args.slice(2).join(" ");
      // Allow an explicit --label; otherwise synthesize one from the command.
      let label = rest.startsWith("--label ") ? (rest.split(/\s+/)[1] ?? "") : "";
      const cmd = label ? rest.replace(/^--label \S+\s*/, "") : rest;
      if (!label) label = `${interval}:${cmd.split(/\s+/)[0] ?? "job"}`;
      try {
        const entry = sched.add(label, interval, cmd);
        return {
          output: `[+] Scheduled '${entry.label}' every ${entry.interval} → ${entry.command}`,
        };
      } catch (err) {
        return { output: `[-] ${err instanceof Error ? err.message : String(err)}` };
      }
    }
    return {
      output:
        "Usage: schedule every <Ns|Nm|Nh|Nd> <cmd...> | schedule list | schedule remove <label>",
    };
  }

  private async cmd_connect(args: string[], ctx: CommandContext): Promise<CommandResult> {
    const host = args[0];
    const port = Number.parseInt(args[1] ?? "", 10);
    if (!host || !Number.isFinite(port)) {
      return { output: "Usage: connect <host> <port>" };
    }
    const { createConnection } = await import("node:net");
    ctx.print.status(`Connecting to ${host}:${port}...`);
    const chunks: string[] = [];
    await new Promise<void>((resolve) => {
      const sock = createConnection({ host, port });
      let settled = false;
      const finish = () => {
        if (settled) return;
        settled = true;
        sock.destroy();
        resolve();
      };
      sock.on("connect", () => {
        ctx.print.good(`Connected to ${host}:${port}`);
      });
      sock.on("data", (buf) => chunks.push(buf.toString("utf8")));
      sock.on("error", (err) => {
        chunks.push(`[-] ${err.message}`);
        finish();
      });
      sock.on("end", finish);
      sock.on("close", finish);
      ctx.signal?.addEventListener("abort", finish);
      // Close after 5s of inactivity — interactive back-and-forth would need
      // a different lifecycle; this is enough for banner-grab / smoke tests.
      setTimeout(finish, 5000);
    });
    return { output: chunks.join("") || "[-] No bytes received." };
  }

  // helpers

  /** Find the active module dispatcher's datastore, if a `use` was issued. */
  private findModuleStore(ctx: CommandContext): Datastore | undefined {
    const stack = ctx.driver.stack();
    for (let i = stack.length - 1; i >= 0; i--) {
      const d = stack[i];
      if (d instanceof ModuleDispatcher) return d.datastore;
    }
    return undefined;
  }

  /** Top-most ModuleDispatcher in the stack, or undefined. */
  private activeModuleDispatcher(ctx: CommandContext): ModuleDispatcher | undefined {
    const stack = ctx.driver.stack();
    for (let i = stack.length - 1; i >= 0; i--) {
      const d = stack[i];
      if (d instanceof ModuleDispatcher) return d;
    }
    return undefined;
  }
}

// info / module rendering

export function formatModuleInfo(mod: CopilotModule): string {
  const lines: string[] = [];
  lines.push(`       Name: ${mod.displayName}`);
  lines.push(`     Module: ${mod.id}`);
  lines.push(`   Category: ${mod.category}`);
  lines.push(`    Version: ${mod.version}`);
  lines.push(`       Rank: ${mod.rank ?? "normal"}`);
  if (mod.disclosureDate) lines.push(`  Disclosed: ${mod.disclosureDate}`);
  if (mod.authors && mod.authors.length > 0) lines.push(`    Authors: ${mod.authors.join(", ")}`);
  lines.push("");
  lines.push("Description:");
  for (const part of mod.description.split("\n")) lines.push(`  ${part}`);
  if (mod.references && mod.references.length > 0) {
    lines.push("");
    lines.push("References:");
    for (const ref of mod.references) lines.push(`  ${ref.type}: ${ref.value}`);
  }
  if (mod.notes) {
    lines.push("");
    lines.push("Notes:");
    if (mod.notes.stability) lines.push(`  Stability:    ${mod.notes.stability.join(", ")}`);
    if (mod.notes.reliability) lines.push(`  Reliability:  ${mod.notes.reliability.join(", ")}`);
    if (mod.notes.sideEffects) lines.push(`  Side effects: ${mod.notes.sideEffects.join(", ")}`);
  }
  if (mod.tools.length > 0) {
    lines.push("");
    lines.push("Tools:");
    for (const t of mod.tools) lines.push(`  ${t.name.padEnd(28)}  ${t.description}`);
  }
  return lines.join("\n");
}

export function formatToolInfo(mod: CopilotModule, tool: CopilotModule["tools"][number]): string {
  const lines: string[] = [];
  lines.push(`       Name: ${tool.name}`);
  lines.push(`     Module: ${mod.id}`);
  lines.push(`       Rank: ${tool.rank ?? mod.rank ?? "normal"}`);
  lines.push(`   Headless: ${tool.headless ? "yes" : "no"}`);
  lines.push("");
  lines.push("Description:");
  for (const part of tool.description.split("\n")) lines.push(`  ${part}`);
  const refs = [...(tool.references ?? []), ...(mod.references ?? [])];
  if (refs.length > 0) {
    lines.push("");
    lines.push("References:");
    for (const ref of refs) lines.push(`  ${ref.type}: ${ref.value}`);
  }
  return lines.join("\n");
}

/**
 * Rank candidate strings by fuzzy closeness to `query` and return up to
 * `limit` of the best matches. Scoring prefers exact prefix > substring >
 * small Levenshtein distance; candidates that share no characters are
 * dropped so the suggestion list stays useful (typing "zzz" shouldn't
 * suggest every loaded module).
 */
export function suggestMatches(
  query: string,
  candidates: ReadonlyArray<string>,
  limit = 3,
): string[] {
  const q = query.toLowerCase();
  if (q.length === 0) return [];
  const scored = candidates
    .map((c) => {
      const lc = c.toLowerCase();
      if (lc === q) return { c, score: 0 };
      if (lc.startsWith(q)) return { c, score: 1 };
      if (lc.includes(q)) return { c, score: 2 };
      const d = levenshtein(q, lc);
      // Require the distance to be small relative to the query length so
      // near-typos like "modles" → "modules" (dist 1 on q.len 6) are
      // suggested, but unrelated strings are dropped.
      if (d <= Math.max(1, Math.floor(q.length / 3))) return { c, score: 3 + d };
      return undefined;
    })
    .filter((x): x is { c: string; score: number } => x !== undefined)
    .sort((a, b) => a.score - b.score || a.c.length - b.c.length);
  return scored.slice(0, limit).map((x) => x.c);
}

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const prev = new Array<number>(b.length + 1);
  const curr = new Array<number>(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min((curr[j - 1] ?? 0) + 1, (prev[j] ?? 0) + 1, (prev[j - 1] ?? 0) + cost);
    }
    for (let j = 0; j <= b.length; j++) prev[j] = curr[j] ?? 0;
  }
  return prev[b.length] ?? 0;
}

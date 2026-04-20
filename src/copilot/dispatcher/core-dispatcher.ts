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

import type { ModuleRegistry } from "../../modules/registry.js";
import type { CopilotModule } from "../../modules/types.js";
import { type Datastore, formatOptionsTable } from "../options.js";
import { formatSearchResult, searchCatalog } from "../search.js";
import { randomTip } from "../tips.js";
import { ModuleDispatcher, type ModuleToolRunner } from "./module-dispatcher.js";
import type { CommandContext, CommandDispatcher, CommandResult } from "./types.js";

export interface CoreDispatcherOptions {
  registry: ModuleRegistry;
  /** Global datastore — stores `setg`-set keys. */
  globals: Datastore;
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
  exit: "Exit the shell",
  quit: "Exit the shell (alias for exit)",
};

export class CoreDispatcher implements CommandDispatcher {
  readonly name = "core";
  readonly commands = COMMANDS;

  constructor(private readonly opts: CoreDispatcherOptions) {}

  async execute(cmd: string, args: string[], ctx: CommandContext): Promise<CommandResult | void> {
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

  // -------------------------------------------------------------------------
  // Handlers
  // -------------------------------------------------------------------------

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
    };
    const header = `  ${pad("Id", widths.id)}  ${pad("Category", widths.cat)}  ${pad("Version", widths.ver)}  Tools  Description`;
    const sep = `  ${"-".repeat(widths.id)}  ${"-".repeat(widths.cat)}  ${"-".repeat(widths.ver)}  -----  -----------`;
    const body = list
      .map(
        (m) =>
          `  ${pad(m.id, widths.id)}  ${pad(m.category, widths.cat)}  ${pad(m.version, widths.ver)}  ${String(m.toolCount).padStart(5)}  ${m.description}`,
      )
      .join("\n");
    return { output: [header, sep, body].join("\n") };
  }

  private cmd_use(args: string[], _ctx: CommandContext): CommandResult {
    const id = args[0];
    if (!id) return { output: "Usage: use <module-id>" };
    if (!this.opts.registry.has(id)) {
      return { output: `Unknown module: ${id}. Try: modules` };
    }
    const mod = this.opts.registry.get(id);
    const dispatcher = new ModuleDispatcher({
      module: mod,
      globals: this.opts.globals,
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
      default:
        return { output: `Unknown show target: ${what}` };
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

  // -------------------------------------------------------------------------
  // Discovery & learning-curve commands
  // -------------------------------------------------------------------------

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
    const lines: string[] = [`Why ${mod.id}'s preflight cares:`];
    for (const req of reqs) {
      if (req.kind === "snapshot") {
        const present = !!snapshot && snapshot[req.field] != null;
        lines.push(
          `  ${present ? "✓" : "✗"} snapshot.${req.field}   (produced by: ${req.moduleId})`,
        );
        if (!present) {
          lines.push(`      Fix: use ${req.moduleId}; run`);
        }
      } else if (req.kind === "findings") {
        const count = ctx.driver.getFindingCount?.() ?? 0;
        const need = req.minCount ?? 1;
        lines.push(`  ${count >= need ? "✓" : "✗"} findings   (have ${count}, need ${need}+)`);
        if (count < need) lines.push(`      Fix: run a scanner first (e.g. use semgrep; run)`);
      } else if (req.kind === "hosts") {
        const count = ctx.driver.getHostCount?.() ?? 0;
        const need = req.minCount ?? 1;
        lines.push(`  ${count >= need ? "✓" : "✗"} hosts   (have ${count}, need ${need}+)`);
        if (count < need) lines.push(`      Fix: use recon; run`);
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
    lines.push(`  Or run the full DAG: use sast; run`);
    return { output: lines.join("\n") };
  }

  // -------------------------------------------------------------------------
  // Aliases
  // -------------------------------------------------------------------------

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

  // -------------------------------------------------------------------------
  // Favorites (numeric-recall aliases)
  // -------------------------------------------------------------------------

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

  // -------------------------------------------------------------------------
  // Module stack (pushm / popm / listm)
  // -------------------------------------------------------------------------

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

  // -------------------------------------------------------------------------
  // Background jobs
  // -------------------------------------------------------------------------

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
      const elapsed = (((j.endedAt ?? Date.now()) - j.startedAt) / 1000).toFixed(1) + "s";
      return `  ${pad(j.id, widths.id)}  ${pad(j.state, widths.state)}  ${pad(elapsed, widths.elapsed)}  ${j.label}`;
    });
    return { output: [header, sep, ...rows].join("\n") };
  }

  // -------------------------------------------------------------------------
  // Dev REPL
  // -------------------------------------------------------------------------

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

  // -------------------------------------------------------------------------
  // helpers
  // -------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// info / module rendering
// ---------------------------------------------------------------------------

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

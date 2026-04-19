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
import { ModuleDispatcher } from "./module-dispatcher.js";
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
      default:
        return { output: `Unknown command: ${cmd}` };
    }
  }

  complete(cmd: string, partial: string, _words: string[]): string[] {
    if (cmd === "use" || cmd === "info") {
      const ids = this.opts.registry.ids();
      return ids.filter((id) => id.startsWith(partial));
    }
    if (cmd === "show") {
      return ["options", "advanced", "evasion", "missing", "modules", "globals"].filter((s) =>
        s.startsWith(partial),
      );
    }
    if (cmd === "set" || cmd === "unset") {
      // Suggest known module-option names from the top-of-stack module dispatcher.
      const top = this.opts.registry.list();
      void top;
      return [];
    }
    return [];
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

  /** Find the active module dispatcher's datastore, if a `use` was issued. */
  private findModuleStore(ctx: CommandContext): Datastore | undefined {
    const stack = ctx.driver.stack();
    for (let i = stack.length - 1; i >= 0; i--) {
      const d = stack[i];
      if (d instanceof ModuleDispatcher) return d.datastore;
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

import { formatUnknownVerb } from "../ui/error-format.js";

export function buildShellPrompt(focusedModule: string | null): string {
  return focusedModule ? `kuzushi/${focusedModule}> ` : "kuzushi> ";
}

/**
 * Groups come from AGENTS.md so `/help` structure stays anchored to the
 * canonical operator-facing docs. Order matters because `formatHelp()` renders
 * sections in this sequence.
 */
export type ShellCommandGroup =
  | "nav"
  | "planner"
  | "prompt"
  | "replay"
  | "aliases"
  | "config"
  | "scope"
  | "threats"
  | "session";

export type CommandSurfaceKind = "core" | "advanced" | "dev" | "deprecated";

export interface CommandMetadata {
  readonly surface: CommandSurfaceKind;
  readonly canonical?: string;
  readonly deprecatedSince?: string;
}

export interface ShellActionHint {
  readonly command: string;
  readonly label: string;
  readonly surface: CommandSurfaceKind;
}

export interface ShellCommandEntry {
  readonly syntax: string;
  readonly description: string;
  readonly group?: ShellCommandGroup;
  readonly longDescription?: string;
  readonly metadata?: CommandMetadata;
}

export const SHELL_COMMAND_CATALOG: readonly ShellCommandEntry[] = [
  {
    syntax: "/help",
    description: "Show core workflow help; `/help advanced` shows all commands",
    group: "nav",
  },
  { syntax: "/modules", description: "List loaded modules (alias: /m)", group: "nav" },
  { syntax: "/tools", description: "List available tools", group: "nav" },
  { syntax: "/use <module>", description: "Focus on a module", group: "nav" },
  {
    syntax: "/scan [target]",
    description: "Run the default SAST scan shortcut",
    group: "nav",
  },
  {
    syntax: "/back",
    description: "Step back one level (alias: /b) — finding → findings → module → catalog",
    group: "nav",
  },
  {
    syntax: "/findings",
    description: "Show the current findings list (alias: /f)",
    group: "nav",
  },
  { syntax: "/open <F-NNNN>", description: "Open a finding in the linear deep page", group: "nav" },
  {
    syntax: "/tune",
    description: "Open the tune view for the focused module (alias: /t)",
    group: "nav",
  },
  {
    syntax: "/story",
    description: "Open active task story details",
    group: "nav",
  },
  {
    syntax: "/since <git-ref>",
    description: "Scope the findings list to files changed since <ref>",
    group: "nav",
    longDescription:
      "Computes the changed-file set between HEAD and <ref> via git and keeps the user on the findings surface.",
  },
  {
    syntax: "/plan <english>",
    description: "Propose option changes from a plain-English request",
    group: "planner",
    longDescription:
      "Translates the request into a proposed option diff the operator can apply with /yes or discard with /no.",
  },
  {
    syntax: "/yes | /no",
    description: "Apply or discard the pending planner proposal",
    group: "planner",
  },
  {
    syntax: "/prompts",
    description: "Open the prompts editor for the focused module",
    group: "prompt",
  },
  {
    syntax: "/prompt edit <verb>",
    description: "Open the operator system-prompt override in $EDITOR",
    group: "prompt",
  },
  {
    syntax: "/prompt show <verb>",
    description: "Show the effective prompt + source for a tool",
    group: "prompt",
  },
  {
    syntax: "/show prompts",
    description: "Cross-module audit of every *_PROMPT override",
    group: "prompt",
  },
  {
    syntax: "/show runs [repo]",
    description: "List recent pipeline runs (id · status · cost)",
    group: "replay",
  },
  {
    syntax: "/replay <runId>",
    description: "Re-render the summary of a past run from stored state",
    group: "replay",
  },
  {
    syntax: "/trace <runId>",
    description: "Stream the per-event JSONL audit log of a past run",
    group: "replay",
  },
  {
    syntax: "/show aliases [pfx]",
    description: "List short-ID aliases (F-0001, C-01) for the current run",
    group: "aliases",
  },
  { syntax: "/options [tool]", description: "Show tool options", group: "config" },
  { syntax: "/set <key> <value>", description: "Set a tool option", group: "config" },
  { syntax: "/config", description: "Open the interactive config editor", group: "config" },
  {
    syntax: "/config advanced",
    description: "Open advanced/research configuration",
    group: "config",
  },
  {
    syntax: "/config raw|get|set|path",
    description: "Inspect/update ~/.kuzushi/config.json",
    group: "config",
  },
  {
    syntax: "/auth",
    description: "Set or change credentials for any supported provider",
    group: "config",
  },
  {
    syntax: "/provider",
    description: "Show or set the default <provider>:<model> (e.g. openai:gpt-5-mini)",
    group: "config",
  },
  {
    syntax: "/backend [claude|pi-ai]",
    description: "Show or change the agent runtime backend (advanced)",
    group: "config",
  },
  {
    syntax: "/ask <question>",
    description: "Ask the agent with current shell context",
    group: "config",
  },
  { syntax: "/target <path>", description: "Set or show the active target", group: "scope" },
  { syntax: "/context", description: "Generate or show application context map", group: "scope" },
  {
    syntax: "/context build",
    description: "Build scan context (5 phases, writes .kuzushi/scan-context.json)",
    group: "scope",
  },
  { syntax: "/context edit", description: "Review/edit scan context", group: "scope" },
  {
    syntax: "/context dfd",
    description: "Open the context-backed data flow diagram",
    group: "scope",
  },
  {
    syntax: "/context regen <slice>",
    description: "Regenerate a generated context slice (dfd, stride, stories, scenarios, etc.)",
    group: "scope",
  },
  {
    syntax: "/workspace <id>",
    description: "Set or show the active workspace",
    group: "scope",
  },
  { syntax: "/threats", description: "Show threat model summary", group: "threats" },
  {
    syntax: "/threats dfd | 1",
    description: "Data flow diagram grouped by trust zone",
    group: "threats",
  },
  {
    syntax: "/threats stride | 2",
    description: "Element × STRIDE heat matrix + impact × likelihood",
    group: "threats",
  },
  {
    syntax: "/threats stories | 3",
    description: "Attacker narrative cards + input-categories rail",
    group: "threats",
  },
  {
    syntax: "/threats scope | 4",
    description: "Criticality buckets + out-of-scope + operator edits",
    group: "threats",
  },
  {
    syntax: "/threats summary | 5",
    description: "Counts bar charts + drives + artifact paths",
    group: "threats",
  },
  {
    syntax: "/threats edit",
    description: "Review/edit threat model interactively; creates a draft when none exists",
    group: "threats",
  },
  {
    syntax: "/threats ask <instruction>",
    description: "Ask AI to propose a reviewable threat-model patch",
    group: "threats",
  },
  {
    syntax: "/load <specifier>",
    description: "Load an external module at runtime",
    group: "session",
  },
  { syntax: "/clear", description: "Clear conversation history", group: "session" },
  { syntax: "/history", description: "Show command history", group: "session" },
  { syntax: "/exit", description: "Exit the shell", group: "session" },
];

const ADVANCED_COMMANDS = new Set([
  "/plan",
  "/yes",
  "/prompt",
  "/show prompts",
  "/show runs",
  "/show aliases",
  "/replay",
  "/trace",
  "/options",
  "/set",
  "/config advanced",
  "/config raw|get|set|path",
  "/backend",
  "/ask",
  "/context build",
  "/context edit",
  "/context regen",
  "/threats edit",
  "/threats ask",
]);

const DEV_COMMANDS = new Set(["/load"]);

export function commandSurface(entry: ShellCommandEntry): CommandSurfaceKind {
  if (entry.metadata?.surface) return entry.metadata.surface;
  if (DEV_COMMANDS.has(entry.syntax.split(/\s+/)[0] ?? entry.syntax)) return "dev";
  if (ADVANCED_COMMANDS.has(entry.syntax)) return "advanced";
  const head = entry.syntax.split(/\s+/)[0] ?? entry.syntax;
  if (ADVANCED_COMMANDS.has(head)) return "advanced";
  return "core";
}

export function isCommandVisibleInDefaultHelp(entry: ShellCommandEntry): boolean {
  return commandSurface(entry) === "core";
}

export function getCommandMetadata(input: string): CommandMetadata {
  const normalized = input.trim().startsWith("/") ? input.trim() : `/${input.trim()}`;
  const entries = [...SHELL_COMMAND_CATALOG].sort((a, b) => b.syntax.length - a.syntax.length);
  const entry = entries.find((candidate) => {
    const head = candidate.syntax.split(/\s+/)[0] ?? candidate.syntax;
    return normalized.toLowerCase().startsWith(head.toLowerCase());
  });
  return { surface: entry ? commandSurface(entry) : "advanced" };
}

export const SHELL_COMMAND_GROUP_TITLES: Record<ShellCommandGroup, string> = {
  nav: "Module + view navigation",
  planner: "Natural-language planner",
  prompt: "Prompt editor",
  replay: "Replay & trace",
  aliases: "Short-ID aliases",
  config: "Config & tool options",
  scope: "Target · context · workspace",
  threats: "Threat modelling",
  session: "Session",
};

export function collectKnownVerbs(): string[] {
  const verbs = new Set<string>();
  for (const entry of SHELL_COMMAND_CATALOG) {
    const raw = entry.syntax.replace(/^\//, "");
    const head = raw.split(/\s+/)[0] ?? "";
    if (entry.syntax.includes("|")) {
      for (const alt of entry.syntax.split("|").map((s) => s.trim().replace(/^\//, ""))) {
        const altHead = alt.split(/\s+/)[0];
        if (altHead) verbs.add(altHead);
      }
    } else if (head) {
      verbs.add(head);
    }
  }
  for (const alias of ["f", "t", "m", "b", "apply-plan", "discard-plan", "runs"]) {
    verbs.add(alias);
  }
  return Array.from(verbs);
}

export function formatHelpForVerb(input: string): string {
  const needle = input.replace(/^\//, "").trim().toLowerCase();
  if (!needle) return "Usage: /help [verb]";
  const entries = SHELL_COMMAND_CATALOG.filter((entry) => {
    const head = entry.syntax.replace(/^\//, "").split(/\s+/)[0]?.toLowerCase();
    if (head === needle) return true;
    if (entry.syntax.includes("|")) {
      return entry.syntax
        .split("|")
        .some((s) => s.trim().replace(/^\//, "").toLowerCase() === needle);
    }
    return false;
  });
  if (entries.length === 0) {
    return formatUnknownVerb(needle, collectKnownVerbs());
  }
  const lines: string[] = [];
  for (const entry of entries) {
    lines.push(`  ${entry.syntax}`);
    lines.push(`    ${entry.description}`);
    if (entry.longDescription) {
      lines.push(`    ${entry.longDescription}`);
    }
  }
  return lines.join("\n");
}

export function listShellSuggestions(input: string, limit = 4): string[] {
  const trimmed = input.trim();
  if (!trimmed.startsWith("/")) return [];
  const prefix = trimmed.toLowerCase();
  const matches: string[] = [];
  for (const { syntax } of SHELL_COMMAND_CATALOG) {
    if (syntax.toLowerCase().startsWith(prefix)) {
      matches.push(syntax);
      if (matches.length >= limit) break;
    }
  }
  return matches;
}

export function firstShellSuggestion(input: string): string | null {
  return listShellSuggestions(input, 1)[0] ?? null;
}

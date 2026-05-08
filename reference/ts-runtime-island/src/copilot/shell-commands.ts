import { formatUnknownVerb } from "../ui/error-format.js";

export function buildShellPrompt(focusedModule: string | null): string {
  return focusedModule ? `kuzushi ${focusedModule} > ` : "kuzushi > ";
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
  | "kb"
  | "session";

export type CommandSurfaceKind = "core" | "advanced" | "dev";

export interface CommandMetadata {
  readonly surface: CommandSurfaceKind;
  readonly canonical?: string;
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
    description: "Show core workflow help (alias: /h); `/help advanced` shows all commands",
    group: "nav",
  },
  {
    syntax: "/quickstart",
    description: "Three-step guided tour for first-time operators (e.g. /quickstart)",
    group: "nav",
    longDescription:
      "Prints the current target, recommends a starter module, and shows the exact verbs to run your first scan. Read-only — does not change config.",
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
    syntax: "/actor <n>",
    description: "Drill into a per-actor transcript from inside ModuleRunView (1–4 keys)",
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
    description: "Scope the findings list to files changed since <ref> (use /since clear to drop)",
    group: "nav",
    longDescription:
      "Computes the changed-file set between HEAD and <ref> via git and keeps the user on the findings surface. Use `/since clear` (or `reset`/`off`) to drop the scope.",
  },
  // Phase 5 cleanup — `/plan`, `/yes`, `/no` are no longer advertised in
  // /help. The same flow is reachable by typing prose at a focused-module
  // prompt (e.g. `kuzushi taint-iris > only look at admin routes`); the
  // resulting plan card is then accepted with bare `y` / dismissed with
  // bare `n`. The slash forms remain wired for muscle memory but stay out
  // of the catalog so analysts don't have to learn two surfaces.
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
    syntax: "/prompt diff <verb>",
    description: "Show the override file path so you can git-diff vs builtin",
    group: "prompt",
  },
  {
    syntax: "/prompt reset <verb>",
    description: "Delete the override file and revert to the compiled default",
    group: "prompt",
  },
  {
    syntax: "/show prompts",
    description: "Cross-module audit of every *_PROMPT override",
    group: "prompt",
  },
  {
    syntax: "/show runs [repo] [--status s] [--limit n]",
    description: "List recent pipeline runs (id · status · started · duration · cost · findings)",
    group: "replay",
  },
  {
    syntax: "/replay <runId>",
    description: "Re-render the summary of a past run from stored state",
    group: "replay",
  },
  {
    syntax: "/resume [runId]",
    description: "Continue an unfinished checkpoint for the focused module",
    group: "replay",
  },
  {
    syntax: "/pause",
    description: "Pause queued live work for tools with pause/resume control",
    group: "replay",
  },
  {
    syntax: "/trace <runId> [--json] [--all]",
    description: "Stream the per-event JSONL audit log of a past run (jq-friendly with --json)",
    group: "replay",
  },
  {
    syntax: "/show aliases [pfx]",
    description: "List short-ID aliases (F-0001, C-01) for the current run",
    group: "aliases",
  },
  { syntax: "/options [tool]", description: "Open the tool options screen", group: "config" },
  { syntax: "/set <key> <value>", description: "Set a tool option", group: "config" },
  { syntax: "/tasks", description: "Open SAST task selection", group: "config" },
  { syntax: "/task block <id>", description: "Block a SAST task capability", group: "config" },
  {
    syntax: "/task allow <id>",
    description: "Allow a blocked SAST task capability",
    group: "config",
  },
  {
    syntax: "/task toggle [id]",
    description: "Toggle the selected or named SAST task capability",
    group: "config",
  },
  {
    syntax: "/task mode auto|manual|toggle",
    description: "Switch SAST task selection mode",
    group: "config",
  },
  { syntax: "/task reset", description: "Reset SAST task selection overrides", group: "config" },
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
    syntax: "/model",
    description: "Override the model for the current session (alias for /provider)",
    longDescription:
      "Five places set the model, in precedence order: " +
      "(1) per-tool option `set model anthropic:claude-opus-4-7` while in a focused module, " +
      "(2) taskConfig[<id>].model in ~/.kuzushi/config.json or .kuzushi/config.json, " +
      "(3) `/model` or `/provider` for this session only, " +
      "(4) `setg MODEL ...` for this session globally, " +
      "(5) `--model` CLI flag at launch. Show resolved with /config raw or /backend show.",
    group: "config",
  },
  {
    syntax: "/backend [claude|pi-ai|codex]",
    description: "Show or change the agent runtime backend (advanced)",
    group: "config",
  },
  {
    syntax: "/cost",
    description: "Session-to-date cost: live run + cumulative across all runs in ~/.kuzushi/runs",
    group: "config",
  },
  {
    syntax: "/auth import-from-config",
    description:
      "One-shot migration: project config.json agentRuntimeConfig → .kuzushi/credentials.json",
    longDescription:
      "Reads the project config.json's `agentRuntimeConfig` block (which is silently stripped " +
      "by the loader for safety) and writes per-slot credentials to the supported " +
      ".kuzushi/credentials.json location. Updates .gitignore. Use this when you put creds " +
      "in the natural-but-unsupported per-repo config.json and the strip banner fired.",
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
    syntax: "/context regen <slice>",
    description: "Regenerate a context slice (all, repo, enrichment, app-model)",
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
    syntax: "/threats regen <slice>",
    description: "Regenerate threat-model artifacts (all, dfd, stride, stories, scope, scenarios)",
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
    syntax: "/kb",
    description: "Open the focused module's knowledge base (attachments)",
    group: "kb",
    longDescription:
      "Opens the cursor+preview view for the focused module's attachments. Bare `attachments` is an alias.",
  },
  {
    syntax: "attach <path-or-url>",
    description: "Attach a file or URL to the focused module's KB",
    group: "kb",
    longDescription:
      "Routes to `<focusedModule>:attach`. Text/Markdown/JSON/CSV/YAML/XML/HTML are parsed natively; PDFs use a lightweight extractor; images and unsupported types are retained as metadata-only references.",
  },
  {
    syntax: "attachments",
    description: "List attachments for the focused module (alias for /kb)",
    group: "kb",
  },
  {
    syntax: "detach <id>",
    description: "Remove an attachment by id, unique prefix, or unique title",
    group: "kb",
  },
  {
    syntax: "reparse <id>",
    description: "Re-run the parser after the source file changed on disk",
    group: "kb",
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
  "/prompts",
  "/show prompts",
  "/show runs",
  "/show aliases",
  "/replay",
  "/trace",
  "/options",
  "/set",
  "/tasks",
  "/task block",
  "/task allow",
  "/task toggle",
  "/task mode",
  "/task reset",
  "/config advanced",
  "/config raw|get|set|path",
  "/backend",
  "/ask",
  "/context build",
  "/context edit",
  "/context regen",
  "/threats edit",
  "/threats ask",
  "/threats regen",
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
  kb: "Knowledge base",
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
  for (const alias of ["f", "t", "m", "b", "h", "apply-plan", "discard-plan", "runs"]) {
    verbs.add(alias);
  }
  return Array.from(verbs);
}

const SHELL_VERB_ALIASES: Record<string, string> = {
  h: "help",
  f: "findings",
  t: "tune",
  m: "modules",
  b: "back",
  "apply-plan": "yes",
  "discard-plan": "no",
};

export function formatHelpForVerb(input: string): string {
  const raw = input.replace(/^\//, "").trim().toLowerCase();
  if (!raw) return "Usage: /help [verb]";
  const needle = SHELL_VERB_ALIASES[raw] ?? raw;
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

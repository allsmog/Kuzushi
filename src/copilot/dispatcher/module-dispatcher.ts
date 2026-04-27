/**
 * Per-module dispatcher — pushed onto the stack by `use <module>`.
 *
 * Provides:
 *   run [tool]       — invoke a module tool (defaults to first/only headless tool)
 *   check            — call the module's `check` tool if one exists ("module:check")
 *   options          — alias for `show options` (msfconsole convention)
 *   tools            — list module tools
 *
 * The dispatcher owns the module's local Datastore. It seeds the datastore from
 * the tool's JSONSchema (if no explicit option specs are wired) so users still
 * get `set FOO bar` ergonomics even on legacy modules.
 */

import {
  describeModelOverrideFormat,
  validateModelOverride,
} from "../../agent-runtime/model-validation.js";
import type { AgentRuntimeBackend } from "../../contracts.js";
import type { CopilotModule, JSONSchema, ModuleTool, ToolResult } from "../../modules/types.js";
import { looksLikePath } from "../dispatch/resolve-tool.js";
import { Datastore, type OptionSpec } from "../options.js";
import type { CommandContext, CommandDispatcher, CommandResult } from "./types.js";

export type ModuleToolRunner = (
  tool: ModuleTool,
  input: Record<string, unknown>,
  signal?: AbortSignal,
  /** Active module-local datastore — lets tools honor operator-set overrides. */
  datastore?: Datastore,
) => Promise<ToolResult>;

export interface ModuleDispatcherOptions {
  module: CopilotModule;
  /** Shared global datastore (set by `setg`). */
  globals: Datastore;
  /** Active agent runtime backend, used to validate model overrides. */
  agentRuntimeBackend?: AgentRuntimeBackend;
  /** Optional executor — when present, `run` invokes the tool. Otherwise prints the call. */
  runTool?: ModuleToolRunner;
}

export class ModuleDispatcher implements CommandDispatcher {
  readonly name: string;
  readonly commands: Record<string, string>;
  /** Local datastore (specific to this module instance). */
  readonly datastore: Datastore;
  readonly module: CopilotModule;
  private readonly runTool?: ModuleToolRunner;

  constructor(opts: ModuleDispatcherOptions) {
    this.module = opts.module;
    this.runTool = opts.runTool;
    this.name = `module(${opts.module.id})`;
    this.commands = {
      run: "Run the active module's primary tool",
      exploit: "Alias for run",
      check: "Run the module's check action (if defined)",
      options: "Alias for `show options`",
      tools: "List tools exposed by this module",
    };
    this.datastore = createModuleDatastore(opts.module, opts.globals, {
      agentRuntimeBackend: opts.agentRuntimeBackend,
    });
  }

  async execute(cmd: string, args: string[], ctx: CommandContext): Promise<CommandResult | void> {
    switch (cmd) {
      case "run":
      case "exploit":
        return this.cmd_run(args, ctx);
      case "check":
        return this.cmd_check(ctx);
      case "options":
        // Falls through to the core dispatcher's `show options` via re-issuing.
        return ctx.driver.handle("show options", ctx.signal);
      case "tools":
        return this.cmd_tools(args);
      default:
        return undefined;
    }
  }

  complete(cmd: string, partial: string): string[] {
    if (cmd === "run" || cmd === "exploit") {
      return this.module.tools.map((t) => t.name).filter((n) => n.startsWith(partial));
    }
    return [];
  }

  // -------------------------------------------------------------------------
  // Handlers
  // -------------------------------------------------------------------------

  private cmd_tools(args: string[]): CommandResult {
    const includeHidden = args.includes("--all");
    const tools = this.module.tools;
    if (tools.length === 0) return { output: "  (no tools)" };
    const visible = includeHidden ? tools : tools.filter((t) => t.hidden !== true);
    const hiddenCount = tools.length - visible.length;
    if (visible.length === 0 && hiddenCount > 0) {
      return {
        output: `  All ${hiddenCount} tools on this module are DAG-internal. Run \`tools --all\` to list them.`,
      };
    }
    const lines = visible.map((t) => `  ${t.name.padEnd(28)}  ${t.description}`);
    if (hiddenCount > 0) {
      lines.push(
        `  + ${hiddenCount} advanced pipeline step${hiddenCount === 1 ? "" : "s"} hidden (run \`tools --all\` to list)`,
      );
    }
    return { output: lines.join("\n") };
  }

  private async cmd_check(ctx: CommandContext): Promise<CommandResult> {
    const checkName = `${this.module.id}:check`;
    const tool = this.module.tools.find((t) => t.name === checkName);
    if (!tool) return { output: `[-] Module ${this.module.id} has no check action.` };
    return this.invoke(tool, ctx);
  }

  private async cmd_run(args: string[], ctx: CommandContext): Promise<CommandResult> {
    // Pull off flags before tool-name resolution. `--dry` previews the call
    // without invoking the tool (useful for agentic workflows where the
    // operator wants to see what options resolved to before burning tokens).
    const bg = args.includes("--bg") || args.includes("&");
    const dry = args.includes("--dry");
    const posArgs = args.filter((a) => a !== "--bg" && a !== "&" && a !== "--dry");
    const explicit = posArgs[0];

    let tool: ModuleTool | undefined;
    let positionals: string[] = [];
    if (explicit) {
      const matchedTool = this.module.tools.find(
        (t) => t.name === explicit || t.name === `${this.module.id}:${explicit}`,
      );
      if (matchedTool) {
        tool = matchedTool;
        positionals = posArgs.slice(1);
      } else if (looksLikePath(explicit)) {
        // Positional path (e.g. `run .`) — treat as value for the default tool's
        // first required option so users don't have to `set target .; run`.
        tool = pickDefaultTool(this.module);
        positionals = posArgs;
      } else {
        return { output: `[-] Unknown tool: ${explicit}` };
      }
    } else {
      tool = pickDefaultTool(this.module);
    }

    if (!tool) {
      return { output: "[-] No runnable tool." };
    }

    if (positionals.length > 0) {
      const requiredSpecs = this.datastore.allSpecs().filter((s) => s.required);
      for (let i = 0; i < positionals.length && i < requiredSpecs.length; i += 1) {
        this.datastore.set(requiredSpecs[i]!.name, positionals[i]!);
      }
    }

    if (dry) return this.preview(tool, ctx);
    if (bg) return this.invokeInBackground(tool, ctx);
    return this.invoke(tool, ctx);
  }

  /**
   * Dry-run preview. Runs the same preflight as a real invoke (missing-required
   * + module.requires checks) and then prints the resolved Datastore snapshot
   * without calling the tool.
   */
  private preview(tool: ModuleTool, ctx: CommandContext): CommandResult {
    const missing = this.datastore.missingRequired();
    if (missing.length > 0) {
      return { output: `[-] Missing required: ${missing.join(", ")}` };
    }
    const depError = this.checkRequires(ctx);
    if (depError) return { output: depError };
    const snapshot = snapshotToolInput(this.datastore, tool);
    const lines = [
      `[*] DRY RUN — would invoke ${tool.name}`,
      `      module: ${this.module.id}`,
      `      inputs:`,
    ];
    const pretty = JSON.stringify(snapshot, null, 2)
      .split("\n")
      .map((l) => `        ${l}`)
      .join("\n");
    lines.push(pretty);
    return { output: lines.join("\n") };
  }

  /**
   * Fire-and-forget variant of `invoke`. Registers the tool run as a job
   * with the driver's JobManager (if any) and returns immediately with the
   * assigned job id. Preflight (requires, missing-required) still runs so
   * operators get immediate feedback on unmet deps.
   */
  private async invokeInBackground(tool: ModuleTool, ctx: CommandContext): Promise<CommandResult> {
    const missing = this.datastore.missingRequired();
    if (missing.length > 0) {
      return { output: `[-] Missing required: ${missing.join(", ")}` };
    }
    const depError = this.checkRequires(ctx);
    if (depError) return { output: depError };
    if (!this.runTool) {
      return { output: `[*] Would background ${tool.name}` };
    }
    const jobMgr = ctx.driver.jobManager?.();
    if (!jobMgr) {
      return { output: "[-] Background jobs are not enabled. Run foreground instead." };
    }
    const input = snapshotToolInput(this.datastore, tool);
    const id = jobMgr.start({ label: tool.name, kind: "tool" }, async (jobCtx) => {
      jobCtx.log(`[*] Running ${tool.name} in background`);
      const result = await this.runTool!(tool, input, jobCtx.signal, this.datastore);
      jobCtx.log(result.ok ? `[+] ${tool.name} completed` : `[-] ${tool.name} failed`);
      if (result.output) for (const line of result.output.split("\n")) jobCtx.log(line);
      return result.output;
    });
    return { output: `[*] Started job ${id} — ${tool.name} (tail: jobs -i ${id})` };
  }

  private async invoke(tool: ModuleTool, ctx: CommandContext): Promise<CommandResult> {
    const missing = this.datastore.missingRequired();
    if (missing.length > 0) {
      return { output: `[-] Missing required: ${missing.join(", ")}` };
    }
    const depError = this.checkRequires(ctx);
    if (depError) return { output: depError };
    if (!this.runTool) {
      return {
        output: `[*] Would invoke ${tool.name} with: ${JSON.stringify(snapshotToolInput(this.datastore, tool))}`,
      };
    }
    // Progress + completion are now printed by `runToolFromDispatcher` in
    // `shell.ts` as cc-repo-style `⏺ tool(hint)` + `⎿  done/failed in Xs`
    // history entries. Intentionally no `print.status` / `print.good` here
    // to avoid duplicating the header/footer in scrollback.
    const result = await this.runTool(
      tool,
      snapshotToolInput(this.datastore, tool),
      ctx.signal,
      this.datastore,
    );
    return { output: result.output };
  }

  /**
   * Preflight module.requires against the driver's optional ShellState /
   * finding-count hooks. Returns an error message if any dep is unmet, else null.
   */
  private checkRequires(ctx: CommandContext): string | null {
    const reqs = this.module.requires;
    if (!reqs || reqs.length === 0) return null;
    const shell = ctx.driver.getShellState?.();
    const snapshot = (shell?.contextSnapshot ?? undefined) as Record<string, unknown> | undefined;

    const missing: string[] = [];
    for (const req of reqs) {
      if (req.kind === "snapshot") {
        const ok = !!snapshot && snapshot[req.field] != null;
        if (!ok) {
          missing.push(
            `  - ${req.field} from '${req.moduleId}' — fix: 'use ${req.moduleId}' then 'run'`,
          );
        }
      } else if (req.kind === "findings") {
        const count = ctx.driver.getFindingCount?.() ?? 0;
        const need = req.minCount ?? 1;
        if (count < need) {
          missing.push(
            `  - ${need}+ findings in workspace — run a scanner first (e.g. 'use semgrep' then 'run')`,
          );
        }
      } else if (req.kind === "hosts") {
        const count = ctx.driver.getHostCount?.() ?? 0;
        const need = req.minCount ?? 1;
        if (count < need) {
          missing.push(`  - ${need}+ hosts in workspace — add hosts to the active workspace first`);
        }
      } else if (req.kind === "session") {
        const count = ctx.driver.getLiveSessionCount?.(req.sessionKind) ?? 0;
        if (count < 1) {
          const label = req.sessionKind ? `'${req.sessionKind}'` : "any";
          missing.push(
            `  - ${label} live session — open one first (e.g. 'use blackbox' then 'run connect')`,
          );
        }
      } else if (req.kind === "env") {
        if (!process.env[req.name]) {
          missing.push(`  - env var ${req.name} is not set — export it before running`);
        }
      }
    }
    if (missing.length === 0) return null;
    return [
      `[-] ${this.module.id} has unmet prerequisites:`,
      ...missing,
      `    Or run the full DAG: 'use sast' then 'run'`,
    ].join("\n");
  }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function pickDefaultTool(mod: CopilotModule): ModuleTool | undefined {
  // Prefer "<id>:run" or "<id>:scan" or "<id>:exploit", else the first headless tool, else the first tool.
  const preferred = [`${mod.id}:run`, `${mod.id}:scan`, `${mod.id}:exploit`, `${mod.id}:audit`];
  for (const name of preferred) {
    const t = mod.tools.find((x) => x.name === name);
    if (t) return t;
  }
  return mod.tools.find((t) => t.headless) ?? mod.tools[0];
}

/**
 * Build a datastore for a module by reading its tools' JSONSchema.
 * If a tool's input properties have `description` + `default`, those become
 * OptionSpecs so `show options` works without per-module wiring.
 */
export function createModuleDatastore(
  mod: CopilotModule,
  globals: Datastore,
  opts: { agentRuntimeBackend?: AgentRuntimeBackend } = {},
): Datastore {
  const specs: OptionSpec[] = [];
  const seen = new Set<string>();
  for (const tool of mod.tools) {
    const props = readProperties(tool.inputSchema);
    const required = new Set(readRequired(tool.inputSchema));
    for (const [name, schema] of Object.entries(props)) {
      const key = name.toUpperCase();
      if (seen.has(key)) continue;
      seen.add(key);
      specs.push(propertyToSpec(name, schema, required.has(name)));
    }
  }
  installModelOptionSpec(specs, opts.agentRuntimeBackend);
  // Inherit any globally-set values into the resolved view (no copy — they
  // live in `globals`; the new store and `globals` are queried separately
  // via Datastore.get(), but for the per-module view we want a single store).
  // To keep the layered semantics, we use a *delegating* datastore.
  return new DelegatingDatastore(specs, globals);
}

export function modelOptionSpec(name: string, backend?: AgentRuntimeBackend): OptionSpec<string> {
  return {
    name,
    type: "string",
    required: false,
    description: describeModelOverrideFormat(backend),
    validate: (value) => validateModelOverride(backend, value),
  };
}

function installModelOptionSpec(specs: OptionSpec[], backend?: AgentRuntimeBackend): void {
  const existingIndex = specs.findIndex((spec) => spec.name.toUpperCase() === "MODEL");
  if (existingIndex === -1) {
    specs.push(modelOptionSpec("model", backend));
    return;
  }

  const existing = specs[existingIndex]!;
  specs[existingIndex] = {
    ...existing,
    description: existing.description || describeModelOverrideFormat(backend),
    validate: (value: unknown) => {
      const previous = existing.validate?.(value as never);
      if (previous) return previous;
      if (typeof value !== "string") return "model must be a string";
      return validateModelOverride(backend, value);
    },
  };
}

function readProperties(schema: JSONSchema): Record<string, JSONSchema> {
  const props = (schema as { properties?: Record<string, JSONSchema> }).properties;
  return props ?? {};
}

function readRequired(schema: JSONSchema): string[] {
  const req = (schema as { required?: unknown }).required;
  return Array.isArray(req) ? req.filter((x): x is string => typeof x === "string") : [];
}

function propertyToSpec(name: string, schema: JSONSchema, required: boolean): OptionSpec {
  const t = (schema as { type?: string }).type;
  const description = String((schema as { description?: string }).description ?? "");
  const def = (schema as { default?: unknown }).default;
  const choices = (schema as { enum?: unknown[] }).enum;
  // JSONSchema extensions that classify an option's display surface.
  // `show options`    → non-advanced, non-evasion only
  // `show advanced`   → advanced only
  // `show evasion`    → evasion only
  const advanced = (schema as { "x-advanced"?: boolean })["x-advanced"] === true;
  const evasion = (schema as { "x-evasion"?: boolean })["x-evasion"] === true;
  const extra: Partial<OptionSpec> = {};
  if (advanced) extra.advanced = true;
  if (evasion) extra.evasion = true;
  if (Array.isArray(choices) && choices.every((c) => typeof c === "string")) {
    return {
      name,
      type: "enum",
      description,
      required,
      ...(def !== undefined ? { default: def as string } : {}),
      choices: choices as string[],
      ...extra,
    };
  }
  switch (t) {
    case "boolean":
      return {
        name,
        type: "bool",
        description,
        required,
        ...(def !== undefined ? { default: def as boolean } : {}),
        ...extra,
      };
    case "integer":
      return {
        name,
        type: "int",
        description,
        required,
        ...(def !== undefined ? { default: def as number } : {}),
        ...extra,
      };
    case "number":
      return {
        name,
        type: "float",
        description,
        required,
        ...(def !== undefined ? { default: def as number } : {}),
        ...extra,
      };
    default:
      return {
        name,
        type: "string",
        description,
        required,
        ...(def !== undefined ? { default: def as string } : {}),
        ...extra,
      };
  }
}

function snapshotToolInput(store: Datastore, tool: ModuleTool): Record<string, unknown> {
  const snapshot = store.snapshot();
  if (!schemaAcceptsProperty(tool.inputSchema, "model")) {
    delete snapshot["model"];
    delete snapshot["MODEL"];
  }
  return snapshot;
}

function schemaAcceptsProperty(schema: JSONSchema, property: string): boolean {
  const props = readProperties(schema);
  if (Object.hasOwn(props, property)) return true;
  if (Object.hasOwn(props, property.toUpperCase())) return true;
  const additional = (schema as { additionalProperties?: unknown }).additionalProperties;
  return additional !== undefined && additional !== false;
}

/**
 * A Datastore that falls back to a parent (`globals`) when no module-local
 * value or default is present.
 */
class DelegatingDatastore extends Datastore {
  constructor(
    specs: ReadonlyArray<OptionSpec>,
    private readonly parent: Datastore,
  ) {
    super(specs);
  }

  override get<T = unknown>(name: string): T | undefined {
    const local = super.get<T>(name);
    if (local !== undefined) return local;
    return this.parent.get<T>(name);
  }

  override has(name: string): boolean {
    return super.has(name) || this.parent.has(name);
  }

  override whence(name: string): ReturnType<Datastore["whence"]> {
    const local = super.whence(name);
    return local === "unset" ? this.parent.whence(name) : local;
  }
}

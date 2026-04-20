/**
 * ModuleRegistry — manages CopilotModule lifecycle and tool resolution.
 *
 * Extends the same patterns as TaskRegistry (agents/registry.ts) but operates
 * at the module level rather than individual tasks. Each module can contribute
 * both tools (for interactive/headless use) and tasks (for DAG pipeline execution).
 *
 * Module tools are namespaced as "moduleId:toolAction" (e.g. "blackbox:recon").
 */

import type { TaskRegistry } from "../agents/registry.js";
import type { AgentTask } from "../agents/types.js";
import type { KnowledgeRegistry } from "../knowledge/types.js";
import type {
  CopilotModule,
  ModuleContext,
  ModuleInfo,
  ModuleSpecifier,
  ModuleTool,
} from "./types.js";

/** Events emitted by the registry itself. */
export interface ModuleRegistryEvents {
  "module:loaded": { moduleId: string };
  "module:unloaded": { moduleId: string };
  "module:error": { moduleId: string; error: string };
}

export class ModuleRegistry {
  private readonly modules = new Map<string, CopilotModule>();
  private readonly initialized = new Set<string>();
  /**
   * Tool-name aliases. Keyed by old fully-qualified name, value is the new
   * fully-qualified name. Used for backward-compat when a tool moves between
   * modules (e.g. `sast:semgrep` → `semgrep:scan`). `resolveTool()` consults
   * this map after a direct lookup misses.
   */
  private readonly aliases = new Map<string, string>();

  /**
   * Register a module instance. Does NOT call init — use loadModule() for full lifecycle.
   * Throws if a module with the same ID is already registered.
   */
  register(mod: CopilotModule): void {
    if (this.modules.has(mod.id)) {
      throw new Error(`Module "${mod.id}" is already registered`);
    }
    this.modules.set(mod.id, mod);
  }

  /**
   * Register and initialize a module. Full lifecycle:
   * 1. Validate no ID conflict
   * 2. Register
   * 3. Call init() if defined
   * 4. Register tasks in the TaskRegistry if provided
   * 5. Register knowledge modules if provided
   */
  async loadModule(
    mod: CopilotModule,
    ctx: ModuleContext,
    opts?: {
      taskRegistry?: TaskRegistry;
      knowledgeRegistry?: KnowledgeRegistry;
      moduleConfig?: Record<string, unknown>;
    },
  ): Promise<void> {
    this.register(mod);

    try {
      // Initialize the module
      if (mod.init) {
        await mod.init(opts?.moduleConfig ?? {}, ctx);
      }
      this.initialized.add(mod.id);

      // Register pipeline tasks in the shared TaskRegistry
      if (mod.tasks && opts?.taskRegistry) {
        for (const task of mod.tasks) {
          if (!opts.taskRegistry.has(task.id)) {
            opts.taskRegistry.register(task);
          }
        }
      }

      // Register knowledge modules in the shared KnowledgeRegistry
      // (KnowledgeRegistry doesn't have a standard register method yet,
      // so this is a forward-compatible hook)
    } catch (err) {
      // Rollback on init failure
      this.modules.delete(mod.id);
      this.initialized.delete(mod.id);
      throw new Error(
        `Failed to load module "${mod.id}": ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  /**
   * Unload a module: call dispose(), remove from registry.
   */
  async unloadModule(moduleId: string): Promise<void> {
    const mod = this.modules.get(moduleId);
    if (!mod) return;

    if (mod.dispose && this.initialized.has(moduleId)) {
      await mod.dispose();
    }

    this.modules.delete(moduleId);
    this.initialized.delete(moduleId);
  }

  /**
   * Gracefully dispose all loaded modules (in reverse registration order).
   */
  async disposeAll(): Promise<void> {
    const ids = [...this.modules.keys()].reverse();
    for (const id of ids) {
      await this.unloadModule(id);
    }
  }

  // -------------------------------------------------------------------------
  // Queries
  // -------------------------------------------------------------------------

  /** Get a module by ID. Throws if not found. */
  get(id: string): CopilotModule {
    const mod = this.modules.get(id);
    if (!mod) {
      throw new Error(`Unknown module: "${id}"`);
    }
    return mod;
  }

  /** Check if a module is registered. */
  has(id: string): boolean {
    return this.modules.has(id);
  }

  /** Check if a module has been initialized. */
  isInitialized(id: string): boolean {
    return this.initialized.has(id);
  }

  /** List all registered module IDs. */
  ids(): string[] {
    return [...this.modules.keys()];
  }

  /** List all modules with summary info. */
  list(): ModuleInfo[] {
    return [...this.modules.values()].map((mod) => ({
      id: mod.id,
      displayName: mod.displayName,
      category: mod.category,
      version: mod.version,
      description: mod.description,
      toolCount: mod.tools.length,
      taskCount: mod.tasks?.length ?? 0,
      loaded: this.initialized.has(mod.id),
      ...(mod.rank ? { rank: mod.rank } : {}),
      ...(mod.references ? { references: mod.references } : {}),
      ...(mod.disclosureDate ? { disclosureDate: mod.disclosureDate } : {}),
    }));
  }

  // -------------------------------------------------------------------------
  // Tool resolution
  // -------------------------------------------------------------------------

  /**
   * Resolve a fully-qualified tool name ("module:action") to the ModuleTool.
   * Returns undefined if not found. Falls back to the alias map on miss so
   * legacy names (e.g. `sast:semgrep`) resolve to their current home.
   */
  resolveTool(qualifiedName: string): { module: CopilotModule; tool: ModuleTool } | undefined {
    const [moduleId, ...rest] = qualifiedName.split(":");
    if (moduleId && rest.length > 0) {
      const mod = this.modules.get(moduleId);
      const tool = mod?.tools.find((t) => t.name === qualifiedName);
      if (mod && tool) return { module: mod, tool };
    }

    // Alias fallback — guarded to avoid pathological cycles.
    const aliased = this.aliases.get(qualifiedName);
    if (aliased && aliased !== qualifiedName) {
      return this.resolveTool(aliased);
    }
    return undefined;
  }

  /**
   * Register a legacy name → canonical name redirect. Used to keep old tool
   * names resolvable after a module split. Overwrites any prior entry.
   */
  registerAlias(oldName: string, newName: string): void {
    this.aliases.set(oldName, newName);
  }

  /** Snapshot of all registered aliases (for diagnostics / `info`). */
  listAliases(): Array<{ from: string; to: string }> {
    return [...this.aliases.entries()].map(([from, to]) => ({ from, to }));
  }

  /**
   * Get all tools across all loaded modules.
   * Optionally filter to headless-only tools (for run mode).
   */
  allTools(opts?: { headlessOnly?: boolean }): Array<{ module: CopilotModule; tool: ModuleTool }> {
    const results: Array<{ module: CopilotModule; tool: ModuleTool }> = [];

    for (const mod of this.modules.values()) {
      if (!this.initialized.has(mod.id)) continue;

      for (const tool of mod.tools) {
        if (opts?.headlessOnly && !tool.headless) continue;
        results.push({ module: mod, tool });
      }
    }

    return results;
  }

  /**
   * Get all tools for a specific module.
   */
  moduleTools(moduleId: string): ReadonlyArray<ModuleTool> {
    const mod = this.modules.get(moduleId);
    return mod?.tools ?? [];
  }

  /**
   * Get all pipeline tasks across all loaded modules.
   */
  allTasks(): Array<{ moduleId: string; task: AgentTask }> {
    const results: Array<{ moduleId: string; task: AgentTask }> = [];

    for (const mod of this.modules.values()) {
      if (!mod.tasks) continue;
      for (const task of mod.tasks) {
        results.push({ moduleId: mod.id, task });
      }
    }

    return results;
  }
}

// ---------------------------------------------------------------------------
// Module specifier parsing
// ---------------------------------------------------------------------------

/**
 * Parse a module specifier string into a typed ModuleSpecifier.
 *
 * Formats:
 *   "builtin:sast"              → { type: "builtin", id: "sast" }
 *   "file:///path/to/module"    → { type: "local", path: "/path/to/module" }
 *   "package:@kuzushi/blackbox" → { type: "package", name: "@kuzushi/blackbox" }
 *   "mcp:http://localhost:3000" → { type: "mcp", serverUrl: "http://localhost:3000" }
 */
export function parseModuleSpecifier(spec: string): ModuleSpecifier {
  if (spec.startsWith("builtin:")) {
    return { type: "builtin", id: spec.slice("builtin:".length) };
  }
  if (spec.startsWith("file://")) {
    return { type: "local", path: spec.slice("file://".length) };
  }
  if (spec.startsWith("package:")) {
    return { type: "package", name: spec.slice("package:".length) };
  }
  if (spec.startsWith("mcp:")) {
    return { type: "mcp", serverUrl: spec.slice("mcp:".length) };
  }

  // Default: treat bare strings as builtin IDs
  return { type: "builtin", id: spec };
}

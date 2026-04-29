/**
 * ModuleRegistry — manages CopilotModule lifecycle and tool resolution.
 *
 * Extends the same patterns as DagRegistry but operates
 * at the module level rather than individual tasks. Each module can contribute
 * both tools (for interactive/headless use) and tasks (for DAG pipeline execution).
 *
 * Module tools are namespaced as "moduleId:toolAction" (e.g. "blackbox:recon").
 */

import type { KnowledgeRegistry } from "../knowledge/types.js";
import { installDagToolExecuteWrappers } from "./dag-execute.js";
import type { DagRegistry } from "./dag-registry.js";
import { registerDagToolsInDagRegistry } from "./dag-registry.js";
import { ModuleLoadError } from "./errors.js";
import {
  type CopilotModule,
  isDagTool,
  type ModuleContext,
  type ModuleInfo,
  type ModuleManifest,
  type ModuleSpecifier,
  type ModuleTool,
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
      throw new ModuleLoadError("ID_MISMATCH", `Module "${mod.id}" is already registered`, {
        moduleId: mod.id,
      });
    }
    this.modules.set(mod.id, mod);
  }

  /**
   * Register and initialize a module. Full lifecycle:
   * 1. Validate no ID conflict
   * 2. Register
   * 3. Call init() if defined
   * 4. Register tasks in the DagRegistry if provided
   * 5. Register knowledge modules if provided
   */
  async loadModule(
    mod: CopilotModule,
    ctx: ModuleContext,
    opts?: {
      dagRegistry?: DagRegistry;
      knowledgeRegistry?: KnowledgeRegistry;
      moduleConfig?: Record<string, unknown>;
      /**
       * Optional manifest reference used to enforce `configSchema` against
       * `moduleConfig` before `mod.init()` runs. When omitted, no schema
       * validation is performed (matches the pre-SCHEMA-3 behavior for
       * builtin modules which have no manifest).
       */
      manifest?: ModuleManifest;
    },
  ): Promise<void> {
    this.register(mod);

    try {
      // SCHEMA-3 — enforce configSchema against moduleConfig before init().
      if (opts?.manifest?.configSchema && opts.moduleConfig) {
        const err = validateConfigAgainstSchema(opts.moduleConfig, opts.manifest.configSchema);
        if (err) {
          throw new ModuleLoadError(
            "CONFIG_INVALID",
            `Module "${mod.id}" moduleConfig failed configSchema validation: ${err}`,
            { moduleId: mod.id, issue: err },
          );
        }
      }

      // Initialize the module
      if (mod.init) {
        await mod.init(opts?.moduleConfig ?? {}, ctx);
      }
      this.initialized.add(mod.id);

      // Register DagTools (module-forward DAG participants) directly.
      // Safe to call unconditionally — the DAG registry skips re-registrations
      // and modules without any DagTools are a no-op.
      if (opts?.dagRegistry) {
        registerDagToolsInDagRegistry(opts.dagRegistry, mod);
      }
      installDagToolExecuteWrappers(mod);

      // Run per-tool init hooks. Scanner-plugin-style tools (semgrep, codeql)
      // use this to resolve rule paths from `moduleConfig` once, before any
      // `execute`/`run` call. Module-level `init` has already run above.
      const toolConfig = opts?.moduleConfig ?? {};
      for (const tool of mod.tools) {
        if (tool.init) {
          await tool.init(toolConfig);
        }
      }

      // Register knowledge modules in the shared KnowledgeRegistry
      // (KnowledgeRegistry doesn't have a standard register method yet,
      // so this is a forward-compatible hook)
    } catch (err) {
      // Rollback on init failure
      this.modules.delete(mod.id);
      this.initialized.delete(mod.id);
      // Preserve `ModuleLoadError` codes through the rollback wrapper.
      if (err instanceof ModuleLoadError) {
        throw err;
      }
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
      throw new ModuleLoadError("ID_MISMATCH", `Unknown module: "${id}"`, { moduleId: id });
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
      // Report the number of DagTools — historically reflected the
      // module's `tasks?` contribution. After the module-forward
      // reconciliation, DAG participants live on `tools` with
      // `isDagTool(t) === true`.
      taskCount: mod.tools.filter(isDagTool).length,
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

// ---------------------------------------------------------------------------
// Lightweight JSON-Schema validation for `configSchema`
// ---------------------------------------------------------------------------

/**
 * Minimal JSON-Schema-ish validator — enough to enforce the common manifest
 * patterns (`type: "object"`, `required: [...]`, per-property `type`, `enum`).
 * Any deeper dialect support (anyOf/allOf/patternProperties/etc.) is out of
 * scope for the SDK loader; authors that need rich validation should do it
 * inside `module.init()` with their own zod/ajv schema.
 *
 * Returns `null` on success, or a human-readable error string on the first
 * issue encountered.
 */
export function validateConfigAgainstSchema(
  config: unknown,
  schema: Record<string, unknown>,
): string | null {
  if (typeof config !== "object" || config === null || Array.isArray(config)) {
    return "config must be a plain object";
  }
  const cfg = config as Record<string, unknown>;

  if (schema["type"] && schema["type"] !== "object") {
    return `configSchema.type "${String(schema["type"])}" is unsupported (expected "object")`;
  }

  const required = Array.isArray(schema["required"])
    ? (schema["required"] as unknown[]).filter((v): v is string => typeof v === "string")
    : [];
  for (const key of required) {
    if (!(key in cfg) || cfg[key] === undefined) {
      return `missing required config field "${key}"`;
    }
  }

  const properties =
    schema["properties"] && typeof schema["properties"] === "object"
      ? (schema["properties"] as Record<string, Record<string, unknown>>)
      : null;
  if (properties) {
    for (const [key, propSchema] of Object.entries(properties)) {
      if (!(key in cfg) || cfg[key] === undefined) continue;
      const expectedType = propSchema["type"];
      if (typeof expectedType === "string") {
        const actual = jsonTypeOf(cfg[key]);
        if (actual !== expectedType) {
          // "integer" is a refinement of "number"; accept integer-valued number.
          if (!(expectedType === "number" && actual === "integer")) {
            return `config field "${key}" expected type ${expectedType}, got ${actual}`;
          }
        }
      }
      if (Array.isArray(propSchema["enum"])) {
        if (!(propSchema["enum"] as unknown[]).includes(cfg[key])) {
          return `config field "${key}" must be one of ${(propSchema["enum"] as unknown[]).join("|")}`;
        }
      }
    }
  }
  return null;
}

function jsonTypeOf(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "number" && Number.isInteger(v)) return "integer";
  return typeof v;
}

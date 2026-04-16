/**
 * CopilotCore — the central coordinator for the Kuzushi security operating environment.
 *
 * Responsibilities:
 * 1. Module lifecycle: load, init, dispose modules via ModuleRegistry
 * 2. Tool dispatch: route tool calls (from LLM or CLI) to the correct module tool
 * 3. Context assembly: build security-aware system prompts from workspace state
 *
 * CopilotCore is used by all three execution modes:
 * - Pipeline mode: loads the core SAST module, dispatches via DAG orchestrator
 * - Run mode: loads requested module, executes a single tool headlessly
 * - Shell mode: loads all requested modules, routes LLM tool calls interactively
 */

import type { AgentRuntime } from "../agent-runtime/types.js";
import type { TaskRegistry } from "../agents/registry.js";
import type { MessageBus } from "../bus/types.js";
import { createCoreSastModule } from "../modules/core-sast.js";
import { ModuleRegistry, parseModuleSpecifier } from "../modules/registry.js";
import type {
  ModuleContext,
  ModuleInfo,
  ToolExecutionContext,
  ToolResult,
} from "../modules/types.js";
import type { KuzushiConfig } from "../types.js";

// ---------------------------------------------------------------------------
// CopilotCore options
// ---------------------------------------------------------------------------

export interface CopilotCoreOptions {
  runtime: AgentRuntime;
  bus: MessageBus;
  config: KuzushiConfig;
  /** The .kuzushi data directory for module persistence. */
  dataDir: string;
  /** Existing task registry (for pipeline mode compatibility). */
  taskRegistry?: TaskRegistry;
  /** Module specifiers to load at startup. */
  modules?: string[];
  /** Whether to load the built-in SAST module. Defaults to true. */
  loadCoreSast?: boolean;
  /** Optional governance enforcer for scope/budget/tier checks. */
  enforcer?: import("../governance/enforcer.js").GovernanceEnforcer;
  /** Optional audit trail for logging tool executions. */
  auditTrail?: import("../governance/audit.js").AuditTrail;
}

// ---------------------------------------------------------------------------
// CopilotCore
// ---------------------------------------------------------------------------

export class CopilotCore {
  readonly registry: ModuleRegistry;
  private readonly moduleCtx: ModuleContext;
  private readonly taskRegistry?: TaskRegistry;

  constructor(private readonly opts: CopilotCoreOptions) {
    this.registry = new ModuleRegistry();
    this.moduleCtx = {
      runtime: opts.runtime,
      bus: opts.bus,
      config: opts.config,
      dataDir: opts.dataDir,
    };
    this.taskRegistry = opts.taskRegistry;
  }

  /**
   * Initialize the copilot: load built-in modules and any requested external modules.
   */
  async init(): Promise<void> {
    // Load the core SAST module (unless explicitly disabled)
    if (this.opts.loadCoreSast !== false) {
      const sast = createCoreSastModule();
      await this.registry.loadModule(sast, this.moduleCtx, {
        taskRegistry: this.taskRegistry,
      });
    }

    // Load any additional modules specified at startup
    if (this.opts.modules) {
      for (const spec of this.opts.modules) {
        await this.loadModuleFromSpecifier(spec);
      }
    }
  }

  /**
   * Load a module from a specifier string.
   *
   * Specifier formats:
   *   "sast"                        → builtin
   *   "builtin:sast"                → builtin
   *   "file:///path/to/module"      → local directory
   *   "package:@kuzushi/blackbox"   → npm package
   *   "mcp:http://localhost:3000"   → MCP server
   */
  async loadModuleFromSpecifier(spec: string): Promise<void> {
    const parsed = parseModuleSpecifier(spec);

    switch (parsed.type) {
      case "builtin":
        await this.loadBuiltinModule(parsed.id);
        break;
      case "local":
        await this.loadLocalModule(parsed.path);
        break;
      case "package":
        await this.loadPackageModule(parsed.name);
        break;
      case "mcp":
        await this.loadMcpModule(parsed.serverUrl);
        break;
    }
  }

  // -------------------------------------------------------------------------
  // Tool dispatch
  // -------------------------------------------------------------------------

  /**
   * Execute a tool by its fully-qualified name ("module:action").
   *
   * This is the primary dispatch method used by all three modes:
   * - Shell mode: LLM tool calls route here
   * - Run mode: CLI argument parsed to tool name, dispatched here
   * - Pipeline mode: orchestrator can optionally dispatch module tools
   */
  async executeTool(
    qualifiedName: string,
    input: unknown,
    ctxOverrides?: Partial<ToolExecutionContext>,
  ): Promise<ToolResult> {
    const resolved = this.registry.resolveTool(qualifiedName);
    if (!resolved) {
      return {
        ok: false,
        output: `Unknown tool: "${qualifiedName}". Use "module list" to see available tools.`,
      };
    }

    const { tool } = resolved;

    // Governance enforcement — check scope, budget, tier before execution
    const inputRecord =
      input && typeof input === "object" && !Array.isArray(input)
        ? (input as Record<string, unknown>)
        : {};
    const target = ctxOverrides?.target ?? (inputRecord.target as string | undefined);

    if (this.opts.enforcer) {
      const check = this.opts.enforcer.checkExecution(qualifiedName, target);
      if (!check.allowed) {
        if (this.opts.auditTrail) {
          this.opts.auditTrail.record(
            this.opts.enforcer.buildAuditEntry(qualifiedName, inputRecord, check, {
              workspaceId: ctxOverrides?.workspaceId,
            }),
          );
        }
        return { ok: false, output: `Blocked by governance: ${check.reason}` };
      }
    }

    const ctx: ToolExecutionContext = {
      cwd: ctxOverrides?.cwd ?? this.opts.dataDir,
      runtime: ctxOverrides?.runtime ?? this.opts.runtime,
      bus: ctxOverrides?.bus ?? this.opts.bus,
      config: ctxOverrides?.config ?? this.opts.config,
      workspaceId: ctxOverrides?.workspaceId,
      target,
      signal: ctxOverrides?.signal,
      uiStore: ctxOverrides?.uiStore,
      seedTaskOutputs: ctxOverrides?.seedTaskOutputs,
    };

    const result = await tool.execute(input, ctx);

    // Post-execution: record audit + track cost
    if (this.opts.enforcer && result.costUsd) {
      this.opts.enforcer.addCost(result.costUsd);
    }
    if (this.opts.auditTrail) {
      this.opts.auditTrail.record(
        (
          this.opts.enforcer ??
          new (await import("../governance/enforcer.js")).GovernanceEnforcer(
            (await import("../governance/types.js")).defaultScopePolicy(),
          )
        ).buildAuditEntry(
          qualifiedName,
          inputRecord,
          { allowed: true },
          {
            costUsd: result.costUsd,
            workspaceId: ctxOverrides?.workspaceId,
          },
        ),
      );
    }

    return result;
  }

  // -------------------------------------------------------------------------
  // Context assembly (for shell mode — builds the agent's system prompt)
  // -------------------------------------------------------------------------

  /**
   * Build a system prompt prefix that gives the LLM awareness of:
   * - Loaded modules and their tools
   * - Current workspace state (targets, findings summary, compliance)
   * - Available structured commands
   *
   * This is injected into the AgentSession's system prompt so the LLM
   * knows what tools are available and what the current security context is.
   */
  buildSystemPromptPrefix(): string {
    const modules = this.registry.list();
    const allTools = this.registry.allTools();

    const sections: string[] = [];

    // Module overview
    sections.push("# Kuzushi Security Copilot\n");
    sections.push("You are Kuzushi, a security-native AI operating environment. ");
    sections.push("You have access to the following security modules and tools.\n");

    // Module list
    sections.push("## Loaded Modules\n");
    for (const mod of modules) {
      if (!mod.loaded) continue;
      sections.push(`- **${mod.displayName}** (${mod.id}) [${mod.category}] — ${mod.description}`);
    }
    sections.push("");

    // Tool catalog
    sections.push("## Available Tools\n");
    for (const { module: mod, tool } of allTools) {
      sections.push(`### ${tool.name}`);
      sections.push(tool.description);
      if (!tool.headless) {
        sections.push("*Requires interactive confirmation.*");
      }
      sections.push("");
    }

    return sections.join("\n");
  }

  // -------------------------------------------------------------------------
  // Module queries
  // -------------------------------------------------------------------------

  /** List all loaded modules with summary info. */
  listModules(): ModuleInfo[] {
    return this.registry.list();
  }

  /** Check if a specific module is loaded. */
  hasModule(id: string): boolean {
    return this.registry.has(id);
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  /** Gracefully shut down all modules. */
  async dispose(): Promise<void> {
    await this.registry.disposeAll();
  }

  // -------------------------------------------------------------------------
  // Module loaders (private)
  // -------------------------------------------------------------------------

  private async loadBuiltinModule(id: string): Promise<void> {
    // Skip if already loaded
    if (this.registry.has(id)) return;

    switch (id) {
      case "sast": {
        const sast = createCoreSastModule();
        await this.registry.loadModule(sast, this.moduleCtx, {
          taskRegistry: this.taskRegistry,
        });
        break;
      }
      // Future built-in modules go here as they're ported
      default:
        throw new Error(`Unknown built-in module: "${id}"`);
    }
  }

  private async loadLocalModule(modulePath: string): Promise<void> {
    const { loadManifestFromPath, checkRequirements, dynamicImportModule } = await import(
      "../modules/loader.js"
    );
    const path = await import("node:path");

    const manifest = loadManifestFromPath(modulePath);

    if (manifest.requires) {
      const reqCheck = checkRequirements(manifest.requires);
      if (!reqCheck.satisfied) {
        throw new Error(
          `Module "${manifest.id}" requirements not met: ${reqCheck.missing.join(", ")}`,
        );
      }
    }

    const entryPath = path.resolve(modulePath, manifest.entry);
    const mod = await dynamicImportModule(entryPath);

    if (mod.id !== manifest.id) {
      throw new Error(
        `Module ID mismatch: manifest declares "${manifest.id}" but module exports "${mod.id}"`,
      );
    }

    await this.registry.loadModule(mod, this.moduleCtx, {
      taskRegistry: this.taskRegistry,
    });
  }

  private async loadPackageModule(packageName: string): Promise<void> {
    const { createRequire } = await import("node:module");
    const path = await import("node:path");
    const { existsSync } = await import("node:fs");

    const require = createRequire(import.meta.url);
    let packageDir: string;

    try {
      packageDir = path.dirname(require.resolve(`${packageName}/package.json`));
    } catch {
      throw new Error(
        `Package "${packageName}" is not installed. ` + `Install it with: pnpm add ${packageName}`,
      );
    }

    // If the package has a module.manifest.json, use the full manifest loader
    const manifestPath = path.join(packageDir, "module.manifest.json");
    if (existsSync(manifestPath)) {
      await this.loadLocalModule(packageDir);
      return;
    }

    // Otherwise try direct import as CopilotModule
    const { dynamicImportModule } = await import("../modules/loader.js");
    const mod = await dynamicImportModule(require.resolve(packageName));
    await this.registry.loadModule(mod, this.moduleCtx, {
      taskRegistry: this.taskRegistry,
    });
  }

  private async loadMcpModule(serverSpec: string): Promise<void> {
    const { createMcpModule } = await import("../modules/mcp-bridge.js");

    // Derive a module ID from the server spec
    const moduleId =
      serverSpec
        .replace(/^(https?:\/\/|npx\s+|node\s+|python\s+)/, "")
        .replace(/[^a-z0-9-]/gi, "-")
        .replace(/-+/g, "-")
        .replace(/^-|-$/g, "")
        .slice(0, 30) || "mcp";

    const { module: mod } = await createMcpModule(serverSpec, moduleId);
    await this.registry.loadModule(mod, this.moduleCtx, {
      taskRegistry: this.taskRegistry,
    });
  }
}

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

import { type Dirent, existsSync, readdirSync } from "node:fs";
import nodePath from "node:path";
import type { AgentRuntime } from "../agent-runtime/types.js";
import { publishAgentActivity, publishTaskActivity, publishTaskOutput } from "../bus/activity.js";
import { ModuleEventBus, type ModuleEventScope } from "../bus/module-events.js";
import { wrapRuntimeWithActivityForwarding } from "../bus/runtime-forwarding.js";
import type { MessageBus } from "../bus/types.js";
import { createAgenticSastModule } from "../modules/agentic-sast/agentic-sast.js";
import { ModuleCache } from "../modules/cache.js";
import { createCarliniThreatHuntModule } from "../modules/carlini-threat-hunt/carlini-threat-hunt.js";
import { createChromeRceModule } from "../modules/chrome-rce/chrome-rce.js";
import { createCodeqlModule } from "../modules/codeql/codeql.js";
import { createContextModule } from "../modules/context/context.js";
import { createCoreSastModule } from "../modules/core-sast.js";
import type { DagRegistry } from "../modules/dag-registry.js";
import { createDepHygieneModule } from "../modules/dep-hygiene/dep-hygiene.js";
import { createFindingsModule } from "../modules/findings/findings.js";
import {
  formatToolInputValidationError,
  normalizeToolInputKeys,
  validateToolInput,
} from "../modules/input-validation.js";
import { readHostKuzushiVersion } from "../modules/loader.js";
import { createNDayDiffHunterModule } from "../modules/n-day-diff-hunter.js";
import { createPatchModule } from "../modules/patch/patch.js";
import { createPipelineModule } from "../modules/pipeline/pipeline.js";
import {
  createProblemDetails,
  ProblemCode,
  problemToolResult,
} from "../modules/problem-details.js";
import { createCorePromptArmorModule } from "../modules/prompt-armor/prompt-armor.js";
import { createCoreRandoriModule } from "../modules/randori/randori.js";
import { ModuleRegistry, parseModuleSpecifier } from "../modules/registry.js";
import { createSecretScanModule } from "../modules/secret-scan/secret-scan.js";
import { createSemgrepModule } from "../modules/semgrep/semgrep.js";
import { createCoreShinsaModule } from "../modules/shinsa/shinsa.js";
import { createSystemsHuntModule } from "../modules/systems-hunt/systems-hunt.js";
import { createTaintIrisModule } from "../modules/taint-iris/taint-iris.js";
import { createTaintIrisNextModule } from "../modules/taint-iris-next/taint-iris-next.js";
import { createThreatModelModule } from "../modules/threat-model/threat-model.js";
import { createCoreTobModule } from "../modules/tob/tob.js";
import { createTriageModule } from "../modules/triage/triage.js";
import type { ExecutionContext, ModuleContext, ModuleInfo, ToolResult } from "../modules/types.js";
import { createVariantHunterModule } from "../modules/variant-hunter.js";
import { createVendorAssessmentModule } from "../modules/vendor-assessment/vendor-assessment.js";
import { createVerifyModule } from "../modules/verify/verify.js";
import { createCoreVulnScoutModule } from "../modules/vuln-scout/vuln-scout.js";
import { createXRayModule } from "../modules/x-ray/x-ray.js";
import type { KuzushiConfig } from "../types.js";

/**
 * Host SDK version injected into `ctx.host.sdkVersion` on every tool call.
 * Read once at load time from the runtime `kuzushi` package.json; falls
 * back to "0.0.0" if the package.json can't be located (vendored/worktree
 * layouts).
 */
const KUZUSHI_SDK_VERSION: string = readHostKuzushiVersion() ?? "0.0.0";

// ---------------------------------------------------------------------------
// CopilotCore options
// ---------------------------------------------------------------------------

export interface CopilotCoreOptions {
  runtime: AgentRuntime;
  bus: MessageBus;
  config: KuzushiConfig;
  /** The .kuzushi data directory for module persistence. */
  dataDir: string;
  /** Existing DAG registry for pipeline mode. */
  dagRegistry?: DagRegistry;
  /** Module specifiers to load at startup. */
  modules?: string[];
  /** Whether to load the built-in SAST module. Defaults to true. */
  loadCoreSast?: boolean;
  /**
   * Built-in module ids to skip during the default load. Useful when a
   * module's binary dependency is missing (e.g. `codeql`) and the
   * operator wants to keep the rest of the catalog functional.
   * Field-test issue #21.
   */
  excludeBuiltinModules?: string[];
  /** Optional governance enforcer for scope/budget/tier checks. */
  enforcer?: import("../governance/enforcer.js").GovernanceEnforcer;
  /** Optional audit trail for logging tool executions. */
  auditTrail?: import("../governance/audit.js").AuditTrail;
  /**
   * Optional global Datastore. When provided, live operator `setg`s take
   * effect per-execution:
   *   BUDGET_USD       → governance enforcer budget cap override
   *   <MOD>_MODEL      → model override for tools in module <mod>
   *                      (upper-cased, e.g. TRIAGE_MODEL / VERIFY_MODEL)
   */
  globals?: import("./options.js").Datastore;
}

// ---------------------------------------------------------------------------
// CopilotCore
// ---------------------------------------------------------------------------

export class CopilotCore {
  readonly registry: ModuleRegistry;
  /** Cross-module framework events (msfconsole-style). */
  readonly events: ModuleEventBus;
  /** Materialized metadata cache — written on init, consulted by search/info. */
  readonly moduleCache: ModuleCache;
  private readonly moduleCtx: ModuleContext;
  private readonly dagRegistry?: DagRegistry;
  /** Lifecycle-scoped event handles per module — disposed on unload. */
  private readonly moduleScopes = new Map<string, ModuleEventScope>();

  constructor(private readonly opts: CopilotCoreOptions) {
    this.registry = new ModuleRegistry();
    this.events = new ModuleEventBus();
    this.moduleCache = new ModuleCache(opts.dataDir);
    this.moduleCtx = {
      runtime: opts.runtime,
      bus: opts.bus,
      config: opts.config,
      dataDir: opts.dataDir,
    };
    this.dagRegistry = opts.dagRegistry;
  }

  /**
   * Late-bind the globals Datastore so operator `setg`s land on the same
   * store CopilotCore reads for live knobs (BUDGET_USD, <MOD>_MODEL).
   * The shell instantiates CopilotCore before the Datastore is available;
   * this setter closes the gap.
   */
  setGlobals(globals: import("./options.js").Datastore): void {
    (this.opts as { globals?: import("./options.js").Datastore }).globals = globals;
  }

  /**
   * Load a module while attaching a per-module event scope.
   * Use instead of `this.registry.loadModule(...)` so cross-module pub/sub
   * subscriptions are lifecycle-managed.
   */
  private async loadWithScope(
    mod: import("../modules/types.js").CopilotModule,
    extra: Record<string, unknown> = {},
  ): Promise<void> {
    const scope = this.events.scope(mod.id);
    this.moduleScopes.set(mod.id, scope);
    const moduleCtx: ModuleContext = { ...this.moduleCtx, events: scope };
    try {
      await this.registry.loadModule(mod, moduleCtx, {
        dagRegistry: this.dagRegistry,
        ...extra,
      });
      this.moduleCache.upsertFromModule(mod);
    } catch (err) {
      scope.disposeAll();
      this.moduleScopes.delete(mod.id);
      throw err;
    }
  }

  /**
   * Initialize the copilot: load built-in modules and any requested external modules.
   */
  async init(): Promise<void> {
    // Load the core SAST module family (unless explicitly disabled).
    // The umbrella `sast` module owns the full-DAG `sast:scan`; each
    // capability (semgrep, codeql, agentic-sast, carlini-threat-hunt, taint-iris,
    // triage, verify, patch, findings, context) is its own CopilotModule so
    // operators can `use <capability>` and get a focused option surface.
    if (this.opts.loadCoreSast !== false) {
      const sastFamily = [
        createCoreSastModule(),
        createSemgrepModule(),
        createCodeqlModule(),
        createAgenticSastModule(),
        createCarliniThreatHuntModule(),
        createTaintIrisModule(),
        createTaintIrisNextModule(),
        createSystemsHuntModule(),
        createTriageModule(),
        createVerifyModule(),
        createPatchModule(),
        createFindingsModule(),
        createContextModule(),
        createThreatModelModule(),
        createXRayModule(),
        createVendorAssessmentModule(),
        createChromeRceModule(),
        createDepHygieneModule(),
        createSecretScanModule(),
        // Hidden orchestrator-level module — infrastructure DAG nodes
        // (task-selector, approval gates, taint-iris sub-tasks). Loaded so
        // the module registry owns every scan-DAG participant; the user
        // never sees `/use pipeline` in the catalog.
        createPipelineModule(),
      ];
      const excluded = new Set(this.opts.excludeBuiltinModules ?? []);
      for (const mod of sastFamily) {
        if (excluded.has(mod.id)) continue;
        await this.loadWithScope(mod);
      }
    }

    // Load any additional modules specified at startup
    if (this.opts.modules) {
      for (const spec of this.opts.modules) {
        await this.loadModuleFromSpecifier(spec);
      }
    }

    // Persist the module metadata cache so follow-up `search` / `info`
    // launches can read it without re-importing every module. Errors are
    // non-fatal — the cache is an optimization, not a source of truth.
    try {
      this.moduleCache.save();
    } catch {
      // Ignore — a missing/unwritable dataDir should never break init.
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
    ctxOverrides?: Partial<ExecutionContext>,
  ): Promise<ToolResult> {
    const resolved = this.registry.resolveTool(qualifiedName);
    if (!resolved) {
      const detail = `Unknown tool: "${qualifiedName}". Use "module list" to see available tools.`;
      return problemToolResult(
        createProblemDetails({
          code: ProblemCode.ToolNotFound,
          title: "Unknown tool",
          status: 404,
          detail,
          instance: qualifiedName,
        }),
      );
    }

    const { tool } = resolved;

    const normalizedInput = normalizeToolInputKeys(input, tool.inputSchema);
    const validation = validateToolInput(normalizedInput, tool.inputSchema);
    if (!validation.ok) {
      const detail = formatToolInputValidationError(qualifiedName, validation.issues);
      return problemToolResult(
        createProblemDetails({
          code: ProblemCode.InputValidationFailed,
          title: "Tool input validation failed",
          status: 400,
          detail,
          instance: qualifiedName,
          errors: validation.issues.map((issue) => ({
            path: issue.path,
            message: issue.message,
          })),
        }),
      );
    }

    // Governance enforcement — check scope, budget, tier before execution
    const inputRecord =
      normalizedInput && typeof normalizedInput === "object" && !Array.isArray(normalizedInput)
        ? (normalizedInput as Record<string, unknown>)
        : {};
    const target = ctxOverrides?.target ?? (inputRecord.target as string | undefined);

    const datastore = ctxOverrides?.datastore;

    // Live operator knobs read from the active Datastore and global Datastore.
    // BUDGET_USD caps the enforcer's budget check. `model` / `MODEL` is the
    // universal session override; <MOD>_MODEL remains as a legacy per-module
    // override for compatibility.
    const budgetOverride = parseBudgetOverride(this.opts.globals?.get("BUDGET_USD"));
    const moduleId = resolved.module.id;
    const modelKey = `${moduleId.toUpperCase().replace(/-/g, "_")}_MODEL`;
    const toolModel =
      readModelOverride(datastore?.get("model")) ??
      readModelOverride(this.opts.globals?.get("MODEL")) ??
      readModelOverride(this.opts.globals?.get(modelKey));

    if (this.opts.enforcer) {
      const check =
        budgetOverride !== undefined
          ? this.opts.enforcer.checkExecutionWithBudget(qualifiedName, target, budgetOverride)
          : this.opts.enforcer.checkExecution(qualifiedName, target);
      if (!check.allowed) {
        if (this.opts.auditTrail) {
          this.opts.auditTrail.record(
            this.opts.enforcer.buildAuditEntry(qualifiedName, inputRecord, check, {
              workspaceId: ctxOverrides?.workspaceId,
            }),
          );
        }
        return problemToolResult(
          createProblemDetails({
            code: ProblemCode.GovernanceBlocked,
            title: "Governance policy blocked tool execution",
            status: 403,
            detail: `Blocked by governance: ${check.reason}`,
            instance: qualifiedName,
          }),
        );
      }
    }

    // Inject the module's framework-event scope so `ctx.events.emit(...)`
    // reaches other modules subscribing to well-known events.
    const scope = this.moduleScopes.get(resolved.module.id);

    const ctxBus = ctxOverrides?.bus ?? this.opts.bus;
    const toolRuntime = wrapRuntimeWithActivityForwarding(
      ctxOverrides?.runtime ?? this.opts.runtime,
      ctxBus,
      qualifiedName,
      "shell",
    );
    // HOST-21 — build the per-call capability probe. Modules call
    // `ctx.host?.capabilities.has("workspace")` to guard optional features.
    const capabilities = new Set<string>();
    if (ctxOverrides?.workspace) capabilities.add("workspace");
    if (ctxOverrides?.uiStore) capabilities.add("ui-store");
    if (ctxOverrides?.datastore) capabilities.add("datastore");
    if (ctxOverrides?.print) capabilities.add("print-sink");
    if (scope) capabilities.add("module-events");
    if (toolModel) capabilities.add("tool-model");
    // Structured-output is a runtime-level capability — treat presence of
    // the upstream runtime as sufficient; tools that need the feature can
    // still probe the runtime directly.
    if (toolRuntime) capabilities.add("structured-output");

    const host = {
      sdkVersion: KUZUSHI_SDK_VERSION,
      capabilities: capabilities as ReadonlySet<string>,
    };

    const runConfig = ctxOverrides?.config ?? this.opts.config;
    const ctx: ExecutionContext = {
      cwd: ctxOverrides?.cwd ?? this.opts.dataDir,
      runtime: toolRuntime,
      bus: ctxBus,
      config: runConfig,
      workspaceId: ctxOverrides?.workspaceId,
      target,
      tool: {
        moduleId,
        name: qualifiedName,
        ...(tool.displayName ? { displayName: tool.displayName } : {}),
      },
      signal: ctxOverrides?.signal,
      uiStore: ctxOverrides?.uiStore,
      seedTaskOutputs: ctxOverrides?.seedTaskOutputs,
      ...(datastore ? { datastore } : {}),
      ...(ctxOverrides?.print ? { print: ctxOverrides.print } : {}),
      ...(ctxOverrides?.workspace ? { workspace: ctxOverrides.workspace } : {}),
      ...(scope ? { events: scope } : {}),
      ...(toolModel ? { toolModel } : {}),
      host,
      reportActivity: (description, meta) => {
        void publishTaskActivity(ctxBus, qualifiedName, description, meta ?? {});
      },
      reportOutput: (line) => {
        void publishTaskOutput(ctxBus, qualifiedName, line);
      },
      /**
       * Unified operator-option resolver. Replaces the duplicated pattern of
       * "read `CARLINI_THREAT_HUNT_PROMPT` from the datastore in core-carlini-threat-hunt.ts,
       * then read `promptOverride` from `taskConfig` in carlini-threat-hunt.ts" that
       * exists in every task-wrapping module today.
       *
       * Fallback order:
       *   1. `ctx.datastore.get(key)` — shell `set` / global `setg` (highest priority)
       *   2. `ctx.config.taskConfig[moduleId][key]` — persisted operator overrides
       *
       * Authors that want a legacy-field fallback (e.g.
       * `taskConfig["carlini-threat-hunt"]["promptOverride"]`) should call
       * `resolveOption` first and fall back to the legacy lookup explicitly:
       *
       *   const prompt = ctx.resolveOption<string>("CARLINI_THREAT_HUNT_PROMPT")
       *     ?? (ctx.config.taskConfig["carlini-threat-hunt"]?.["promptOverride"] as string);
       */
      resolveOption: <T = string>(key: string): T | undefined => {
        const fromStore = datastore?.get<T>(key);
        if (fromStore !== undefined) return fromStore;
        const moduleBucket = runConfig.taskConfig?.[moduleId] as
          | Record<string, unknown>
          | undefined;
        if (moduleBucket && key in moduleBucket) {
          return moduleBucket[key] as T;
        }
        return undefined;
      },
      /**
       * Emit a `${moduleId}:agent-activity` event via the unified publisher.
       * The report-worker subscribes via a pattern listener (see
       * `src/bus/workers/report-worker.ts`), so every DagTool that fans out
       * sub-agents gets identical UI plumbing without bespoke bus wiring.
       */
      reportAgentActivity: (fingerprint, kind, meta) => {
        publishAgentActivity(ctxBus, moduleId, fingerprint, kind, meta);
      },
    };

    // Module lifecycle events — fire on the module's own scope so the module
    // can subscribe to its own tool calls in init(). Other modules can
    // observe too; the bus broadcasts. See src/bus/module-events.ts for
    // the full well-known event list.
    scope?.emit("tool:before_run", { qualifiedName, input: normalizedInput });

    let result: ToolResult;
    try {
      result = await tool.execute(normalizedInput, ctx);
    } catch (err) {
      scope?.emit("tool:on_error", {
        qualifiedName,
        error: err instanceof Error ? err.message : String(err),
      });
      throw err;
    }
    scope?.emit("tool:after_run", { qualifiedName, result });

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
    for (const { tool } of allTools) {
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
    for (const scope of this.moduleScopes.values()) scope.disposeAll();
    this.moduleScopes.clear();
  }

  // -------------------------------------------------------------------------
  // Module loaders (private)
  // -------------------------------------------------------------------------

  private async loadBuiltinModule(id: string): Promise<void> {
    // Skip if already loaded
    if (this.registry.has(id)) return;

    switch (id) {
      case "sast":
        await this.loadWithScope(createCoreSastModule());
        break;
      case "variant":
      // Backward-compat — the old module id was "variant-hunter"; bare
      // `--load variant-hunter` should still work.
      case "variant-hunter":
        await this.loadWithScope(createVariantHunterModule());
        break;
      case "ndiff":
      // Backward-compat — prior id was "n-day-diff-hunter".
      case "n-day-diff-hunter":
        await this.loadWithScope(createNDayDiffHunterModule());
        break;
      case "randori":
        await this.loadWithScope(createCoreRandoriModule());
        break;
      case "threat-model":
        await this.loadWithScope(createThreatModelModule());
        break;
      case "x-ray":
        await this.loadWithScope(createXRayModule());
        break;
      case "taint-iris-next":
        await this.loadWithScope(createTaintIrisNextModule());
        break;
      case "vendor-assessment":
        await this.loadWithScope(createVendorAssessmentModule());
        break;
      case "vuln-scout":
        await this.loadWithScope(createCoreVulnScoutModule());
        break;
      case "tob":
        await this.loadWithScope(createCoreTobModule());
        break;
      case "shinsa":
        await this.loadWithScope(createCoreShinsaModule());
        break;
      case "prompt-armor":
        await this.loadWithScope(createCorePromptArmorModule());
        break;
      case "secret-scan":
        await this.loadWithScope(createSecretScanModule());
        break;
      // Future built-in modules go here as they're ported
      default:
        throw new Error(`Unknown built-in module: "${id}"`);
    }
  }

  private async loadLocalModule(modulePath: string): Promise<void> {
    const { loadManifestFromPath, checkRequirements, dynamicImportModule } = await import(
      "../modules/loader.js"
    );
    const { ModuleLoadError } = await import("../modules/errors.js");
    const path = await import("node:path");

    const manifest = loadManifestFromPath(modulePath);

    if (manifest.requires) {
      const reqCheck = checkRequirements(manifest.requires);
      if (!reqCheck.satisfied) {
        throw new ModuleLoadError(
          "REQUIREMENTS_UNMET",
          `Module "${manifest.id}" requirements not met: ${reqCheck.missing.join(", ")}`,
          { moduleId: manifest.id, missing: reqCheck.missing },
        );
      }
    }

    const entryPath = path.resolve(modulePath, manifest.entry);
    const mod = await dynamicImportModule(entryPath);

    if (mod.id !== manifest.id) {
      throw new ModuleLoadError(
        "ID_MISMATCH",
        `Module ID mismatch: manifest declares "${manifest.id}" but module exports "${mod.id}"`,
        { manifestId: manifest.id, exportedId: mod.id, path: modulePath },
      );
    }

    await this.loadWithScope(mod, { manifest });
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

    // If the package is a Claude Code plugin (has .claude-plugin/plugin.json
    // at the root or inside any immediate subdirectory), redirect the user
    // to the appropriate builtin CopilotModule wrapper. Loading it via
    // package: would fail opaquely with "module.id is undefined".
    const claudePluginHint = detectClaudeCodePlugin(packageDir);
    if (claudePluginHint) {
      throw new Error(
        `Package "${packageName}" is a Claude Code plugin (${claudePluginHint}), not a CopilotModule. ` +
          builtinHintFor(packageName),
      );
    }

    // Otherwise try direct import as CopilotModule
    const { dynamicImportModule } = await import("../modules/loader.js");
    const mod = await dynamicImportModule(require.resolve(packageName));
    await this.loadWithScope(mod);
  }

  private async loadMcpModule(serverSpec: string): Promise<void> {
    const { createMcpModule } = await import("../modules/mcp-bridge.js");

    // Derive a module ID from the server spec and pick a collision-free
    // suffix so two MCP specs that slug to the same base (e.g. localhost:3000
    // and localhost:3001 both stripping punctuation to "localhost-3000"
    // depending on pattern quirks) coexist. The original serverSpec is
    // preserved in the module's description so operators can tell them apart
    // in `/modules` and `/tools` listings.
    const moduleId = deriveUniqueMcpModuleId(serverSpec, (id) => this.registry.has(id));

    const { module: mod } = await createMcpModule(serverSpec, moduleId);
    await this.loadWithScope(mod);
  }
}

/**
 * Derive a Kuzushi module ID from an MCP server spec, appending `-2`, `-3`,
 * ... until `isTaken(id)` returns false. Exported for tests.
 *
 * The base slug trims a handful of common command/URL prefixes
 * (`http(s)://`, `npx `, `node `, `python `), replaces non-alphanumerics with
 * `-`, collapses runs, trims leading/trailing dashes, and caps length at 30.
 * Empty slugs fall back to `"mcp"`.
 */
export function deriveUniqueMcpModuleId(
  serverSpec: string,
  isTaken: (id: string) => boolean,
): string {
  const base =
    serverSpec
      .replace(/^(https?:\/\/|npx\s+|node\s+|python\s+)/, "")
      .replace(/[^a-z0-9-]/gi, "-")
      .replace(/-+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 30) || "mcp";

  if (!isTaken(base)) return base;
  for (let n = 2; n < 1000; n++) {
    const candidate = `${base}-${n}`;
    if (!isTaken(candidate)) return candidate;
  }
  throw new Error(
    `Failed to derive a unique module ID for MCP server "${serverSpec}" after 1000 attempts.`,
  );
}

/**
 * Parse a BUDGET_USD global value into a non-negative number. Returns
 * undefined when unset or unparseable — callers treat that as "use the
 * scope policy's static cap."
 */
function parseBudgetOverride(raw: unknown): number | undefined {
  if (raw === undefined || raw === null || raw === "") return undefined;
  const n = typeof raw === "number" ? raw : Number.parseFloat(String(raw));
  if (!Number.isFinite(n) || n < 0) return undefined;
  return n;
}

function readModelOverride(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const value = raw.trim();
  return value.length > 0 ? value : undefined;
}

// ---------------------------------------------------------------------------
// Package-shape detection helpers (exported for testing)
// ---------------------------------------------------------------------------

/**
 * If `packageDir` looks like a Claude Code plugin, return a short description
 * of where the plugin manifest was found. Otherwise return null.
 *
 * Claude Code plugins are detected by the presence of `.claude-plugin/plugin.json`
 * at the root or inside any immediate subdirectory (e.g. `whitebox-pentest/` for
 * @kuzushi/vuln-scout, `plugins/<name>/` for @kuzushi/tob-skills).
 */
export function detectClaudeCodePlugin(packageDir: string): string | null {
  const rootMarker = nodePath.join(packageDir, ".claude-plugin", "plugin.json");
  if (existsSync(rootMarker)) return ".claude-plugin/plugin.json";

  let entries: Dirent[];
  try {
    entries = readdirSync(packageDir, { withFileTypes: true });
  } catch {
    return null;
  }

  for (const entry of entries) {
    if (!entry.isDirectory() || entry.name.startsWith(".") || entry.name === "node_modules") {
      continue;
    }
    const nestedMarker = nodePath.join(packageDir, entry.name, ".claude-plugin", "plugin.json");
    if (existsSync(nestedMarker)) return `${entry.name}/.claude-plugin/plugin.json`;

    // One more level deep — tob-skills nests plugins under plugins/<name>/.
    if (entry.name === "plugins") {
      let inner: Dirent[];
      try {
        inner = readdirSync(nodePath.join(packageDir, entry.name), { withFileTypes: true });
      } catch {
        continue;
      }
      for (const sub of inner) {
        if (!sub.isDirectory()) continue;
        const marker = nodePath.join(
          packageDir,
          entry.name,
          sub.name,
          ".claude-plugin",
          "plugin.json",
        );
        if (existsSync(marker)) return `plugins/${sub.name}/.claude-plugin/plugin.json`;
      }
    }
  }

  return null;
}

/**
 * Map known Claude-Code-plugin package names to the builtin CopilotModule
 * that wraps them. Returns a user-facing hint about which builtin to load.
 */
export function builtinHintFor(packageName: string): string {
  const map: Record<string, string> = {
    "@kuzushi/randori-plugin": "threat-model",
    "@kuzushi/vuln-scout": "vuln-scout",
    "@kuzushi/tob-skills": "tob",
    "shinsa-plugin": "shinsa",
    "promptarmor-plugin": "prompt-armor",
  };
  const builtinId = map[packageName];
  if (builtinId) {
    return (
      `Use \`--load builtin:${builtinId}\` (or \`--load ${builtinId}\`) instead — ` +
      `the ${builtinId} built-in module exposes ${builtinId}:* tools that drive this plugin.`
    );
  }
  return "Claude Code plugins cannot be loaded as CopilotModules directly.";
}

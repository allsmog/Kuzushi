/**
 * Core type definitions for the Kuzushi module system.
 *
 * A CopilotModule is the unit of capability composition — each module
 * exposes tools (for interactive/headless invocation) and optionally
 * pipeline tasks (for DAG execution), knowledge modules, and bus events.
 *
 * Modules are loaded by the ModuleRegistry and dispatched by CopilotCore.
 * They work identically across all three execution modes (pipeline, shell, run).
 */

import type { AgentTask } from "../agents/types.js";
import type { AgentRuntime } from "../agent-runtime/types.js";
import type { MessageBus } from "../bus/types.js";
import type { KnowledgeModule } from "../knowledge/types.js";
import type { KuzushiConfig } from "../types.js";

// ---------------------------------------------------------------------------
// Module categories
// ---------------------------------------------------------------------------

/** High-level classification for module capabilities. */
export type ModuleCategory = "offense" | "defense" | "governance" | "intel";

// ---------------------------------------------------------------------------
// Module tool types
// ---------------------------------------------------------------------------

/** JSON Schema type alias — tools declare their input shape this way. */
export type JSONSchema = Record<string, unknown>;

/** Result returned by a tool execution. */
export interface ToolResult {
  /** Whether the tool executed successfully. */
  ok: boolean;
  /** Human-readable output (rendered in shell, included in JSON for run mode). */
  output: string;
  /** Optional structured data (machine-readable, for downstream consumption). */
  data?: unknown;
  /** Optional cost in USD for this tool invocation. */
  costUsd?: number;
}

/** Context provided to every tool execution. */
export interface ToolExecutionContext {
  /** Active workspace ID, if any. */
  workspaceId?: string;
  /** Current target (repo path, host, etc.). */
  target?: string;
  /** The project/scan root directory. */
  cwd: string;
  /** Agent runtime for LLM queries. */
  runtime: AgentRuntime;
  /** Message bus for event coordination. */
  bus: MessageBus;
  /** Full config for reading module-specific settings. */
  config: KuzushiConfig;
  /** Abort signal for cancellation. */
  signal?: AbortSignal;
}

/**
 * A tool exposed by a module — callable from shell mode (via LLM tool dispatch),
 * run mode (direct headless invocation), or pipeline mode (if wrapped as a task).
 */
export interface ModuleTool {
  /** Fully qualified name: "module:action" (e.g. "blackbox:recon"). */
  readonly name: string;
  /** Human-readable description — the LLM reads this to decide when to invoke. */
  readonly description: string;
  /** JSON Schema for the tool's input parameters. */
  readonly inputSchema: JSONSchema;
  /**
   * Whether this tool can run without interactive confirmation.
   * Tools marked headless: true work in all three modes.
   * Tools marked headless: false require shell mode (approval gate in run/pipeline modes).
   */
  readonly headless: boolean;
  /** Execute the tool with validated input. */
  execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult>;
}

// ---------------------------------------------------------------------------
// Module manifest (for external/npm modules)
// ---------------------------------------------------------------------------

/** Requirements that must be satisfied before a module can load. */
export interface ModuleRequirements {
  /** Environment variables that must be set. */
  env?: string[];
  /** CLI binaries that must exist on PATH. */
  bins?: string[];
  /** Minimum Node.js version (e.g. ">=22"). */
  nodeVersion?: string;
}

/** Declarative manifest for a module — lives in module.manifest.json. */
export interface ModuleManifest {
  id: string;
  displayName: string;
  version: string;
  description: string;
  category: ModuleCategory;
  /** Entry point relative to the manifest file. */
  entry: string;
  requires?: ModuleRequirements;
  /** Per-module configuration schema. */
  configSchema?: JSONSchema;
  author?: string;
  license?: string;
}

// ---------------------------------------------------------------------------
// Module context (provided during init)
// ---------------------------------------------------------------------------

/** Context provided to a module during initialization. */
export interface ModuleContext {
  /** Agent runtime for LLM queries. */
  runtime: AgentRuntime;
  /** Message bus for event pub/sub. */
  bus: MessageBus;
  /** Full Kuzushi config. */
  config: KuzushiConfig;
  /** The .kuzushi data directory (for module-specific persistence). */
  dataDir: string;
}

// ---------------------------------------------------------------------------
// CopilotModule — the first-class capability unit
// ---------------------------------------------------------------------------

/**
 * A CopilotModule is a pluggable capability package.
 *
 * Each module exposes:
 * - **tools**: callable from shell (NL dispatch), run mode (headless), or as agent tools
 * - **tasks**: AgentTasks for DAG pipeline execution (optional)
 * - **knowledge**: domain-specific vuln knowledge for triage/detection (optional)
 * - **events**: bus events this module produces/consumes (optional)
 *
 * Modules are loaded from:
 * - Built-in (e.g. the core SAST module)
 * - npm packages (e.g. @kuzushi/blackbox)
 * - Local directories (file:// specifiers)
 * - MCP servers (tools auto-wrapped as ModuleTools)
 */
export interface CopilotModule {
  /** Unique module identifier (e.g. "sast", "blackbox", "honeypot"). */
  readonly id: string;
  /** Human-readable name shown in UI. */
  readonly displayName: string;
  /** Module category for grouping/filtering. */
  readonly category: ModuleCategory;
  /** Semver version string. */
  readonly version: string;
  /** Short description of what the module does. */
  readonly description: string;

  /** Tools exposed by this module. */
  readonly tools: ReadonlyArray<ModuleTool>;

  /** Pipeline tasks contributed by this module (registered in TaskRegistry). */
  readonly tasks?: ReadonlyArray<AgentTask>;

  /** Knowledge modules contributed (registered in KnowledgeRegistry). */
  readonly knowledge?: ReadonlyArray<KnowledgeModule>;

  /** Events this module interacts with. Used for documentation and validation. */
  readonly events?: {
    produces: string[];
    consumes: string[];
  };

  /**
   * Initialize the module with config and runtime context.
   * Called once when the module is loaded. May be async (e.g. to check binary deps).
   */
  init?(config: Record<string, unknown>, ctx: ModuleContext): Promise<void>;

  /**
   * Graceful shutdown — close connections, stop background processes.
   * Called when the copilot session ends or the module is unloaded.
   */
  dispose?(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Module specifier (how modules are referenced for loading)
// ---------------------------------------------------------------------------

/** How a module is referenced for loading. */
export type ModuleSpecifier =
  | { type: "builtin"; id: string }
  | { type: "local"; path: string }
  | { type: "package"; name: string }
  | { type: "mcp"; serverUrl: string };

// ---------------------------------------------------------------------------
// Module registry query types
// ---------------------------------------------------------------------------

/** Summary info for listing modules. */
export interface ModuleInfo {
  id: string;
  displayName: string;
  category: ModuleCategory;
  version: string;
  description: string;
  toolCount: number;
  taskCount: number;
  loaded: boolean;
}

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

import type { AgentRuntime } from "../agent-runtime/types.js";
import type { AgentTask } from "../agents/types.js";
import type { MessageBus } from "../bus/types.js";
import type { PrintSink } from "../copilot/print.js";
import type { KnowledgeModule } from "../knowledge/types.js";
import type { KuzushiConfig } from "../types.js";

// ---------------------------------------------------------------------------
// Module categories
// ---------------------------------------------------------------------------

/** High-level classification for module capabilities. */
export type ModuleCategory = "offense" | "defense" | "governance" | "intel";

// ---------------------------------------------------------------------------
// Module ranking + provenance metadata (msfconsole-inspired)
// ---------------------------------------------------------------------------

/**
 * Reliability/quality tier. Mirrors Metasploit's Rank system so operators have
 * a one-word summary of what to expect. Higher = more reliable/accurate.
 *
 *  - manual    : requires human driving; not safe to automate
 *  - low       : works rarely or only under narrow conditions
 *  - normal    : generic default; no special claims
 *  - good      : reliable in typical conditions
 *  - great     : reliable across platforms/versions
 *  - excellent : production-grade; very high signal
 */
export type ModuleRank = "manual" | "low" | "normal" | "good" | "great" | "excellent";

/** Numeric ordering matching msf::RankingName. */
export const RANK_VALUE: Record<ModuleRank, number> = {
  manual: 0,
  low: 100,
  normal: 300,
  good: 400,
  great: 500,
  excellent: 600,
};

/** External reference on a module/tool/finding — CVE, CWE, URL, ATT&CK, etc. */
export interface ModuleReference {
  type: "CVE" | "CWE" | "URL" | "ATT&CK" | "OSVDB" | "BID" | "EDB" | "KB" | "OWASP";
  value: string;
}

/** Qualitative notes about runtime behavior (msf::Notes). */
export interface ModuleNotes {
  /** stable | crash-safe | crash-service-down — how stable at runtime. */
  stability?: string[];
  /** reliable | unreliable-session | first-attempt — session/tool success profile. */
  reliability?: string[];
  /** artifacts-on-disk | ioc-in-logs | screen-effects — observable side effects. */
  sideEffects?: string[];
}

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
  /**
   * UIStore for Ink rendering. When provided, tools that run pipelines
   * should pass this through so the Ink UI renders progress natively
   * (PipelineIndicator, StatusFooter, etc.) instead of capturing stdout.
   */
  uiStore?: import("../ui/state.js").UIStore;
  /**
   * Pre-computed task outputs to inject into a pipeline run, keyed by task ID.
   * Avoids re-running context tasks when the shell already has a ContextSnapshot.
   */
  seedTaskOutputs?: Map<string, unknown>;
  /**
   * msfconsole-style print helpers. Tools should prefer `ctx.print.status(...)`
   * / `ctx.print.good(...)` / `ctx.print.error(...)` / `ctx.print.warn(...)`
   * over direct console.log so output is consistently tagged and auditable.
   * May be undefined when a tool is invoked outside a shell/run driver.
   */
  print?: PrintSink;
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
  /**
   * Optional reliability tier — defaults to the module's rank if unset.
   * Used by `search rank:...` and `info` output.
   */
  readonly rank?: ModuleRank;
  /** Optional external references specific to this tool. */
  readonly references?: ReadonlyArray<ModuleReference>;
  /** Optional behavioral notes specific to this tool. */
  readonly notes?: ModuleNotes;
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

  /**
   * Reliability tier — inherited by tools that don't override `rank`.
   * Defaults to "normal" when absent.
   */
  readonly rank?: ModuleRank;
  /** Authors (strings or "Name <email>"). */
  readonly authors?: ReadonlyArray<string>;
  /** External references — CVEs, ATT&CK techniques, CWEs, relevant URLs. */
  readonly references?: ReadonlyArray<ModuleReference>;
  /** Disclosure date (ISO YYYY-MM-DD) — relevant for n-day/CVE-tied modules. */
  readonly disclosureDate?: string;
  /** Stability/reliability/side-effect notes. */
  readonly notes?: ModuleNotes;

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
  rank?: ModuleRank;
  references?: ReadonlyArray<ModuleReference>;
  disclosureDate?: string;
}

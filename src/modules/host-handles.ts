/**
 * Narrow host-side handles exposed to modules via `ExecutionContext`.
 *
 * These interfaces intentionally describe only the slice of the underlying
 * host objects (`UIStore`, `Datastore`, `WorkspaceManager`, `ModuleEventBus`)
 * that modules are expected to use. The concrete classes are structurally
 * compatible with these interfaces — they expose the same methods plus more —
 * so passing a `UIStore` instance where a `HostUiHandle` is expected works
 * with no cast. Third-party authors can rely on these narrow shapes without
 * pulling in host-internal types.
 *
 * Design principle: add to these interfaces only when a concrete module needs
 * a new method. Keeping them thin protects third parties from host churn.
 */

// HostUiHandle — minimal UIStore surface

/**
 * Shallow patch object passed to `HostUiHandle.update`. Modules treat this
 * as opaque key/value metadata; the host merges it into its rich `UIState`.
 * Host `UIStore.update(Partial<UIState>)` is structurally compatible because
 * every UIState field is a `Partial<unknown>`.
 */
export type UiStatePatch = Record<string, unknown>;

/**
 * Minimal UIStore surface. Concrete `UIStore` (in `src/ui/state.ts`) is a
 * structural superset of this interface — `getState()` returns the rich
 * `UIState`, but modules that only need string-keyed reads see it via
 * the `unknown` return.
 *
 * Tools use this for two things today:
 *   1. `getState()` to read the current shell phase / surface custom renderers
 *      when the Ink shell is active.
 *   2. `update(partial)` to push a progress-rail entry (repo name, shell
 *      context snapshot, etc.).
 *
 * If your tool needs something beyond these, propose an addition here rather
 * than casting to the concrete class — adding methods is non-breaking.
 */
/**
 * Narrow shape for one row in the ModuleRunView "steps" block. Mirrors the
 * host `ModuleRunStep` (in `src/ui/state.ts`) but re-declared here so the
 * SDK surface stays free of internal UI imports.
 */
export interface ModuleRunStepLike {
  id: string;
  title: string;
  status: "pending" | "running" | "done" | "error";
  count?: string;
  elapsedSeconds?: number;
  error?: string;
}

export interface HostUiHandle {
  /** Read the current UI state. Modules treat the returned value as opaque. */
  getState(): unknown;
  /**
   * Merge `partial` into the current UI state and notify subscribers.
   * `partial` is a shallow patch — matching the host `UIStore.update()` signature.
   */
  update(partial: UiStatePatch): void;
  /**
   * Replace the steps array on the active module run. No-op when no run
   * is currently active (the dispatcher seeds `shell.moduleRun` only for
   * modules with a v3 home renderer).
   *
   * Modules call this to drive the `✓ done / → running / ○ pending` rows
   * in `ModuleRunView`. Idempotent — emit the full list each time.
   */
  setModuleRunSteps?(steps: ReadonlyArray<ModuleRunStepLike>): void;
  /**
   * Patch fields on the active module run (e.g. cost, artifacts). Same
   * no-op semantics as `setModuleRunSteps` when no run is active.
   */
  patchModuleRun?(patch: {
    costUsd?: number;
    artifacts?: ReadonlyArray<{ label: string; path: string; size?: string }>;
  }): void;
}

// ToolOptionStore — minimal Datastore surface

/**
 * Narrow key/value option store exposed to modules. The concrete host
 * `Datastore` (three-layer: global → workspace → module, see
 * `src/copilot/options.ts`) is a superset of this interface — modules only
 * need scalar get/set/has and don't care about scoping.
 *
 * Keys are case-insensitive (the underlying store normalizes to upper-case),
 * matching msfconsole `set FOO bar` semantics.
 */
export interface ToolOptionStore {
  /** Resolve a value, crossing scopes highest-specificity first. */
  get<T = unknown>(key: string): T | undefined;
  /**
   * Store a raw string value. Returns an error message on coercion failure,
   * or `null` on success. Matches `Datastore.set(name, raw)` (scope defaults
   * to module-scope in the host implementation).
   */
  set(key: string, value: string): string | null;
  /** Whether any layer has this key set (doesn't include spec defaults). */
  has(key: string): boolean;
}

// WorkspaceHandle — minimal WorkspaceManager surface

// The individual store types are re-declared here as opaque object types so
// modules can describe them without importing the concrete `better-sqlite3`-
// backed stores. Host `WorkspaceManager` stores satisfy these structurally
// because the parameter shapes are assignable (`object` / record-wider types)
// and the return values are treated as opaque `unknown` on the module side.

/** Opaque handle to workspace-scoped host/service/vuln stores. */
export interface WorkspaceHostStore {
  upsert(input: object): unknown;
  findByAddress?(workspaceId: string, address: string): unknown;
}
export interface WorkspaceServiceStore {
  upsert(input: object): unknown;
}
export interface WorkspaceVulnStore {
  listForWorkspace(workspaceId: string): ReadonlyArray<unknown>;
}
export interface WorkspaceNoteStore {
  create(input: object): unknown;
}

/**
 * Narrow WorkspaceManager surface — the handful of sub-stores plus `rawDb()`
 * that modules actually touch today (`core-recon.ts`, `sast/core-findings.ts`,
 * `sast/core-triage.ts`, etc.). The full host `WorkspaceManager` from
 * `src/workspace/manager.ts` is a superset — passing it where a
 * `WorkspaceHandle` is expected is a safe upcast.
 */
export interface WorkspaceHandle {
  readonly hosts: WorkspaceHostStore;
  readonly services: WorkspaceServiceStore;
  readonly vulns: WorkspaceVulnStore;
  readonly notes: WorkspaceNoteStore;
  /**
   * Escape hatch — raw `better-sqlite3` handle. Typed as `unknown` in the
   * public surface because the sqlite type isn't part of the module SDK
   * contract; host code that needs it casts.
   */
  rawDb(): unknown;
}

// ModuleEventScope — re-export the bus/module-events shape

/**
 * Cross-module pub/sub handle. Concrete implementation lives in
 * `src/bus/module-events.ts`; re-declared here so the public module SDK
 * surface doesn't leak that path.
 *
 * The root `ModuleEventBus.scope(moduleId)` returns an object satisfying
 * this interface — subscriptions made through a scope are torn down on
 * `disposeAll()`.
 */
export type ModuleEventPayload = unknown;
export type ModuleEventHandler = (payload: ModuleEventPayload) => void | Promise<void>;

export interface ModuleEventScope {
  /** Emit an event — all subscribing scopes receive it. */
  emit(type: string, payload?: ModuleEventPayload): void;
  /** Subscribe; returns an unsubscribe closure. */
  on(type: string, handler: ModuleEventHandler): () => void;
  /** One-shot subscribe (auto-removed after first delivery). */
  once(type: string, handler: ModuleEventHandler): () => void;
  /** Tear down every subscription created through this scope. */
  disposeAll(): void;
}

// ToolLogger — optional structured diagnostics surface

/**
 * Lightweight structured logger for module-facing diagnostics. Distinct from
 * `ctx.print` (operator-visible status output) and `ctx.reportActivity`
 * (progress-rail entries) — logger calls are intended for machine-readable
 * events that may be surfaced in a future "module log" panel. Default
 * implementation (when the host provides one) emits to the MessageBus.
 */
export interface ToolLogger {
  info(message: string, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
  error(message: string, meta?: Record<string, unknown>): void;
  debug(message: string, meta?: Record<string, unknown>): void;
}

// HostInfo — capability probe (populated by CopilotCore)

/**
 * The set of host capabilities available at tool-execution time. Strings are
 * intentionally open-ended so new capabilities can be added without a type
 * release — modules call `ctx.host.capabilities.has("workspace")`.
 *
 * Well-known capabilities (populated by `CopilotCore.executeTool`):
 *   "workspace"         — `ctx.workspace` is populated (WorkspaceHandle)
 *   "ui-store"          — `ctx.uiStore` is populated (shell/report-worker path)
 *   "datastore"         — `ctx.datastore` is populated (operator `set`/`setg`)
 *   "print-sink"        — `ctx.print` helpers are wired
 *   "module-events"     — `ctx.events` scope is wired
 *   "structured-output" — runtime supports structured (JSON-schema) output
 *   "tool-model"        — a per-tool model override is active on this call
 */
export type HostCapability =
  | "workspace"
  | "ui-store"
  | "datastore"
  | "print-sink"
  | "module-events"
  | "structured-output"
  | "tool-model"
  | (string & {});

export interface HostInfo {
  /** Semver of the host (kuzushi package) this module is running against. */
  readonly sdkVersion: string;
  /** Capability probe — what the host offers on this specific tool call. */
  readonly capabilities: ReadonlySet<HostCapability>;
}

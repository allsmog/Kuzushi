/**
 * Public testing surface for third-party module authors.
 *
 * Import via: `import { createMockToolContext, assertToolResult } from
 * "kuzushi/testing"`.
 *
 * Goals:
 *   - Let module authors exercise `ModuleTool.execute(input, ctx)` in a unit
 *     test without standing up a real AgentRuntime, MessageBus, workspace
 *     manager, or interactive shell.
 *   - Provide a populated compatibility profile plus faithful per-handle and
 *     headless absence modeling.
 *   - Provide recording stubs (logger, print-sink, event-scope, workspace,
 *     datastore) so tests can assert on side-effects without extra wiring.
 *
 * Every helper is copy-pasteable into a third-party test file; internal
 * host types are never leaked — only the `kuzushi/modules` public surface.
 */

import type { AgentRuntime } from "../agent-runtime/types.js";
import type { MessageBus } from "../bus/types.js";
import type {
  HostInfo,
  HostUiHandle,
  ModuleEventScope,
  RunArtifactStore,
  ToolLogger,
  ToolOptionStore,
  WorkspaceHandle,
} from "../modules/host-handles.js";
import type { ExecutionContext } from "../modules/types.js";
import type { KuzushiConfig } from "../public-types.js";
import { createMockBus } from "./mocks/bus.js";
import { createMockOptionStore } from "./mocks/datastore.js";
import { createMockEventScope } from "./mocks/event-scope.js";
import { createRecordingLogger } from "./mocks/logger.js";
import { createRecordingPrintSink } from "./mocks/print-sink.js";
import { createMockUiStore } from "./mocks/ui-store.js";
import { createMockWorkspace } from "./mocks/workspace.js";

// Defaults

const DEFAULT_CONFIG = {
  model: "anthropic:claude-sonnet-4-6",
  busBackend: "in-process",
  triageBatchSize: 5,
  triageConcurrency: 2,
  scanMode: "concurrent",
  tasks: [] as string[],
  severity: ["ERROR"],
  excludePatterns: [] as string[],
  taskConfig: {},
} as unknown as KuzushiConfig;

const DEFAULT_HOST_CAPABILITIES: ReadonlySet<string> = new Set([
  "workspace",
  "ui-store",
  "datastore",
  "module-events",
  "print-sink",
]);

const HANDLE_CAPABILITIES = [
  ["workspace", "workspace"],
  ["uiStore", "ui-store"],
  ["datastore", "datastore"],
  ["events", "module-events"],
  ["print", "print-sink"],
  ["runArtifacts", "run-artifacts"],
] as const satisfies ReadonlyArray<readonly [keyof ExecutionContext, string]>;

const HEADLESS_ABSENT_FIELDS: ReadonlySet<keyof ExecutionContext> = new Set([
  "runtime",
  "logger",
  "uiStore",
  "datastore",
  "workspace",
  "events",
  "print",
  "reportActivity",
  "reportOutput",
]);

/** Default `HostInfo` for tests. SDK version is `"0.0.0-test"`. */
export function createMockHostInfo(
  overrides: Partial<{ sdkVersion: string; capabilities: Iterable<string> }> = {},
): HostInfo {
  return {
    sdkVersion: overrides.sdkVersion ?? "0.0.0-test",
    capabilities: new Set(overrides.capabilities ?? DEFAULT_HOST_CAPABILITIES),
  };
}

function createContextHost(
  overrides: MockToolContextOverrides,
  context: ExecutionContext,
): HostInfo | undefined {
  if (hasOwn(overrides, "host") && overrides.host === undefined) return undefined;
  const inferred = inferredCapabilities(context);
  if (overrides.host === undefined) return createMockHostInfo({ capabilities: inferred });
  const capabilities = hasOwn(overrides.host, "capabilities")
    ? (overrides.host.capabilities ?? [])
    : inferred;
  const host = createMockHostInfo({ ...overrides.host, capabilities });
  assertCapabilitiesHaveHandles(host, context);
  return host;
}

function inferredCapabilities(context: ExecutionContext): Set<string> {
  const capabilities = new Set<string>();
  for (const [field, capability] of HANDLE_CAPABILITIES) {
    if (context[field] !== undefined) capabilities.add(capability);
  }
  return capabilities;
}

function assertCapabilitiesHaveHandles(host: HostInfo, context: ExecutionContext): void {
  for (const [field, capability] of HANDLE_CAPABILITIES) {
    if (host.capabilities.has(capability) && context[field] === undefined) {
      throw new Error(`createMockToolContext: host capability ${capability} needs ctx.${field}`);
    }
  }
}

// Noop / fake runtimes

/**
 * Async-generator runtime stub — yields nothing. Use for tools that don't
 * invoke the LLM. For tools that do, prefer `createFakeRuntime(responses)`.
 */
export const noopRuntime: AgentRuntime = {
  id: "noop-runtime",
  async *query() {
    // no-op
  },
} as unknown as AgentRuntime;

// createMockToolContext

export type MockToolContextProfile = "default" | "headless";

export type MockToolContextOverrides = Omit<Partial<ExecutionContext>, "config" | "host"> & {
  /** `headless` omits optional runtime/UI/workspace handles unless explicitly overridden. */
  profile?: MockToolContextProfile;
  config?: Partial<KuzushiConfig>;
  host?: Partial<HostInfo>;
};

type ActivityCall = {
  description: string;
  meta?: { phase?: string; step?: number; total?: number };
};

function recordedActivity(description: string, meta: ActivityCall["meta"]): ActivityCall {
  if (meta === undefined) return { description };
  return { description, meta };
}

function buildMockToolContext(
  overrides: MockToolContextOverrides,
  activityCalls: ActivityCall[],
  outputCalls: string[],
): ExecutionContext {
  const recordActivity: NonNullable<ExecutionContext["reportActivity"]> = (description, meta) => {
    activityCalls.push(recordedActivity(description, meta));
  };
  const recordOutput: NonNullable<ExecutionContext["reportOutput"]> = (line) => {
    outputCalls.push(line);
  };
  const { config: _config, host: _host, profile: _profile, ...contextOverrides } = overrides;
  const context: ExecutionContext = {
    ...contextOverrides,
    cwd: overrides.cwd ?? process.cwd(),
    runtime: contextValue(overrides, "runtime", () => noopRuntime),
    bus: contextValue(overrides, "bus", createMockBus),
    config: { ...DEFAULT_CONFIG, ...(overrides.config ?? {}) } as KuzushiConfig,
    logger: contextValue(overrides, "logger", createRecordingLogger),
    uiStore: contextValue(overrides, "uiStore", createMockUiStore),
    datastore: contextValue(overrides, "datastore", createMockOptionStore),
    workspace: contextValue(overrides, "workspace", createMockWorkspace),
    events: contextValue(overrides, "events", createMockEventScope),
    print: contextValue(overrides, "print", createRecordingPrintSink),
    seedTaskOutputs: contextValue(overrides, "seedTaskOutputs", () => new Map<string, unknown>()),
    reportActivity: contextValue(overrides, "reportActivity", () => recordActivity),
    reportOutput: contextValue(overrides, "reportOutput", () => recordOutput),
  };
  context.host = createContextHost(overrides, context);
  return context;
}

function contextValue<K extends keyof ExecutionContext>(
  overrides: MockToolContextOverrides,
  field: K,
  fallback: () => ExecutionContext[K],
): ExecutionContext[K] {
  if (hasOwn(overrides, field)) return overrides[field] as ExecutionContext[K];
  if (overrides.profile === "headless" && HEADLESS_ABSENT_FIELDS.has(field)) {
    return undefined as ExecutionContext[K];
  }
  return fallback();
}

function hasOwn(value: object, field: PropertyKey): boolean {
  return Object.hasOwn(value, field);
}

function attachRecordingBuffers(
  ctx: ExecutionContext,
  overrides: MockToolContextOverrides,
  activityCalls: ActivityCall[],
  outputCalls: string[],
): void {
  if (usesDefault(overrides, "reportActivity")) {
    Object.defineProperty(ctx, "__activityCalls", { value: activityCalls, enumerable: false });
  }
  if (usesDefault(overrides, "reportOutput")) {
    Object.defineProperty(ctx, "__outputCalls", { value: outputCalls, enumerable: false });
  }
}

function usesDefault(overrides: MockToolContextOverrides, field: keyof ExecutionContext): boolean {
  return !hasOwn(overrides, field) && overrides.profile !== "headless";
}

/**
 * Build an `ExecutionContext` for unit tests. The compatibility profile
 * populates common handles; override the pieces your tool actually reads.
 * Pass a handle as `undefined` to model its absence, or use
 * `profile: "headless"` to omit all optional
 * runtime/UI/workspace handles together. Recording stubs (logger,
 * print, uiStore, workspace, datastore, events) are installed by default so
 * tests can `expect(ctx.logger!.records).toContain(...)` with no extra wiring.
 *
 * @example
 *   const ctx = createMockToolContext({
 *     cwd: "/tmp/fixture",
 *     target: "/tmp/fixture",
 *     runtime: createFakeRuntime([{ match: /triage/, output: "ok" }]),
 *   });
 *   const result = await myTool.execute({ arg: 1 }, ctx);
 *   assertToolResult(result, { ok: true });
 */
export function createMockToolContext(overrides: MockToolContextOverrides = {}): ExecutionContext {
  const activityCalls: ActivityCall[] = [];
  const outputCalls: string[] = [];
  const ctx = buildMockToolContext(overrides, activityCalls, outputCalls);
  attachRecordingBuffers(ctx, overrides, activityCalls, outputCalls);
  return ctx;
}

/**
 * Read the default `reportActivity` call log installed by
 * `createMockToolContext`. Returns an empty array when the caller overrode
 * `reportActivity` with a custom spy.
 */
export function getRecordedActivity(
  ctx: ExecutionContext,
): Array<{ description: string; meta?: { phase?: string; step?: number; total?: number } }> {
  return (
    ((ctx as unknown as Record<string, unknown>)["__activityCalls"] as Array<{
      description: string;
      meta?: { phase?: string; step?: number; total?: number };
    }>) ?? []
  );
}

/** Read the default `reportOutput` call log installed by `createMockToolContext`. */
export function getRecordedOutput(ctx: ExecutionContext): string[] {
  return ((ctx as unknown as Record<string, unknown>)["__outputCalls"] as string[]) ?? [];
}

// Re-exports (mocks + assertions + shape helper)

export { assertToolResult, type ToolResultExpectations } from "./assertions.js";
export { createMockBus, type MockMessageBus } from "./mocks/bus.js";
export { createMockOptionStore, type MockToolOptionStore } from "./mocks/datastore.js";
export { createMockEventScope, type MockEventScope } from "./mocks/event-scope.js";
export {
  createRecordingLogger,
  type LogLevel,
  type LogRecord,
  type RecordingLogger,
} from "./mocks/logger.js";
export {
  createRecordingPrintSink,
  type PrintRecord,
  type RecordingPrintSink,
} from "./mocks/print-sink.js";
export {
  createMockRunArtifactStore,
  type MockRunArtifactStore,
  type RunArtifactWrite,
} from "./mocks/run-artifacts.js";
export {
  createFakeRuntime,
  type FakeRuntime,
  type FakeRuntimeResponse,
} from "./mocks/runtime.js";
export { createMockUiStore, type MockHostUiHandle } from "./mocks/ui-store.js";
export { createMockWorkspace, type MockWorkspace } from "./mocks/workspace.js";
export { expectModuleShape, ModuleShapeError } from "./module-shape.js";
export type {
  AgentRuntime,
  ExecutionContext,
  HostInfo,
  HostUiHandle,
  MessageBus,
  ModuleEventScope,
  RunArtifactStore,
  ToolLogger,
  ToolOptionStore,
  WorkspaceHandle,
};

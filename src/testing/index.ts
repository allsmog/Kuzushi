/**
 * Public testing surface for third-party module authors.
 *
 * Import via: `import { createMockToolContext, assertToolResult } from
 * "kuzushi/testing"`.
 *
 * Goals:
 *   - Let module authors exercise `ModuleTool.execute(input, ctx)` in a unit
 *     test without standing up a real AgentRuntime, MessageBus, sqlite
 *     workspace, or Ink shell.
 *   - Cover every field on `ExecutionContext` with a sensible default,
 *     overridable per-test.
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

/** Default `HostInfo` for tests. SDK version is `"0.0.0-test"`. */
export function createMockHostInfo(
  overrides: Partial<{ sdkVersion: string; capabilities: Iterable<string> }> = {},
): HostInfo {
  return {
    sdkVersion: overrides.sdkVersion ?? "0.0.0-test",
    capabilities: new Set(overrides.capabilities ?? DEFAULT_HOST_CAPABILITIES),
  };
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

// MessageBus mock (legacy API — unchanged shape for back-compat)

/**
 * MessageBus stub that records `emit` calls and dispatches to subscribers
 * registered via `subscribe`. The `emit`/`subscribe` pair is a minimal subset
 * of the production `MessageBus.publish`/`subscribe` contract, intentionally
 * narrower — tools that need `publish<E>(envelope)` should wrap payloads
 * themselves.
 *
 * @example
 *   const bus = createMockBus();
 *   bus.subscribe("scan:done", async (p) => console.log(p));
 *   await bus.emit("scan:done", { count: 3 });
 *   expect(bus.emitted).toHaveLength(1);
 */
export function createMockBus(): MessageBus & {
  emitted: Array<{ eventType: string; payload: unknown }>;
} {
  const emitted: Array<{ eventType: string; payload: unknown }> = [];
  const handlers = new Map<string, Array<(event: unknown) => void | Promise<void>>>();

  const emit = async (eventType: string, payload: unknown): Promise<void> => {
    emitted.push({ eventType, payload });
    const fns = handlers.get(eventType) ?? [];
    for (const fn of fns) await fn(payload);
  };

  const bus = {
    emitted,
    emit,
    // Host `MessageBus.publish(envelope)` accepts `{ type, meta, payload }`.
    // The mock accepts the same shape and forwards to `emit`.
    async publish(event: { type: string; payload: unknown }) {
      return emit(event.type, event.payload);
    },
    subscribe(eventType: string, handler: (event: unknown) => void | Promise<void>) {
      const list = handlers.get(eventType) ?? [];
      list.push(handler);
      handlers.set(eventType, list);
    },
    unsubscribe(eventType: string, handler: (event: unknown) => void | Promise<void>) {
      const list = handlers.get(eventType);
      if (!list) return;
      const next = list.filter((fn) => fn !== handler);
      handlers.set(eventType, next);
    },
    async waitFor() {
      throw new Error("createMockBus: waitFor is not implemented");
    },
    async close() {
      handlers.clear();
    },
  } as unknown as MessageBus & {
    emitted: Array<{ eventType: string; payload: unknown }>;
    emit: (eventType: string, payload: unknown) => Promise<void>;
  };

  return bus;
}

// createMockToolContext

export type MockToolContextOverrides = Omit<Partial<ExecutionContext>, "config" | "host"> & {
  config?: Partial<KuzushiConfig>;
  host?: Partial<HostInfo>;
};

/**
 * Build a `ExecutionContext` for unit tests. Every field has a default;
 * override the pieces your tool actually reads. Recording stubs (logger,
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
  const {
    config: configOverrides,
    host: hostOverrides,
    runtime,
    bus,
    logger,
    uiStore,
    datastore,
    workspace,
    events,
    print,
    reportActivity,
    reportOutput,
    seedTaskOutputs,
    runArtifacts,
    ...rest
  } = overrides;

  const activityCalls: Array<{
    description: string;
    meta?: { phase?: string; step?: number; total?: number };
  }> = [];
  const outputCalls: string[] = [];

  const ctx: ExecutionContext = {
    cwd: rest.cwd ?? process.cwd(),
    runtime: runtime ?? noopRuntime,
    bus: bus ?? createMockBus(),
    config: { ...DEFAULT_CONFIG, ...(configOverrides ?? {}) } as KuzushiConfig,
    host: {
      sdkVersion: hostOverrides?.sdkVersion ?? "0.0.0-test",
      capabilities: new Set(hostOverrides?.capabilities ?? DEFAULT_HOST_CAPABILITIES),
    },
    logger: logger ?? createRecordingLogger(),
    uiStore: uiStore ?? createMockUiStore(),
    datastore: datastore ?? createMockOptionStore(),
    workspace: workspace ?? createMockWorkspace(),
    events: events ?? createMockEventScope(),
    print: print ?? createRecordingPrintSink(),
    seedTaskOutputs: seedTaskOutputs ?? new Map<string, unknown>(),
    ...(runArtifacts ? { runArtifacts } : {}),
    reportActivity:
      reportActivity ??
      ((description, meta) => {
        activityCalls.push(meta !== undefined ? { description, meta } : { description });
      }),
    reportOutput:
      reportOutput ??
      ((line) => {
        outputCalls.push(line);
      }),
    ...rest,
  };

  // Attach the recording buffers for default reportActivity/reportOutput onto
  // the context (non-enumerable so they don't leak into object spreads).
  if (!reportActivity) {
    Object.defineProperty(ctx, "__activityCalls", {
      value: activityCalls,
      enumerable: false,
    });
  }
  if (!reportOutput) {
    Object.defineProperty(ctx, "__outputCalls", {
      value: outputCalls,
      enumerable: false,
    });
  }

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

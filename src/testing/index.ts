/**
 * Public testing surface for third-party module authors.
 *
 * Import via: `import { createMockToolContext } from "kuzushi/testing"`.
 *
 * The goal is to let module authors exercise a ModuleTool's `execute(input, ctx)`
 * contract without standing up a real AgentRuntime, MessageBus, or SQLite
 * store. Supply partial overrides for anything you care about; unspecified
 * fields use permissive defaults.
 */

import type { AgentRuntime } from "../agent-runtime/types.js";
import type { MessageBus } from "../bus/types.js";
import type { ToolExecutionContext } from "../modules/types.js";
import type { KuzushiConfig } from "../types.js";

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

/** Async-generator runtime stub — yields nothing. Use for tools that don't invoke the LLM. */
export const noopRuntime: AgentRuntime = {
  // biome-ignore lint/suspicious/useAwait: stub returns an empty async iterator
  async *query() {
    // no-op
  },
} as unknown as AgentRuntime;

/** MessageBus stub that records `emit` calls; useful for asserting published events. */
export function createMockBus(): MessageBus & {
  emitted: Array<{ eventType: string; payload: unknown }>;
} {
  const emitted: Array<{ eventType: string; payload: unknown }> = [];
  const handlers = new Map<string, Array<(event: unknown) => void | Promise<void>>>();

  const bus = {
    emitted,
    async emit(eventType: string, payload: unknown) {
      emitted.push({ eventType, payload });
      const fns = handlers.get(eventType) ?? [];
      for (const fn of fns) await fn(payload);
    },
    subscribe(eventType: string, handler: (event: unknown) => void | Promise<void>) {
      const list = handlers.get(eventType) ?? [];
      list.push(handler);
      handlers.set(eventType, list);
    },
    async close() {
      handlers.clear();
    },
  } as unknown as MessageBus & { emitted: Array<{ eventType: string; payload: unknown }> };

  return bus;
}

export type MockToolContextOverrides = Omit<Partial<ToolExecutionContext>, "config"> & {
  config?: Partial<KuzushiConfig>;
};

/**
 * Build a ToolExecutionContext for unit tests. All fields have defaults;
 * override the pieces your tool actually reads.
 *
 * @example
 *   const ctx = createMockToolContext({
 *     cwd: "/tmp/fixture",
 *     target: "/tmp/fixture",
 *     runtime: myFakeRuntime,
 *   });
 *   await myTool.execute({ arg: 1 }, ctx);
 */
export function createMockToolContext(
  overrides: MockToolContextOverrides = {},
): ToolExecutionContext {
  const { config: configOverrides, runtime, bus, ...rest } = overrides;
  return {
    cwd: rest.cwd ?? process.cwd(),
    runtime: runtime ?? noopRuntime,
    bus: bus ?? createMockBus(),
    config: { ...DEFAULT_CONFIG, ...(configOverrides ?? {}) } as KuzushiConfig,
    ...rest,
  };
}

export type { AgentRuntime, MessageBus, ToolExecutionContext };

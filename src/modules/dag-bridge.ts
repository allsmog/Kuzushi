/**
 * DAG bridge — adapts `DagTool` → `AgentTask` so the existing pipeline
 * orchestrator + TaskRegistry can consume module-forward tools without
 * rewriting their internals during migration.
 *
 * When the plan's module-forward reconciliation completes (Step 4), most of
 * this file disappears — the orchestrator will call `DagTool.run(input, ctx)`
 * directly and the `AgentTask`/`TaskContext` types become internal-only.
 * Until then, this module provides two primitives:
 *
 *   1. `adaptDagToolToAgentTask(mod, tool)` — wraps a DagTool as an AgentTask
 *      whose `run()` converts a TaskContext into an ExecutionContext (with
 *      `ctx.dag` populated) and delegates to the DagTool.
 *   2. `registerDagToolsInTaskRegistry(registry, mod)` — walks a module's
 *      `tools`, filters DagTool instances, and registers the adapters into
 *      the shared TaskRegistry. Guards against re-registration.
 *
 * **Naming convention during migration.** The bridge registers adapters under
 * the *bare module id* (e.g. `mod.id === "threat-hunt"` → task id
 * `"threat-hunt"`) so legacy `AgentTask.dependsOn: ["threat-model-randori"]`
 * references keep working while some tasks are still un-migrated. Authors
 * writing new DagTools should use the same bare id in their `dag.dependsOn`
 * entries. When Step 4 deletes the legacy task layer, both will switch to
 * qualified tool names ("threat-hunt:run") in a single sweep.
 *
 * If a module exposes multiple DagTools, the *first* one is registered under
 * the bare module id; subsequent DagTools are registered under their full
 * qualified name (`module:action`) so both shapes remain resolvable.
 */

import type { TaskRegistry } from "../agents/registry.js";
import type { AgentTask, TaskContext, TaskOutputKind } from "../agents/types.js";
import {
  createPopulatedRegistry,
  getProfileForTask,
  withMultiStrategy,
} from "../strategies/index.js";
import { defineDagTool } from "./define.js";
import type {
  CopilotModule,
  DagTool,
  ExecutionContext,
  ModuleTool,
  ToolExecutionContext,
  ToolResult,
} from "./types.js";
import { isDagTool } from "./types.js";

/**
 * Marker attached to DagTools produced by `exposeAgentTaskAsHiddenDagTool`
 * so `registerDagToolsInTaskRegistry` knows to register the source task
 * under its own id (preserving `dependsOn` chains across the codebase)
 * instead of building a fresh adapter under `module:action`.
 */
const SOURCE_AGENT_TASK = Symbol.for("kuzushi.dag-bridge.sourceAgentTask");
const MULTI_STRATEGY_WRAP = Symbol.for("kuzushi.dag-bridge.multiStrategy");

interface HiddenDagToolInternals {
  [SOURCE_AGENT_TASK]?: AgentTask;
  [MULTI_STRATEGY_WRAP]?: boolean;
}

/**
 * Construct an `ExecutionContext` from a `TaskContext`. The task context
 * carries pipeline-only fields (runId, scan paths, upstreamOutputs); we copy
 * those into the new `ctx.dag` block and fill in shell-side fields
 * (`workspace`, `datastore`, `uiStore`, `print`, `logger`, `reportActivity`,
 * etc.) from the optional `hostOverrides` parameter.
 *
 * During Step 1–3 of the migration, the orchestrator doesn't pass a host
 * overrides bundle — the TaskContext already lacks shell handles, so the
 * resulting ExecutionContext's shell fields stay undefined, which DagTool
 * authors must handle gracefully (they do, because they were written as
 * tasks and already knew they could be invoked without a shell).
 */
export function buildExecutionContextFromTaskContext(
  taskCtx: TaskContext,
  hostOverrides?: Partial<
    Pick<
      ToolExecutionContext,
      | "workspaceId"
      | "target"
      | "uiStore"
      | "seedTaskOutputs"
      | "print"
      | "datastore"
      | "workspace"
      | "events"
      | "toolModel"
      | "reportActivity"
      | "reportOutput"
      | "host"
      | "logger"
      | "resolveOption"
      | "reportAgentActivity"
    >
  >,
): ExecutionContext {
  const scanPath = taskCtx.scanPath ?? taskCtx.workRoot ?? taskCtx.repoRoot;
  return {
    cwd: scanPath,
    target: hostOverrides?.target ?? scanPath,
    runtime: taskCtx.runtime,
    bus: taskCtx.bus,
    config: taskCtx.config,
    ...(taskCtx.signal ? { signal: taskCtx.signal } : {}),
    dag: {
      runId: taskCtx.runId,
      repoRoot: taskCtx.repoRoot,
      ...(taskCtx.workRoot !== undefined ? { workRoot: taskCtx.workRoot } : {}),
      ...(taskCtx.scanPath !== undefined ? { scanPath: taskCtx.scanPath } : {}),
      ...(taskCtx.gitRoot !== undefined ? { gitRoot: taskCtx.gitRoot } : {}),
      repoName: taskCtx.repoName,
      ...(taskCtx.db !== undefined ? { db: taskCtx.db } : {}),
      upstreamOutputs: taskCtx.upstreamOutputs,
    },
    ...(hostOverrides ?? {}),
  };
}

/**
 * Adapt a `DagTool` into an `AgentTask` whose id is the bare module id
 * (so legacy `dependsOn` references keep resolving) and whose `run`
 * converts a TaskContext into an ExecutionContext before delegating.
 *
 * The adapter copies over `condition`, `promptMode`, `toolPolicy`, and
 * `triageAgentConfig` from `tool.dag`. The DagTool's `init` (if any)
 * becomes the AgentTask's `init` — letting scanner-plugin-style
 * per-tool config (semgrep rule paths, codeql database location) survive
 * the migration without losing its one-time-setup semantics.
 */
export function adaptDagToolToAgentTask(
  mod: CopilotModule,
  tool: DagTool,
  options?: { idOverride?: string },
): AgentTask {
  const id = options?.idOverride ?? mod.id;
  const displayName = tool.displayName ?? mod.displayName ?? id;

  const adapter: AgentTask = {
    id,
    displayName,
    outputKind: tool.dag.outputKind as TaskOutputKind,
    dependsOn: [...tool.dag.dependsOn],
    ...(tool.dag.condition ? { condition: tool.dag.condition } : {}),
    ...(tool.dag.promptMode ? { promptMode: tool.dag.promptMode } : {}),
    ...(tool.dag.toolPolicy ? { toolPolicy: tool.dag.toolPolicy } : {}),
    ...(tool.dag.triageAgentConfig ? { triageAgentConfig: tool.dag.triageAgentConfig } : {}),
    ...(tool.init
      ? {
          async init(config) {
            await tool.init?.(config);
          },
        }
      : {}),
    async run(input, context) {
      const execCtx = buildExecutionContextFromTaskContext(context);
      return tool.run(input, execCtx);
    },
  };
  return adapter;
}

/**
 * Install a working `execute()` on a DagTool so shell / `kuzushi run` paths
 * can invoke it through the standard `ModuleTool` contract. The generated
 * wrapper boots the full scan pipeline filtered to this one task — that's
 * what gives the tool context gathering, dependency resolution, upstream
 * output wiring, findings persistence, and cost accounting "for free."
 *
 * `defineDagTool` attaches a placeholder `execute` that throws a descriptive
 * error to surface bugs if a DagTool is invoked before registration. This
 * function replaces that placeholder at module-load time.
 *
 * Scanner-plugin wrappers (semgrep, codeql, agentic-sast, taint-iris) and
 * the full scan pipeline share this path, so shell invocation of
 * `semgrep:scan` spawns the same runPipeline() call the scan CLI uses —
 * just filtered to a single task.
 */
export function wrapDagToolExecute(
  mod: CopilotModule,
  tool: DagTool,
  options?: { registrationId?: string; extraTaskIds?: ReadonlyArray<string> },
): void {
  const registrationId = options?.registrationId ?? mod.id;
  const extraTaskIds =
    options?.extraTaskIds ??
    (tool.dag.chainBefore && tool.dag.chainBefore.length > 0 ? tool.dag.chainBefore : []);
  // Prepend extras so upstream chain-before tasks visually come first in
  // logs; orchestrator's resolveOrder() topologically re-sorts regardless.
  const taskIds = [...extraTaskIds, registrationId];
  const summaryLabel = tool.displayName ?? mod.displayName ?? mod.id;

  // Mutate the tool in place so the CopilotRegistry / Shell see the
  // installed execute without needing to track a second registration.
  (tool as { execute: ModuleTool["execute"] }).execute = async (
    input: unknown,
    ctx: ToolExecutionContext,
  ): Promise<ToolResult> => {
    const { runSingleTaskPipeline } = await import("./sast/shared.js");
    return runSingleTaskPipeline(taskIds, input, ctx, { summaryLabel });
  };
}

/**
 * Build a hidden DagTool that wraps an existing `AgentTask`. The source
 * task's body runs unchanged through `TaskRegistry`; the DagTool simply
 * exposes the task on a `CopilotModule.tools[]` for module-system
 * discoverability (counts, catalog rendering, `/use` overview filtering).
 *
 * Hidden DagTools are excluded from shell search, LLM dispatch lists, and
 * module overviews — operators never invoke them directly. The orchestrator
 * still resolves `dependsOn` chains against the source task's id.
 *
 * Pass `multiStrategy: true` when the source task is eligible for
 * `withMultiStrategy` wrapping; the bridge applies the wrapper at
 * registration time so modules don't need to reach into the strategy
 * registry themselves.
 */
export function exposeAgentTaskAsHiddenDagTool<Id extends string>(
  task: AgentTask,
  options: {
    moduleId: Id;
    description?: string;
    multiStrategy?: boolean;
  },
): DagTool<Id> {
  const tool = defineDagTool<Id>({
    name: `${options.moduleId}:${task.id}` as `${Id}:${string}`,
    displayName: task.displayName,
    description: options.description ?? `Internal DAG node: ${task.displayName}.`,
    headless: true,
    hidden: true,
    inputSchema: {
      type: "object",
      additionalProperties: true,
    },
    dag: {
      outputKind: task.outputKind,
      dependsOn: [...task.dependsOn],
      ...(task.condition ? { condition: task.condition } : {}),
      ...(task.promptMode ? { promptMode: task.promptMode } : {}),
      ...(task.toolPolicy ? { toolPolicy: task.toolPolicy } : {}),
      ...(task.triageAgentConfig ? { triageAgentConfig: task.triageAgentConfig } : {}),
    },
    ...(task.init
      ? {
          async init(config) {
            await task.init?.(config);
          },
        }
      : {}),
    async run(input, ctx: ExecutionContext) {
      const taskCtx = buildTaskContextFromExecutionContext(ctx);
      return task.run(input, taskCtx);
    },
  });

  const internals = tool as DagTool<Id> & HiddenDagToolInternals;
  internals[SOURCE_AGENT_TASK] = task;
  if (options.multiStrategy) internals[MULTI_STRATEGY_WRAP] = true;

  return tool;
}

/**
 * Reverse of `buildExecutionContextFromTaskContext` — reconstructs a
 * TaskContext from an ExecutionContext's `dag` block. Used by hidden
 * DagTool wrappers that delegate to a source AgentTask's run body.
 * Callers must have already asserted the presence of `ctx.dag`.
 */
function buildTaskContextFromExecutionContext(ctx: ExecutionContext): TaskContext {
  if (!ctx.dag) {
    throw new Error(
      "Hidden DagTool invoked without a DAG context. Hidden DAG nodes only run through the scan pipeline.",
    );
  }
  const dag = ctx.dag;
  return {
    runId: dag.runId,
    repoRoot: dag.repoRoot,
    ...(dag.workRoot !== undefined ? { workRoot: dag.workRoot } : {}),
    ...(dag.scanPath !== undefined ? { scanPath: dag.scanPath } : {}),
    ...(dag.gitRoot !== undefined ? { gitRoot: dag.gitRoot } : {}),
    repoName: dag.repoName,
    ...(dag.db !== undefined ? { db: dag.db } : {}),
    config: ctx.config,
    runtime: ctx.runtime,
    bus: ctx.bus,
    upstreamOutputs: dag.upstreamOutputs as Map<string, unknown>,
    ...(ctx.signal ? { signal: ctx.signal } : {}),
  };
}

/**
 * Walk a module's `tools` array, pick out DagTool instances, and register
 * each one as an AgentTask in the shared TaskRegistry. The first *visible*
 * DagTool wins the bare module id; subsequent visible DagTools register
 * under their qualified `module:action` name. Hidden DagTools that wrap an
 * existing AgentTask (via `exposeAgentTaskAsHiddenDagTool`) register the
 * source task directly under its own id so cross-task `dependsOn`
 * references stay valid.
 *
 * Also installs a working `execute()` on every DagTool (replacing the
 * placeholder `defineDagTool` attaches) so shell / run mode can invoke
 * them through the normal `ModuleTool` contract. Hidden wrappers skip this
 * step — operators can't invoke them directly.
 *
 * Silently skips tools that already have a registered entry so callers
 * can invoke this unconditionally from `ModuleRegistry.loadModule`.
 */
export function registerDagToolsInTaskRegistry(registry: TaskRegistry, mod: CopilotModule): void {
  let seenForBareId = false;
  for (const tool of mod.tools as ReadonlyArray<ModuleTool>) {
    if (!isDagTool(tool)) continue;

    const internals = tool as DagTool & HiddenDagToolInternals;
    const sourceTask = internals[SOURCE_AGENT_TASK];
    if (sourceTask) {
      // Hidden wrappers of existing AgentTasks: register the source task
      // directly under its own id (preserves dependsOn chains) and skip
      // the execute-wrapper installation (they're hidden from shell/run).
      if (!registry.has(sourceTask.id)) {
        const toRegister = internals[MULTI_STRATEGY_WRAP]
          ? applyMultiStrategyWrap(sourceTask)
          : sourceTask;
        registry.register(toRegister);
      }
      continue;
    }

    const id = !seenForBareId ? mod.id : tool.name;
    seenForBareId = true;

    // Install the shell/run-mode execute wrapper regardless of whether the
    // task registry already has an entry for this id — operators still need
    // a working execute() on the CopilotModule side. `chainBefore` is
    // read from `tool.dag` automatically.
    wrapDagToolExecute(mod, tool, { registrationId: id });

    if (registry.has(id)) continue;
    const adapter = adaptDagToolToAgentTask(mod, tool, { idOverride: id });
    registry.register(adapter);
  }
}

/**
 * Lazy-initialised per-process strategy registry. Only constructed the
 * first time a hidden DagTool with `multiStrategy: true` registers, so
 * modules that never request strategy wrapping don't pay the cost.
 */
let cachedStrategyRegistry: ReturnType<typeof createPopulatedRegistry> | undefined;
function applyMultiStrategyWrap(task: AgentTask): AgentTask {
  const profile = getProfileForTask(task.id);
  if (!profile) return task;
  if (!cachedStrategyRegistry) cachedStrategyRegistry = createPopulatedRegistry();
  const registryRef = cachedStrategyRegistry;
  return withMultiStrategy(
    task as AgentTask<unknown, unknown>,
    profile,
    () => registryRef,
  ) as AgentTask;
}

import { isRecord } from "../utils.js";
import type { CopilotModule, DagTool, ExecutionContext, ModuleTool, ToolResult } from "./types.js";
import { isDagTool } from "./types.js";

const PIPELINE_CONTROL_INPUT_KEYS = new Set([
  "target",
  "tasks",
  "taskMode",
  "disabledTasks",
  "severity",
  "excludePatterns",
  "fresh",
  "resume",
]);

function extractTaskConfigFromInput(tool: DagTool, input: unknown): Record<string, unknown> {
  if (!isRecord(input)) return {};
  const properties = isRecord(tool.inputSchema["properties"]) ? tool.inputSchema["properties"] : {};
  const allowedKeys = new Set(Object.keys(properties));
  const taskConfig: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(input)) {
    if (!allowedKeys.has(key) || PIPELINE_CONTROL_INPUT_KEYS.has(key)) continue;
    if (value !== undefined) taskConfig[key] = value;
  }

  return taskConfig;
}

function buildTaskConfigOverrides(
  tool: DagTool,
  taskIds: string[],
  input: unknown,
  ctx: ExecutionContext,
): Record<string, Record<string, unknown>> | undefined {
  const perTask = {
    ...extractTaskConfigFromInput(tool, input),
    ...(ctx.toolModel ? { model: ctx.toolModel } : {}),
  };
  if (Object.keys(perTask).length === 0) return undefined;
  return Object.fromEntries(taskIds.map((taskId) => [taskId, perTask]));
}

/**
 * Install a working `execute()` on a DagTool so shell / `kuzushi run` paths
 * can invoke it through the standard `ModuleTool` contract. The generated
 * wrapper boots the full scan pipeline filtered to this one task.
 */
export function wrapDagToolExecute(
  mod: CopilotModule,
  tool: DagTool,
  options?: { registrationId?: string; extraTaskIds?: ReadonlyArray<string> },
): void {
  const registrationId = options?.registrationId ?? tool.name;
  const extraTaskIds =
    options?.extraTaskIds ??
    (tool.dag.chainBefore && tool.dag.chainBefore.length > 0 ? tool.dag.chainBefore : []);
  const taskIds = [...extraTaskIds, registrationId];
  const summaryLabel = tool.displayName ?? mod.displayName ?? mod.id;

  (tool as { execute: ModuleTool["execute"] }).execute = async (
    input: unknown,
    ctx: ExecutionContext,
  ): Promise<ToolResult> => {
    const { runSingleTaskPipeline } = await import("./sast/pipeline-runner.js");
    const taskConfig = buildTaskConfigOverrides(tool, taskIds, input, ctx);
    const configOverrides =
      tool.runLifecycle?.pipelineContext === "none"
        ? {
            enableContextGathering: false,
            enableContextEnrichment: false,
          }
        : undefined;
    return runSingleTaskPipeline(taskIds, input, ctx, {
      summaryLabel,
      ...(taskConfig ? { taskConfig } : {}),
      ...(configOverrides ? { configOverrides } : {}),
    });
  };
}

/**
 * Install execute wrappers for visible DagTools. Hidden wrappers are pipeline
 * internals and remain non-invokable from shell/run mode.
 */
export function installDagToolExecuteWrappers(mod: CopilotModule): void {
  for (const tool of mod.tools as ReadonlyArray<ModuleTool>) {
    if (!isDagTool(tool) || tool.hidden) continue;
    wrapDagToolExecute(mod, tool, { registrationId: tool.name });
  }
}

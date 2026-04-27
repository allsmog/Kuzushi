import type { CopilotModule, DagTool, ExecutionContext, ModuleTool, ToolResult } from "./types.js";
import { isDagTool } from "./types.js";

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
  const registrationId = options?.registrationId ?? mod.id;
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
    const taskConfig = ctx.toolModel
      ? Object.fromEntries(taskIds.map((taskId) => [taskId, { model: ctx.toolModel }]))
      : undefined;
    return runSingleTaskPipeline(taskIds, input, ctx, {
      summaryLabel,
      ...(taskConfig ? { taskConfig } : {}),
    });
  };
}

/**
 * Install execute wrappers for visible DagTools. Hidden wrappers are pipeline
 * internals and remain non-invokable from shell/run mode.
 */
export function installDagToolExecuteWrappers(mod: CopilotModule): void {
  let seenForBareId = false;
  for (const tool of mod.tools as ReadonlyArray<ModuleTool>) {
    if (!isDagTool(tool) || tool.hidden) continue;
    const id = !seenForBareId ? mod.id : tool.name;
    seenForBareId = true;
    wrapDagToolExecute(mod, tool, { registrationId: id });
  }
}

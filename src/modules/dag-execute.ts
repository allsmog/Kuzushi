import type { CopilotModule, DagTool, ModuleTool, ToolResult } from "./types.js";
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
  const registrationId = options?.registrationId ?? tool.name;
  const summaryLabel = tool.displayName ?? mod.displayName ?? mod.id;

  (tool as { execute: ModuleTool["execute"] }).execute = async (): Promise<ToolResult> => {
    return {
      ok: false,
      output: `${summaryLabel} (${registrationId}) is a module-owned DAG tool. TypeScript single-task pipeline execution was retired with the TS runtime island; use the Rust CLI/TUI scan path or call the tool's DagTool.run() from a DAG host.`,
    };
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

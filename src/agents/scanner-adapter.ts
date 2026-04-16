import type { Finding, ScannerPlugin } from "../scanners/types.js";
import type { ScanOpts } from "../types.js";
import type { AgentTask } from "./types.js";

/** Wrap a ScannerPlugin as a generic AgentTask<ScanOpts, Finding[]>. */
export function adaptScannerPlugin(plugin: ScannerPlugin): AgentTask<ScanOpts, Finding[]> {
  return {
    id: plugin.id,
    displayName: plugin.displayName,
    outputKind: "findings",
    dependsOn: [],
    async run(opts, context) {
      const pluginConfig = context.config.taskConfig[plugin.id] ?? {};
      return plugin.scan(
        context.scanPath ?? context.repoRoot,
        opts,
        pluginConfig,
        context.runtime,
        {
          bus: context.bus,
          taskId: plugin.id,
          runId: context.runId,
          runContext: {
            runId: context.runId,
            repoRoot: context.scanPath ?? context.repoRoot,
            scanPath: context.scanPath,
            repoName: context.repoName,
            dbPath: context.dbPath ?? "",
          },
        },
      );
    },
    init: plugin.init ? async (config) => plugin.init?.(config) : undefined,
    triageAgentConfig: plugin.triageAgentConfig,
  };
}

import type { ScanOpts } from "../types.js";
import type { Finding, ScannerPlugin } from "../scanners/types.js";
import type { AgentTask } from "./types.js";

/** Wrap a ScannerPlugin as a generic AgentTask<ScanOpts, Finding[]>. */
export function adaptScannerPlugin(plugin: ScannerPlugin): AgentTask<ScanOpts, Finding[]> {
  return {
    id: plugin.id,
    displayName: plugin.displayName,
    outputKind: "findings",
    dependsOn: [],
    async run(opts, context) {
      const pluginConfig = context.config.scannerConfig[plugin.id] ?? {};
      return plugin.scan(context.repoRoot, opts, pluginConfig);
    },
    init: plugin.init
      ? async (config) => plugin.init?.(config)
      : undefined,
    triageAgentConfig: plugin.triageAgentConfig,
  };
}

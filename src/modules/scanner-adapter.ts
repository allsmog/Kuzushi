/**
 * Adapter that turns a `ScannerPlugin` into a DagTool on a CopilotModule.
 *
 * Scanner plugins (Semgrep, CodeQL, Agentic) implement a common contract:
 *   - `init(config)` — one-time setup from module config (binary paths, flags).
 *   - `scan(repoRoot, opts, config, runtime, scanContext)` → `Finding[]`.
 *   - `triageAgentConfig(finding, repoName)` — per-finding triage prompt.
 *
 * This adapter wraps that contract as a `DagTool`, hoisting the per-plugin
 * state into a closure so `init()` and `run()` can share it. The DagTool's
 * `run()` does the scan; the module registry installs a shell-mode
 * `execute()` that re-enters the pipeline filtered to this one task.
 *
 * Authors writing a new scanner module just call
 * `buildScannerDagTool(new MyPlugin(), { name: "my:scan", ... })` — see the
 * three scanner modules in `src/modules/{semgrep,codeql,agentic-sast}/` for
 * the canonical call sites.
 */

import type { Finding, ScannerPlugin, TaskConfig } from "../scanners/types.js";
import type { ScanOpts } from "../types.js";
import { defineDagTool } from "./define.js";
import type { DagTool, ExecutionContext } from "./types.js";
import { requireDag } from "./types.js";

export interface ScannerDagToolSpec<Id extends string> {
  name: `${Id}:${string}`;
  displayName: string;
  description: string;
  inputSchema: DagTool["inputSchema"];
  rank?: DagTool["rank"];
  headless?: boolean;
}

const resumeProperty = {
  type: ["boolean", "string"],
  description: "Resume the latest checkpoint or a specific run id.",
};

function withResumeProperty(schema: DagTool["inputSchema"]): DagTool["inputSchema"] {
  const properties =
    schema.properties && typeof schema.properties === "object" && !Array.isArray(schema.properties)
      ? (schema.properties as Record<string, unknown>)
      : {};
  return {
    ...schema,
    properties: {
      ...properties,
      resume: resumeProperty,
    },
  };
}

/**
 * Build a DagTool backed by a `ScannerPlugin`. The closure over
 * `state` lets `init` and `run` share the per-module-load plugin instance.
 */
export function buildScannerDagTool<Id extends string>(
  plugin: ScannerPlugin,
  spec: ScannerDagToolSpec<Id>,
): DagTool<Id, ScanOpts, Finding[]> {
  const state = { taskConfig: {} as TaskConfig };

  return defineDagTool<Id, ScanOpts, Finding[]>({
    name: spec.name,
    displayName: spec.displayName,
    description: spec.description,
    headless: spec.headless ?? true,
    runLifecycle: {
      persistence: "pipeline-checkpoint",
      resume: "checkpoint",
      liveControl: "pause-resume",
      pipelineTasks: [spec.name],
    },
    ...(spec.rank ? { rank: spec.rank } : {}),
    formatInput(input) {
      const p = input as Record<string, unknown> | undefined;
      return typeof p?.["target"] === "string" ? (p["target"] as string) : null;
    },
    renderResult(result) {
      const first = result.output.split("\n", 1)[0]?.trim();
      return first && first.length > 0 ? first : null;
    },
    inputSchema: withResumeProperty(spec.inputSchema),
    dag: {
      outputKind: "findings",
      dependsOn: [],
      triageAgentConfig: (finding, repoName) => plugin.triageAgentConfig(finding, repoName),
    },
    async init(moduleConfig) {
      state.taskConfig = moduleConfig as TaskConfig;
      await plugin.init?.(state.taskConfig);
    },
    async run(input: ScanOpts, ctx: ExecutionContext): Promise<Finding[]> {
      const dag = requireDag(ctx);
      const repoRoot = dag.scanPath ?? dag.workRoot ?? dag.repoRoot;
      return plugin.scan(repoRoot, input, state.taskConfig, ctx.runtime, {
        bus: ctx.bus,
        taskId: plugin.id,
        runId: dag.runId,
        signal: ctx.signal,
        runContext: {
          runId: dag.runId,
          repoRoot: dag.workRoot ?? dag.repoRoot,
          ...(dag.scanPath ? { scanPath: dag.scanPath } : {}),
          repoName: dag.repoName,
          dbPath: "",
        },
      });
    },
  });
}

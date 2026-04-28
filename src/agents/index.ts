import type { KuzushiConfig } from "../types.js";
import { TaskRegistry } from "./registry.js";

/**
 * Create a task registry populated by every built-in CopilotModule that
 * ships scan-DAG participants.
 *
 * Historically, this function imported ~40 individual AgentTask exports and
 * registered each one. After the module-forward reconciliation, every
 * DAG-capable task lives inside a `CopilotModule` — either as a visible
 * `DagTool` or a hidden `DagTool` wrapper over a legacy AgentTask body.
 * We invoke each module factory and pipe its tools through the bridge
 * (`registerDagToolsInTaskRegistry`) to get the same TaskRegistry shape as
 * before, without the 40-line import list.
 *
 * Scan mode (`kuzushi scan`) and headless task introspection (`kuzushi task
 * list`) call this directly. Shell/run mode builds its registry the same
 * way via `CopilotCore.init()` — both paths converge on the bridge's
 * `registerDagToolsInTaskRegistry`.
 */
export async function createDefaultTaskRegistry(
  _config?: KuzushiConfig,
  _repoRoot?: string,
  options: { excludeBuiltinModules?: string[] } = {},
): Promise<TaskRegistry> {
  const tasks = new TaskRegistry();

  // Deferred imports keep this module's dependency footprint small
  // (task-list / task-info CLI commands don't pull in the whole scan stack
  // unless they explicitly call this factory). The module factories below
  // are all synchronous — the `await import` is only paying the one-time
  // lazy-load cost.
  const { registerDagToolsInTaskRegistry } = await import("../modules/dag-bridge.js");
  const { createAgenticSastModule } = await import("../modules/agentic-sast/agentic-sast.js");
  const { createCodeqlModule } = await import("../modules/codeql/codeql.js");
  const { createContextModule } = await import("../modules/context/context.js");
  const { createPipelineModule } = await import("../modules/pipeline/pipeline.js");
  const { createCoreRandoriModule } = await import("../modules/randori/randori.js");
  const { createSemgrepModule } = await import("../modules/semgrep/semgrep.js");
  const { createSystemsHuntModule } = await import("../modules/systems-hunt/systems-hunt.js");
  const { createThreatHuntModule } = await import("../modules/threat-hunt/threat-hunt.js");
  const { createCoreTobModule } = await import("../modules/tob/tob.js");
  const { createCoreVulnScoutModule } = await import("../modules/vuln-scout/vuln-scout.js");

  const dagModules = [
    createContextModule(),
    createPipelineModule(),
    createSemgrepModule(),
    createCodeqlModule(),
    createAgenticSastModule(),
    createThreatHuntModule(),
    createSystemsHuntModule(),
    createCoreRandoriModule(),
    createCoreTobModule(),
    createCoreVulnScoutModule(),
  ];

  // Symmetric with `kuzushi shell --exclude` — drop modules the
  // operator explicitly opted out of (e.g. `codeql` when its CLI
  // binary isn't installed). Field-test issue #40.
  const excluded = new Set(options.excludeBuiltinModules ?? []);
  const filtered = excluded.size > 0 ? dagModules.filter((m) => !excluded.has(m.id)) : dagModules;

  for (const mod of filtered) {
    registerDagToolsInTaskRegistry(tasks, mod);
  }

  return tasks;
}

export * from "./registry.js";
export * from "./types.js";

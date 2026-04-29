import { DagRegistry } from "../modules/dag-registry.js";
import type { KuzushiConfig } from "../types.js";

/** Create the default scan DAG registry from built-in CopilotModules. */
export async function createDefaultDagRegistry(
  _config?: KuzushiConfig,
  _repoRoot?: string,
  options: { excludeBuiltinModules?: string[] } = {},
): Promise<DagRegistry> {
  const tasks = new DagRegistry();

  // Deferred imports keep this module's dependency footprint small
  // (task-list / task-info CLI commands don't pull in the whole scan stack
  // unless they explicitly call this factory). The module factories below
  // are all synchronous — the `await import` is only paying the one-time
  // lazy-load cost.
  const { registerDagToolsInDagRegistry } = await import("../modules/dag-registry.js");
  const { createAgenticSastModule } = await import("../modules/agentic-sast/agentic-sast.js");
  const { createCodeqlModule } = await import("../modules/codeql/codeql.js");
  const { createContextModule } = await import("../modules/context/context.js");
  const { createPipelineModule } = await import("../modules/pipeline/pipeline.js");
  const { createSemgrepModule } = await import("../modules/semgrep/semgrep.js");
  const { createSystemsHuntModule } = await import("../modules/systems-hunt/systems-hunt.js");
  const { createTaintIrisModule } = await import("../modules/taint-iris/taint-iris.js");
  const { createCarliniThreatHuntModule } = await import(
    "../modules/carlini-threat-hunt/carlini-threat-hunt.js"
  );
  const { createThreatModelModule } = await import("../modules/threat-model/threat-model.js");
  const { createCoreTobModule } = await import("../modules/tob/tob.js");
  const { createCoreVulnScoutModule } = await import("../modules/vuln-scout/vuln-scout.js");

  const dagModules = [
    createContextModule(),
    createPipelineModule(),
    createSemgrepModule(),
    createCodeqlModule(),
    createAgenticSastModule(),
    createTaintIrisModule(),
    createCarliniThreatHuntModule(),
    createThreatModelModule(),
    createSystemsHuntModule(),
    createCoreTobModule(),
    createCoreVulnScoutModule(),
  ];

  // Symmetric with `kuzushi shell --exclude` — drop modules the
  // operator explicitly opted out of (e.g. `codeql` when its CLI
  // binary isn't installed). Field-test issue #40.
  const excluded = new Set(options.excludeBuiltinModules ?? []);
  const filtered = excluded.size > 0 ? dagModules.filter((m) => !excluded.has(m.id)) : dagModules;

  for (const mod of filtered) {
    registerDagToolsInDagRegistry(tasks, mod);
  }

  return tasks;
}

export * from "./types.js";

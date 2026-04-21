/**
 * Regression coverage for task planning — specifically the "single-task
 * dispatch (e.g. `/threat-hunt run .`) shouldn't pull in the ambient
 * `config.tasks` baseline" contract that shared.ts relies on.
 */
import { describe, expect, it } from "vitest";
import { TaskRegistry } from "../../../src/agents/registry.js";
import type { AgentTask } from "../../../src/agents/types.js";
import { resolveInitialTaskPlan } from "../../../src/bus/orchestrator/task-policy.js";

type AnyTask = AgentTask<unknown, unknown>;

function stubTask(id: string, dependsOn: string[] = []): AnyTask {
  return {
    id,
    displayName: id,
    outputKind: "findings",
    dependsOn,
    run: async () => [],
  } as unknown as AnyTask;
}

function makeRegistry(tasks: AnyTask[]): TaskRegistry {
  const reg = new TaskRegistry();
  for (const t of tasks) reg.register(t);
  return reg;
}

describe("resolveInitialTaskPlan", () => {
  it("merges `config.tasks` into the candidate list when tasks arg is empty", () => {
    const registry = makeRegistry([stubTask("semgrep"), stubTask("threat-hunt")]);
    const plan = resolveInitialTaskPlan(registry, [], {
      tasks: ["semgrep"],
      enableContextGathering: false,
      enableContextEnrichment: false,
      enableDynamicTaskSelection: false,
    });
    expect(plan.enabledTaskIds).toContain("semgrep");
  });

  it("merges both the explicit `tasks` arg AND `config.tasks` — leak scenario", () => {
    // This is the historical bug's mechanism: a caller passes an explicit
    // task list but the ambient config.tasks also feeds in, so running
    // threat-hunt alone also pulls in semgrep from config defaults.
    const registry = makeRegistry([stubTask("semgrep"), stubTask("threat-hunt")]);
    const plan = resolveInitialTaskPlan(registry, ["threat-hunt"], {
      tasks: ["semgrep"],
      enableContextGathering: false,
      enableContextEnrichment: false,
      enableDynamicTaskSelection: false,
    });
    expect(plan.enabledTaskIds).toContain("threat-hunt");
    expect(plan.enabledTaskIds).toContain("semgrep");
  });

  it("when `config.tasks` is empty, single-task dispatch runs only the explicit task + its deps", () => {
    // This is the post-fix behavior: shared.ts clears config.tasks when
    // the caller pinned an explicit task list, so no baseline leak.
    const registry = makeRegistry([
      stubTask("semgrep"),
      stubTask("threat-model-randori"),
      stubTask("threat-hunt", ["threat-model-randori"]),
    ]);
    const plan = resolveInitialTaskPlan(registry, ["threat-hunt"], {
      tasks: [],
      enableContextGathering: false,
      enableContextEnrichment: false,
      enableDynamicTaskSelection: false,
    });
    expect(plan.enabledTaskIds).toContain("threat-hunt");
    expect(plan.enabledTaskIds).toContain("threat-model-randori");
    expect(plan.enabledTaskIds).not.toContain("semgrep");
  });

  it("pulls in context-gatherer when enableContextGathering is true", () => {
    const registry = makeRegistry([stubTask("context-gatherer"), stubTask("threat-hunt")]);
    const plan = resolveInitialTaskPlan(registry, ["threat-hunt"], {
      tasks: [],
      enableContextGathering: true,
      enableContextEnrichment: false,
      enableDynamicTaskSelection: false,
    });
    expect(plan.enabledTaskIds).toContain("context-gatherer");
  });

  it("expands `*` as configuredTasks to include every registered task", () => {
    const registry = makeRegistry([
      stubTask("semgrep"),
      stubTask("codeql"),
      stubTask("threat-hunt"),
    ]);
    const plan = resolveInitialTaskPlan(registry, [], {
      tasks: ["*"],
      enableContextGathering: false,
      enableContextEnrichment: false,
      enableDynamicTaskSelection: false,
    });
    expect(plan.useAllTasks).toBe(true);
    expect(new Set(plan.enabledTaskIds)).toEqual(new Set(["semgrep", "codeql", "threat-hunt"]));
  });

  it("does NOT inject task-selector when enableDynamicTaskSelection is false", () => {
    // Regression: /use threat-hunt; run . had the shell's
    // executeSastPipeline clamp config.tasks=[] but leave dynamic
    // selection on, so resolveInitialTaskPlan still added task-selector
    // which then merged detectors like secrets-crypto-detect into the
    // run. Lock in that the flag alone is sufficient to keep the
    // selector out.
    const registry = makeRegistry([
      stubTask("task-selector"),
      stubTask("threat-hunt"),
      stubTask("secrets-crypto-detect"),
    ]);
    const plan = resolveInitialTaskPlan(registry, ["threat-hunt"], {
      tasks: [],
      enableContextGathering: false,
      enableContextEnrichment: false,
      enableDynamicTaskSelection: false,
    });
    expect(plan.enabledTaskIds).toContain("threat-hunt");
    expect(plan.enabledTaskIds).not.toContain("task-selector");
    expect(plan.enabledTaskIds).not.toContain("secrets-crypto-detect");
    expect(plan.dynamicSelectionActive).toBe(false);
  });
});

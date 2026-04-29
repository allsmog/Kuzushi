/**
 * Regression coverage for task planning — specifically the "single-task
 * dispatch (e.g. `/carlini-threat-hunt run .`) shouldn't pull in the ambient
 * `config.tasks` baseline" contract that shared.ts relies on.
 */
import { describe, expect, it } from "vitest";
import type { DagNodeImpl } from "../../../src/agents/types.js";
import { resolveInitialTaskPlan } from "../../../src/bus/orchestrator/task-policy.js";
import { DagRegistry } from "../../../src/modules/dag-registry.js";

type AnyTask = DagNodeImpl<unknown, unknown>;

function stubTask(id: string, dependsOn: string[] = []): AnyTask {
  return {
    id,
    displayName: id,
    outputKind: "findings",
    dependsOn,
    run: async () => [],
  } as unknown as AnyTask;
}

function makeRegistry(tasks: AnyTask[]): DagRegistry {
  const reg = new DagRegistry();
  for (const t of tasks) reg.register(t);
  return reg;
}

describe("resolveInitialTaskPlan", () => {
  it("merges `config.tasks` into the candidate list when tasks arg is empty", () => {
    const registry = makeRegistry([stubTask("semgrep:scan"), stubTask("carlini-threat-hunt:run")]);
    const plan = resolveInitialTaskPlan(registry, [], {
      tasks: ["semgrep:scan"],
      enableContextGathering: false,
      enableContextEnrichment: false,
      enableDynamicTaskSelection: false,
    });
    expect(plan.enabledTaskIds).toContain("semgrep:scan");
  });

  it("merges both the explicit `tasks` arg AND `config.tasks` — leak scenario", () => {
    // This is the historical bug's mechanism: a caller passes an explicit
    // task list but the ambient config.tasks also feeds in, so running
    // carlini-threat-hunt alone also pulls in semgrep from config defaults.
    const registry = makeRegistry([stubTask("semgrep:scan"), stubTask("carlini-threat-hunt:run")]);
    const plan = resolveInitialTaskPlan(registry, ["carlini-threat-hunt:run"], {
      tasks: ["semgrep:scan"],
      enableContextGathering: false,
      enableContextEnrichment: false,
      enableDynamicTaskSelection: false,
    });
    expect(plan.enabledTaskIds).toContain("carlini-threat-hunt:run");
    expect(plan.enabledTaskIds).toContain("semgrep:scan");
  });

  it("when `config.tasks` is empty, single-task dispatch runs only the explicit task + its deps", () => {
    // This is the post-fix behavior: shared.ts clears config.tasks when
    // the caller pinned an explicit task list, so no baseline leak.
    const registry = makeRegistry([
      stubTask("semgrep:scan"),
      stubTask("threat-model:threat-model-randori"),
      stubTask("carlini-threat-hunt:run", ["threat-model:threat-model-randori"]),
    ]);
    const plan = resolveInitialTaskPlan(registry, ["carlini-threat-hunt:run"], {
      tasks: [],
      enableContextGathering: false,
      enableContextEnrichment: false,
      enableDynamicTaskSelection: false,
    });
    expect(plan.enabledTaskIds).toContain("carlini-threat-hunt:run");
    expect(plan.enabledTaskIds).toContain("threat-model:threat-model-randori");
    expect(plan.enabledTaskIds).not.toContain("semgrep:scan");
  });

  it("pulls in context-gatherer when enableContextGathering is true", () => {
    const registry = makeRegistry([
      stubTask("context:context-gatherer"),
      stubTask("carlini-threat-hunt:run"),
    ]);
    const plan = resolveInitialTaskPlan(registry, ["carlini-threat-hunt:run"], {
      tasks: [],
      enableContextGathering: true,
      enableContextEnrichment: false,
      enableDynamicTaskSelection: false,
    });
    expect(plan.enabledTaskIds).toContain("context:context-gatherer");
  });

  it("expands `*` as configuredTasks to include every registered task", () => {
    const registry = makeRegistry([
      stubTask("semgrep:scan"),
      stubTask("codeql:scan"),
      stubTask("carlini-threat-hunt:run"),
    ]);
    const plan = resolveInitialTaskPlan(registry, [], {
      tasks: ["*"],
      enableContextGathering: false,
      enableContextEnrichment: false,
      enableDynamicTaskSelection: false,
    });
    expect(plan.useAllTasks).toBe(true);
    expect(new Set(plan.enabledTaskIds)).toEqual(
      new Set(["semgrep:scan", "codeql:scan", "carlini-threat-hunt:run"]),
    );
  });

  it("filters disabled tasks from configured task lists", () => {
    const registry = makeRegistry([
      stubTask("semgrep:scan"),
      stubTask("codeql:scan"),
      stubTask("carlini-threat-hunt:run"),
    ]);
    const plan = resolveInitialTaskPlan(
      registry,
      [],
      {
        tasks: ["semgrep:scan", "codeql:scan", "carlini-threat-hunt:run"],
        enableContextGathering: false,
        enableContextEnrichment: false,
        enableDynamicTaskSelection: false,
      },
      { disabledTasks: ["codeql:scan"] },
    );
    expect(plan.enabledTaskIds).toContain("semgrep:scan");
    expect(plan.enabledTaskIds).toContain("carlini-threat-hunt:run");
    expect(plan.enabledTaskIds).not.toContain("codeql:scan");
  });

  it("filters disabled tasks from all-task expansion", () => {
    const registry = makeRegistry([
      stubTask("semgrep:scan"),
      stubTask("codeql:scan"),
      stubTask("carlini-threat-hunt:run"),
    ]);
    const plan = resolveInitialTaskPlan(
      registry,
      [],
      {
        tasks: ["*"],
        enableContextGathering: false,
        enableContextEnrichment: false,
        enableDynamicTaskSelection: false,
      },
      { disabledTasks: ["codeql:scan"] },
    );
    expect(plan.useAllTasks).toBe(true);
    expect(new Set(plan.enabledTaskIds)).toEqual(
      new Set(["semgrep:scan", "carlini-threat-hunt:run"]),
    );
  });

  it("expands disabled public capabilities before filtering", () => {
    const registry = makeRegistry([
      stubTask("semgrep:scan"),
      stubTask("pipeline:taint-cwe-select"),
      stubTask("taint-iris:hunt", ["pipeline:taint-cwe-select"]),
    ]);
    const plan = resolveInitialTaskPlan(
      registry,
      [],
      {
        tasks: ["semgrep:scan", "pipeline:taint-cwe-select", "taint-iris:hunt"],
        enableContextGathering: false,
        enableContextEnrichment: false,
        enableDynamicTaskSelection: false,
      },
      { disabledTasks: ["taint-analysis"] },
    );
    expect(plan.disabledTaskIds).toEqual(["pipeline:taint-cwe-select", "taint-iris:hunt"]);
    expect(plan.enabledTaskIds).toEqual(["semgrep:scan"]);
  });

  it("errors on unknown disabled task identifiers", () => {
    const registry = makeRegistry([stubTask("semgrep:scan")]);
    expect(() =>
      resolveInitialTaskPlan(
        registry,
        [],
        {
          tasks: ["semgrep:scan"],
          enableContextGathering: false,
          enableContextEnrichment: false,
          enableDynamicTaskSelection: false,
        },
        { disabledTasks: ["not-a-task"] },
      ),
    ).toThrow("Unknown disabled task");
  });

  it("does NOT inject task-selector when enableDynamicTaskSelection is false", () => {
    // Regression: /use carlini-threat-hunt; run . had the shell's
    // executeSastPipeline clamp config.tasks=[] but leave dynamic
    // selection on, so resolveInitialTaskPlan still added task-selector
    // which then merged detectors like secrets-crypto-detect into the
    // run. Lock in that the flag alone is sufficient to keep the
    // selector out.
    const registry = makeRegistry([
      stubTask("pipeline:task-selector"),
      stubTask("carlini-threat-hunt:run"),
      stubTask("agentic-sast:secrets-crypto-detect"),
    ]);
    const plan = resolveInitialTaskPlan(registry, ["carlini-threat-hunt:run"], {
      tasks: [],
      enableContextGathering: false,
      enableContextEnrichment: false,
      enableDynamicTaskSelection: false,
    });
    expect(plan.enabledTaskIds).toContain("carlini-threat-hunt:run");
    expect(plan.enabledTaskIds).not.toContain("pipeline:task-selector");
    expect(plan.enabledTaskIds).not.toContain("agentic-sast:secrets-crypto-detect");
    expect(plan.dynamicSelectionActive).toBe(false);
  });
});

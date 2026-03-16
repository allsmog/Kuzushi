import { describe, expect, it } from "vitest";
import { TaskRegistry } from "../../src/agents/registry.js";
import type { AgentTask } from "../../src/agents/types.js";

function task(id: string, dependsOn: string[] = []): AgentTask {
  return {
    id,
    displayName: id,
    outputKind: "custom",
    dependsOn,
    async run() {
      return { ok: true };
    },
  };
}

describe("TaskRegistry", () => {
  it("register/get/has/ids work", () => {
    const registry = new TaskRegistry();
    registry.register(task("a"));

    expect(registry.has("a")).toBe(true);
    expect(registry.get("a").id).toBe("a");
    expect(registry.ids()).toEqual(["a"]);
  });

  it("resolves DAG into parallel execution groups", () => {
    const registry = new TaskRegistry();
    registry.register(task("scanner-a"));
    registry.register(task("scanner-b"));
    registry.register(task("analyzer"));
    registry.register(task("verifier", ["scanner-a", "scanner-b", "analyzer"]));
    registry.register(task("reporter", ["verifier"]));

    const order = registry.resolveOrder([
      "scanner-a",
      "scanner-b",
      "analyzer",
      "verifier",
      "reporter",
    ]);

    expect(order).toEqual([
      ["scanner-a", "scanner-b", "analyzer"],
      ["verifier"],
      ["reporter"],
    ]);
  });

  it("throws on dependency cycles", () => {
    const registry = new TaskRegistry();
    registry.register(task("a", ["c"]));
    registry.register(task("b", ["a"]));
    registry.register(task("c", ["b"]));

    expect(() => registry.resolveOrder(["a", "b", "c"]))
      .toThrow("Task dependency cycle detected");
  });

  it("throws when enabled set misses required dependencies", () => {
    const registry = new TaskRegistry();
    registry.register(task("semgrep"));
    registry.register(task("fp-verification", ["semgrep"]));

    expect(() => registry.resolveOrder(["fp-verification"]))
      .toThrow("but it is not enabled");
  });

  it("throws when dependsOn references unknown task", () => {
    const registry = new TaskRegistry();
    registry.register(task("fp-verification", ["missing-task"]));

    expect(() => registry.validate()).toThrow("depends on unknown task");
  });

  it("prioritizes unknown enabled task errors over unrelated invalid registrations", () => {
    const registry = new TaskRegistry();
    registry.register(task("valid"));
    registry.register(task("broken", ["missing-dep"]));

    expect(() => registry.resolveOrder(["unknown-task"]))
      .toThrow("Unknown enabled task");
  });
});

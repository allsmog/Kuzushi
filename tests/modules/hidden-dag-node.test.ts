import { describe, expect, it } from "vitest";
import { defineHiddenDagNodeTool } from "../../src/modules/hidden-dag-node.js";
import type { KuzushiConfig } from "../../src/types.js";

describe("defineHiddenDagNodeTool", () => {
  it("evaluates conditions with bare aliases for canonical upstream outputs", () => {
    const tool = defineHiddenDagNodeTool<"systems-hunt">(
      {
        id: "systems-context-gatherer",
        displayName: "Systems Context Gatherer",
        outputKind: "custom",
        dependsOn: ["context-gatherer"],
        condition(upstream) {
          return upstream.has("context-gatherer");
        },
        async run() {
          return {};
        },
      },
      { moduleId: "systems-hunt" },
    );

    expect(
      tool.dag.condition?.(
        new Map([["context:context-gatherer", { ok: true }]]),
        {} as KuzushiConfig,
      ),
    ).toBe(true);
  });
});

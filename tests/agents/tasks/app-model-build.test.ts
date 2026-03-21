import { describe, expect, it } from "vitest";
import { appModelBuildTask } from "../../../src/agents/tasks/app-model-build.js";

describe("app-model-build task", () => {
  it("has correct task contract", () => {
    expect(appModelBuildTask.id).toBe("app-model-build");
    expect(appModelBuildTask.outputKind).toBe("custom");
    expect(appModelBuildTask.dependsOn).toContain("context-gatherer");
    expect(appModelBuildTask.dependsOn).toContain("context-enricher");
  });
});

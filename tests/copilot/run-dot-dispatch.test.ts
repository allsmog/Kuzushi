/**
 * Regression test for v0.21 followup M2 — `run .` in `threat-model`
 * was observed dispatching to `attach` with bizarre params instead of
 * `build`. The current `pickDefaultTool` priority list correctly prefers
 * `:build` for threat-model; this suite locks the behavior so a future
 * module-home wiring change can't silently re-route the bare `run` /
 * `run .` shortcut into a destructive sibling tool.
 */

import { describe, expect, it } from "vitest";
import { pickDefaultTool } from "../../src/copilot/dispatcher/module-dispatcher.js";
import type { CopilotModule, ModuleTool } from "../../src/modules/types.js";

function fakeTool(name: string, overrides: Partial<ModuleTool> = {}): ModuleTool {
  return {
    name,
    description: `${name} description`,
    inputSchema: { type: "object", properties: {} },
    headless: true,
    async execute() {
      return { ok: true, output: "" };
    },
    ...overrides,
  };
}

function fakeModule(id: string, toolNames: string[]): CopilotModule {
  return {
    id,
    displayName: id,
    category: "defense",
    version: "0.0.0",
    description: `${id}`,
    tools: toolNames.map((name) => fakeTool(name)),
  };
}

describe("pickDefaultTool — `run .` dispatch contract (M2)", () => {
  it("threat-model dispatches to threat-model:build, not :attach", () => {
    const mod = fakeModule("threat-model", [
      "threat-model:attach",
      "threat-model:build",
      "threat-model:read",
      "threat-model:methodologies",
      "threat-model:edit",
    ]);
    expect(pickDefaultTool(mod)?.name).toBe("threat-model:build");
  });

  it("carlini-threat-hunt dispatches to :run", () => {
    const mod = fakeModule("carlini-threat-hunt", [
      "carlini-threat-hunt:attach",
      "carlini-threat-hunt:run",
      "carlini-threat-hunt:plan",
    ]);
    expect(pickDefaultTool(mod)?.name).toBe("carlini-threat-hunt:run");
  });

  it("context dispatches to :build (no :run/:scan/:audit/:hunt/:exploit)", () => {
    const mod = fakeModule("context", [
      "context:attach",
      "context:build",
      "context:read",
      "context:slice",
    ]);
    expect(pickDefaultTool(mod)?.name).toBe("context:build");
  });

  it("preference order: :run beats :scan beats :audit beats :hunt beats :exploit beats :build beats :list", () => {
    expect(pickDefaultTool(fakeModule("m", ["m:list", "m:build", "m:run"]))?.name).toBe("m:run");
    expect(pickDefaultTool(fakeModule("m", ["m:list", "m:build", "m:scan"]))?.name).toBe("m:scan");
    expect(pickDefaultTool(fakeModule("m", ["m:list", "m:build", "m:audit"]))?.name).toBe(
      "m:audit",
    );
    expect(pickDefaultTool(fakeModule("m", ["m:list", "m:build", "m:hunt"]))?.name).toBe("m:hunt");
    expect(pickDefaultTool(fakeModule("m", ["m:list", "m:build", "m:exploit"]))?.name).toBe(
      "m:exploit",
    );
    expect(pickDefaultTool(fakeModule("m", ["m:list", "m:build"]))?.name).toBe("m:build");
    expect(pickDefaultTool(fakeModule("m", ["m:list"]))?.name).toBe("m:list");
  });

  it("falls back to first headless tool when no preferred suffix matches", () => {
    const mod: CopilotModule = {
      id: "weird",
      displayName: "weird",
      category: "defense",
      version: "0.0.0",
      description: "weird module",
      tools: [
        fakeTool("weird:upload", { headless: false }),
        fakeTool("weird:inspect", { headless: true }),
        fakeTool("weird:report", { headless: true }),
      ],
    };
    expect(pickDefaultTool(mod)?.name).toBe("weird:inspect");
  });

  it("falls back to the first tool when nothing is headless", () => {
    const mod: CopilotModule = {
      id: "weird",
      displayName: "weird",
      category: "defense",
      version: "0.0.0",
      description: "weird module",
      tools: [
        fakeTool("weird:upload", { headless: false }),
        fakeTool("weird:inspect", { headless: false }),
      ],
    };
    expect(pickDefaultTool(mod)?.name).toBe("weird:upload");
  });

  it("returns undefined for an empty module (defensive)", () => {
    expect(pickDefaultTool(fakeModule("empty", []))).toBeUndefined();
  });
});

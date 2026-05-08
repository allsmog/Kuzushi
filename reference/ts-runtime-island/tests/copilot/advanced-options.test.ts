import { describe, expect, it } from "vitest";
import { createModuleDatastore } from "../../src/copilot/dispatcher/module-dispatcher.js";
import { Datastore, formatOptionsTable } from "../../src/copilot/options.js";
import type { CopilotModule, ModuleTool, ToolResult } from "../../src/modules/types.js";

function mkModule(): CopilotModule {
  const tool: ModuleTool = {
    name: "m:run",
    description: "tool",
    inputSchema: {
      type: "object",
      properties: {
        TARGET: { type: "string", description: "required path" },
        VERBOSITY: { type: "integer", description: "log verbosity" },
        TRIAGE_PROMPT: {
          type: "string",
          description: "override prompt",
          "x-advanced": true,
        },
        EVADE_HEADER: {
          type: "string",
          description: "custom header for evasion",
          "x-evasion": true,
        },
      },
      required: ["TARGET"],
    },
    headless: true,
    async execute(): Promise<ToolResult> {
      return { ok: true, output: "" };
    },
  };
  return {
    id: "m",
    displayName: "m",
    category: "defense",
    version: "0.0.1",
    description: "m",
    rank: "good",
    tools: [tool],
  };
}

describe("propertyToSpec x-advanced / x-evasion honoring", () => {
  it("marks options with x-advanced as advanced", () => {
    const ds = createModuleDatastore(mkModule(), new Datastore());
    const prompt = ds.spec("TRIAGE_PROMPT");
    expect(prompt?.advanced).toBe(true);
  });

  it("marks options with x-evasion as evasion", () => {
    const ds = createModuleDatastore(mkModule(), new Datastore());
    const evade = ds.spec("EVADE_HEADER");
    expect(evade?.evasion).toBe(true);
  });

  it("leaves normal options non-advanced, non-evasion", () => {
    const ds = createModuleDatastore(mkModule(), new Datastore());
    const target = ds.spec("TARGET");
    expect(target?.advanced ?? false).toBe(false);
    expect(target?.evasion ?? false).toBe(false);
  });

  it("hides advanced options from default `show options`", () => {
    const ds = createModuleDatastore(mkModule(), new Datastore());
    const out = formatOptionsTable(ds);
    expect(out).toContain("TARGET");
    expect(out).toContain("VERBOSITY");
    expect(out).not.toContain("TRIAGE_PROMPT");
    expect(out).not.toContain("EVADE_HEADER");
  });

  it("surfaces advanced options only in `show advanced`", () => {
    const ds = createModuleDatastore(mkModule(), new Datastore());
    const out = formatOptionsTable(ds, { advanced: true });
    expect(out).toContain("TRIAGE_PROMPT");
    expect(out).not.toContain("TARGET");
    expect(out).not.toContain("EVADE_HEADER");
  });

  it("surfaces evasion options only in `show evasion`", () => {
    const ds = createModuleDatastore(mkModule(), new Datastore());
    const out = formatOptionsTable(ds, { evasion: true });
    expect(out).toContain("EVADE_HEADER");
    expect(out).not.toContain("TARGET");
    expect(out).not.toContain("TRIAGE_PROMPT");
  });
});

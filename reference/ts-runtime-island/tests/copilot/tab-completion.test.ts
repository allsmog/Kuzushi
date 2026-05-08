import { describe, expect, it } from "vitest";
import { CoreDispatcher } from "../../src/copilot/dispatcher/core-dispatcher.js";
import { DispatcherDriver } from "../../src/copilot/dispatcher/driver.js";
import { Datastore } from "../../src/copilot/options.js";
import { createArraySink } from "../../src/copilot/print.js";
import { ModuleRegistry } from "../../src/modules/registry.js";
import type { CopilotModule, ModuleTool, ToolResult } from "../../src/modules/types.js";

function mkTool(): ModuleTool {
  return {
    name: "sast:scan",
    description: "scan",
    inputSchema: {
      type: "object",
      properties: {
        TARGET: { type: "string", description: "path" },
        PRESET: {
          type: "string",
          enum: ["fast", "standard", "deep"],
          default: "standard",
          description: "preset",
        },
        STRICT: { type: "boolean", description: "strict mode" },
      },
      required: ["TARGET"],
    },
    headless: true,
    async execute(): Promise<ToolResult> {
      return { ok: true, output: "ok" };
    },
  };
}

function mkModule(): CopilotModule {
  return {
    id: "sast",
    displayName: "sast",
    category: "defense",
    version: "0.0.1",
    description: "sast",
    rank: "good",
    tools: [mkTool()],
  };
}

function seed() {
  const registry = new ModuleRegistry();
  registry.register(mkModule());
  (registry as unknown as { initialized: Set<string> }).initialized.add("sast");
  const sink = createArraySink();
  const core = new CoreDispatcher({ registry, globals: new Datastore(), history: () => [] });
  const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: sink });
  return { driver };
}

describe("tab completion", () => {
  it("completes command names", () => {
    const { driver } = seed();
    const hits = driver.complete("se");
    expect(hits).toContain("set");
    expect(hits).toContain("setg");
    expect(hits).toContain("search");
  });

  it("completes module ids after `use`", () => {
    const { driver } = seed();
    expect(driver.complete("use s")).toContain("sast");
  });

  it("completes `show` sub-targets", () => {
    const { driver } = seed();
    const hits = driver.complete("show o");
    expect(hits).toContain("options");
  });

  it("completes search DSL keys", () => {
    const { driver } = seed();
    const hits = driver.complete("search cate");
    expect(hits).toContain("category:");
  });

  it("completes search category values", () => {
    const { driver } = seed();
    const hits = driver.complete("search category:off");
    expect(hits).toContain("offense");
  });

  it("completes search rank values", () => {
    const { driver } = seed();
    const hits = driver.complete("search rank:exc");
    expect(hits).toContain("excellent");
  });

  it("completes option names inside a module dispatcher", async () => {
    const { driver } = seed();
    await driver.handle("use sast");
    const hits = driver.complete("set TAR");
    expect(hits).toContain("TARGET");
  });

  it("completes enum values for an option", async () => {
    const { driver } = seed();
    await driver.handle("use sast");
    const hits = driver.complete("set PRESET ");
    expect(hits).toContain("fast");
    expect(hits).toContain("standard");
    expect(hits).toContain("deep");
  });

  it("completes boolean values for a bool option", async () => {
    const { driver } = seed();
    await driver.handle("use sast");
    const hits = driver.complete("set STRICT t");
    expect(hits).toContain("true");
  });

  it("completes `recipes` sub-commands", () => {
    const { driver } = seed();
    const hits = driver.complete("recipes r");
    expect(hits).toContain("run");
  });
});

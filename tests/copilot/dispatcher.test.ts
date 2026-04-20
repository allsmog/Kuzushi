import { describe, expect, it } from "vitest";
import { CoreDispatcher } from "../../src/copilot/dispatcher/core-dispatcher.js";
import { DispatcherDriver, tokenize } from "../../src/copilot/dispatcher/driver.js";
import type { CommandDispatcher } from "../../src/copilot/dispatcher/types.js";
import { Datastore } from "../../src/copilot/options.js";
import { createArraySink } from "../../src/copilot/print.js";
import { ModuleRegistry } from "../../src/modules/registry.js";
import type { CopilotModule, ModuleTool, ToolResult } from "../../src/modules/types.js";

function mkTool(name: string, headless = true): ModuleTool {
  return {
    name,
    description: `dummy ${name}`,
    inputSchema: {
      type: "object",
      properties: {
        RHOST: { type: "string", description: "target" },
        RPORT: { type: "integer", description: "port", default: 80 },
      },
      required: ["RHOST"],
    },
    headless,
    async execute(): Promise<ToolResult> {
      return { ok: true, output: `ran ${name}` };
    },
  };
}

function mkModule(id: string, tools: ModuleTool[] = []): CopilotModule {
  return {
    id,
    displayName: `Mod ${id}`,
    category: "offense",
    version: "0.0.1",
    description: `module ${id}`,
    rank: "good",
    tools,
  };
}

function seed(): {
  driver: DispatcherDriver;
  sink: ReturnType<typeof createArraySink>;
  registry: ModuleRegistry;
} {
  const registry = new ModuleRegistry();
  const mod = mkModule("sast", [mkTool("sast:scan")]);
  registry.register(mod);
  (registry as unknown as { initialized: Set<string> }).initialized.add("sast");

  const sink = createArraySink();
  const core = new CoreDispatcher({
    registry,
    globals: new Datastore(),
    history: () => ["modules", "help"],
  });
  const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: sink });
  return { driver, sink, registry };
}

describe("tokenize", () => {
  it("handles quoted strings", () => {
    expect(tokenize(`set FOO "a b c"`)).toEqual(["set", "FOO", "a b c"]);
    expect(tokenize(`x 'y z' w`)).toEqual(["x", "y z", "w"]);
  });
});

describe("CoreDispatcher", () => {
  it("lists modules", async () => {
    const { driver } = seed();
    const result = await driver.handle("modules");
    expect(result.output).toContain("sast");
    expect(result.output).toContain("offense");
  });

  it("use pushes a module dispatcher + prompt changes", async () => {
    const { driver } = seed();
    const result = await driver.handle("use sast");
    expect(result.output).toContain("Selected module: sast");
    expect(driver.prompt()).toBe("kuzushi/module(sast)> ");
    await driver.handle("back");
    expect(driver.prompt()).toBe("kuzushi> ");
  });

  it("set requires a module, setg works globally", async () => {
    const { driver } = seed();
    const noMod = await driver.handle("set FOO bar");
    expect(noMod.output).toContain("No module selected");
    const globalOk = await driver.handle("setg FOO bar");
    expect(globalOk.output).toBe("FOO => bar");
  });

  it("show options renders the module's inputSchema-derived options", async () => {
    const { driver } = seed();
    await driver.handle("use sast");
    const result = await driver.handle("show options");
    expect(result.output).toContain("RHOST");
    expect(result.output).toContain("RPORT");
    expect(result.output).toContain("Required");
  });

  it("show missing lists required options not yet set", async () => {
    const { driver } = seed();
    await driver.handle("use sast");
    const missing = await driver.handle("show missing");
    expect(missing.output).toContain("Missing: RHOST");
    await driver.handle("set RHOST 10.0.0.1");
    const ok = await driver.handle("show missing");
    expect(ok.output).toContain("All required options are set");
  });

  it("info renders module and tool details", async () => {
    const { driver } = seed();
    const modInfo = await driver.handle("info sast");
    expect(modInfo.output).toContain("Module: sast");
    expect(modInfo.output).toContain("Rank: good");
    const toolInfo = await driver.handle("info sast:scan");
    expect(toolInfo.output).toContain("Name: sast:scan");
  });

  it("search finds by keyword and by type", async () => {
    const { driver } = seed();
    const byKw = await driver.handle("search scan");
    expect(byKw.output).toContain("sast:scan");
    const byType = await driver.handle("search type:module");
    expect(byType.output).toContain("sast");
  });

  it("history -n N slices the log; history -c clears", async () => {
    const cleared: boolean[] = [];
    const core = new CoreDispatcher({
      registry: new ModuleRegistry(),
      globals: new Datastore(),
      history: () => ["one", "two", "three"],
      clearHistory: () => cleared.push(true),
    });
    const sink = createArraySink();
    const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: sink });
    const limited = await driver.handle("history -n 2");
    expect(limited.output).toContain("two");
    expect(limited.output).toContain("three");
    expect(limited.output).not.toContain("one");
    const clr = await driver.handle("history -c");
    expect(clr.output).toContain("Cleared");
    expect(cleared).toEqual([true]);
  });

  it("reports unknown command with matched=false", async () => {
    const { driver } = seed();
    const out = await driver.handle("xyzzy");
    expect(out.output).toContain("Unknown command");
    expect(out.matched).toBe(false);
  });

  it("sets matched=true on recognized commands", async () => {
    const { driver } = seed();
    const out = await driver.handle("modules");
    expect(out.matched).toBe(true);
  });

  it("treats empty input as matched=false, no output", async () => {
    const { driver } = seed();
    const out = await driver.handle("   ");
    expect(out.matched).toBe(false);
    expect(out.output).toBeUndefined();
  });

  it("tab-completes command names", () => {
    const { driver } = seed();
    const hits = driver.complete("se");
    expect(hits).toContain("set");
    expect(hits).toContain("setg");
    expect(hits).toContain("search");
  });

  it("tab-completes `use <prefix>` against registered modules", () => {
    const { driver } = seed();
    const hits = driver.complete("use sa");
    expect(hits).toContain("sast");
  });
});

describe("ModuleDispatcher requires preflight", () => {
  function mkModuleWithRequires(
    id: string,
    requires: import("../../src/modules/types.js").CopilotModuleRequirement[],
  ): CopilotModule {
    return {
      ...mkModule(id, [mkTool(`${id}:run`)]),
      requires,
    };
  }

  it("blocks run when a required snapshot field is missing, with a helpful hint", async () => {
    const registry = new ModuleRegistry();
    const mod = mkModuleWithRequires("threat-hunt", [
      { kind: "snapshot", moduleId: "context", field: "appModel" },
      { kind: "snapshot", moduleId: "randori", field: "threatModel" },
    ]);
    registry.register(mod);
    (registry as unknown as { initialized: Set<string> }).initialized.add("threat-hunt");
    const sink = createArraySink();
    const core = new CoreDispatcher({ registry, globals: new Datastore(), history: () => [] });
    // Empty ShellState — no contextSnapshot.
    const driver = new DispatcherDriver({
      base: core,
      cwd: "/tmp",
      print: sink,
      getShellState: () => ({}),
    });
    await driver.handle("use threat-hunt");
    // Satisfy the required option so the check isn't short-circuited by missing RHOST.
    await driver.handle("set RHOST x");
    const result = await driver.handle("run");
    expect(result.output).toContain("unmet prerequisites");
    expect(result.output).toContain("appModel");
    expect(result.output).toContain("run: use context; run");
    expect(result.output).toContain("threatModel");
  });

  it("allows run when every snapshot requirement is satisfied", async () => {
    const registry = new ModuleRegistry();
    const mod = mkModuleWithRequires("threat-hunt", [
      { kind: "snapshot", moduleId: "context", field: "appModel" },
    ]);
    registry.register(mod);
    (registry as unknown as { initialized: Set<string> }).initialized.add("threat-hunt");
    const sink = createArraySink();
    const core = new CoreDispatcher({
      registry,
      globals: new Datastore(),
      history: () => [],
      runTool: async (t) => ({ ok: true, output: `ran ${t.name}` }),
    });
    const driver = new DispatcherDriver({
      base: core,
      cwd: "/tmp",
      print: sink,
      getShellState: () => ({ contextSnapshot: { appModel: { routes: [] } } }),
    });
    await driver.handle("use threat-hunt");
    await driver.handle("set RHOST x");
    const result = await driver.handle("run");
    expect(result.output).toBe("ran threat-hunt:run");
  });

  it("blocks run when a findings requirement is unmet", async () => {
    const registry = new ModuleRegistry();
    const mod = mkModuleWithRequires("triage", [{ kind: "findings", minCount: 1 }]);
    registry.register(mod);
    (registry as unknown as { initialized: Set<string> }).initialized.add("triage");
    const sink = createArraySink();
    const core = new CoreDispatcher({ registry, globals: new Datastore(), history: () => [] });
    const driver = new DispatcherDriver({
      base: core,
      cwd: "/tmp",
      print: sink,
      getFindingCount: () => 0,
    });
    await driver.handle("use triage");
    await driver.handle("set RHOST x");
    const result = await driver.handle("run");
    expect(result.output).toContain("1+ findings");
    expect(result.output).toContain("run a scanner first");
  });
});

describe("CoreDispatcher runTool wiring", () => {
  it("forwards `run` inside a module dispatcher to the runTool callback", async () => {
    const registry = new ModuleRegistry();
    const tool: ModuleTool = {
      name: "sast:run",
      description: "runnable tool",
      inputSchema: {
        type: "object",
        properties: { TARGET: { type: "string", description: "target", default: "." } },
      },
      headless: true,
      async execute(): Promise<ToolResult> {
        return { ok: true, output: "direct" };
      },
    };
    const mod: CopilotModule = {
      id: "sast",
      displayName: "SAST",
      category: "defense",
      version: "1.0.0",
      description: "SAST",
      rank: "good",
      tools: [tool],
    };
    registry.register(mod);
    (registry as unknown as { initialized: Set<string> }).initialized.add("sast");

    const calls: Array<{ name: string; input: Record<string, unknown> }> = [];
    const runTool = async (t: ModuleTool, input: Record<string, unknown>): Promise<ToolResult> => {
      calls.push({ name: t.name, input });
      return { ok: true, output: `ran ${t.name}` };
    };

    const sink = createArraySink();
    const core = new CoreDispatcher({
      registry,
      globals: new Datastore(),
      history: () => [],
      runTool,
    });
    const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: sink });

    await driver.handle("use sast");
    const result = await driver.handle("run");
    expect(calls).toHaveLength(1);
    expect(calls[0].name).toBe("sast:run");
    // Default value from JSONSchema is surfaced through the Datastore snapshot.
    expect(calls[0].input.TARGET).toBe(".");
    expect(result.matched).toBe(true);
    expect(result.output).toBe("ran sast:run");
  });
});

describe("dispatch stack semantics", () => {
  it("top of stack shadows base commands", async () => {
    const core = new CoreDispatcher({
      registry: new ModuleRegistry(),
      globals: new Datastore(),
      history: () => [],
    });
    const sink = createArraySink();
    const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: sink });
    const shadow: CommandDispatcher = {
      name: "shadow",
      commands: { banner: "shadowed banner" },
      async execute() {
        return { output: "SHADOW" };
      },
    };
    driver.push(shadow);
    const result = await driver.handle("banner");
    expect(result.output).toBe("SHADOW");
    driver.pop();
    const core2 = await driver.handle("banner");
    expect(core2.output).toContain("_");
  });
});

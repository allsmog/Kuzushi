import { describe, expect, it } from "vitest";
import { CoreDispatcher } from "../../src/copilot/dispatcher/core-dispatcher.js";
import { DispatcherDriver, tokenize } from "../../src/copilot/dispatcher/driver.js";
import type { CommandDispatcher } from "../../src/copilot/dispatcher/types.js";
import { Datastore } from "../../src/copilot/options.js";
import { createArraySink } from "../../src/copilot/print.js";
import { JobManager } from "../../src/jobs/manager.js";
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

  it("show <unknown> lists valid targets and hints the focused module", async () => {
    const { driver } = seed();
    const baseline = await driver.handle("show context");
    expect(baseline.output).toContain(`Unknown show target: "context"`);
    expect(baseline.output).toContain("options");
    expect(baseline.output).not.toContain("You're in");

    await driver.handle("use sast");
    const focused = await driver.handle("show context");
    expect(focused.output).toContain(`Unknown show target: "context"`);
    expect(focused.output).toContain("You're in the sast module");
    expect(focused.output).toContain("run `tools`");
  });

  it("show <near-miss> suggests the closest valid target", async () => {
    const { driver } = seed();
    const res = await driver.handle("show module");
    expect(res.output).toContain("Did you mean:");
    expect(res.output).toContain("modules");
  });

  it("use <partial> suggests similar module ids", async () => {
    const registry = new ModuleRegistry();
    registry.register(mkModule("taint-iris", [mkTool("taint-iris:run")]));
    registry.register(mkModule("carlini-threat-hunt", [mkTool("carlini-threat-hunt:run")]));
    registry.register(mkModule("triage", [mkTool("triage:run")]));
    (registry as unknown as { initialized: Set<string> }).initialized.add("taint-iris");
    (registry as unknown as { initialized: Set<string> }).initialized.add("carlini-threat-hunt");
    (registry as unknown as { initialized: Set<string> }).initialized.add("triage");

    const sink = createArraySink();
    const core = new CoreDispatcher({ registry, globals: new Datastore(), history: () => [] });
    const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: sink });

    const res = await driver.handle("use taint");
    expect(res.output).toContain("Unknown module: taint.");
    expect(res.output).toContain("Did you mean: taint-iris");
  });

  it("use <nonsense> falls back to the 'Run `modules`' hint", async () => {
    const { driver } = seed();
    const res = await driver.handle("use zzznope");
    expect(res.output).toContain("Unknown module: zzznope.");
    expect(res.output).toContain("Run `modules`");
  });

  it("modules table wraps long descriptions under the Description column", async () => {
    const registry = new ModuleRegistry();
    const long: CopilotModule = {
      ...mkModule("wordy", [mkTool("wordy:run")]),
      description:
        "This is a very long description that should wrap cleanly beneath the Description column even on a narrow 80-column terminal without breaking mid-word.",
    };
    registry.register(long);
    (registry as unknown as { initialized: Set<string> }).initialized.add("wordy");
    const sink = createArraySink();
    const core = new CoreDispatcher({ registry, globals: new Datastore(), history: () => [] });
    const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: sink });

    // Force a narrow terminal so we can assert wrap behavior.
    const origCols = process.stdout.columns;
    Object.defineProperty(process.stdout, "columns", { configurable: true, value: 80 });
    try {
      const res = await driver.handle("modules");
      const lines = res.output.split("\n");
      // First body line starts with leading spaces + id + category + version + tools + first chunk of description.
      const leader = lines.find((l) => l.includes("wordy"));
      expect(leader).toBeDefined();
      expect(leader!).toMatch(/wordy\s+.*\s+This is a very long/);
      // At least one continuation line padded to align under the Description column.
      const contPad = lines[0]!.indexOf("Description");
      const contLines = lines.filter(
        (l) =>
          l.length > contPad &&
          l.startsWith(" ".repeat(contPad)) &&
          !l.includes("wordy") &&
          !l.trim().startsWith("---"),
      );
      expect(contLines.length).toBeGreaterThan(0);
    } finally {
      Object.defineProperty(process.stdout, "columns", { configurable: true, value: origCols });
    }
  });

  it("tools --all surfaces hidden DAG nodes", async () => {
    const registry = new ModuleRegistry();
    const publicTool = mkTool("sast:scan");
    const hiddenTool: ModuleTool = { ...mkTool("sast:triage-internal"), hidden: true };
    registry.register(mkModule("sast", [publicTool, hiddenTool]));
    (registry as unknown as { initialized: Set<string> }).initialized.add("sast");
    const sink = createArraySink();
    const core = new CoreDispatcher({ registry, globals: new Datastore(), history: () => [] });
    const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: sink });

    await driver.handle("use sast");
    const def = await driver.handle("tools");
    expect(def.output).toContain("sast:scan");
    expect(def.output).not.toContain("sast:triage-internal");
    expect(def.output).toContain("1 advanced pipeline step");

    const all = await driver.handle("tools --all");
    expect(all.output).toContain("sast:scan");
    expect(all.output).toContain("sast:triage-internal");
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
    const mod = mkModuleWithRequires("carlini-threat-hunt", [
      { kind: "snapshot", moduleId: "context", field: "appModel" },
      { kind: "snapshot", moduleId: "threat-model", field: "threatModel" },
    ]);
    registry.register(mod);
    (registry as unknown as { initialized: Set<string> }).initialized.add("carlini-threat-hunt");
    const sink = createArraySink();
    const core = new CoreDispatcher({ registry, globals: new Datastore(), history: () => [] });
    // Empty ShellState — no contextSnapshot.
    const driver = new DispatcherDriver({
      base: core,
      cwd: "/tmp",
      print: sink,
      getShellState: () => ({}),
    });
    await driver.handle("use carlini-threat-hunt");
    // Satisfy the required option so the check isn't short-circuited by missing RHOST.
    await driver.handle("set RHOST x");
    const result = await driver.handle("run");
    expect(result.output).toContain("unmet prerequisites");
    expect(result.output).toContain("appModel");
    expect(result.output).toContain("'use context' then 'run'");
    expect(result.output).toContain("threatModel");
    expect(result.output).toContain("/threats regen dfd");
  });

  it("allows run when every snapshot requirement is satisfied", async () => {
    const registry = new ModuleRegistry();
    const mod = mkModuleWithRequires("carlini-threat-hunt", [
      { kind: "snapshot", moduleId: "context", field: "appModel" },
    ]);
    registry.register(mod);
    (registry as unknown as { initialized: Set<string> }).initialized.add("carlini-threat-hunt");
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
    await driver.handle("use carlini-threat-hunt");
    await driver.handle("set RHOST x");
    const result = await driver.handle("run");
    expect(result.output).toBe("ran carlini-threat-hunt:run");
  });

  it("blocks run when a hosts requirement is unmet", async () => {
    const registry = new ModuleRegistry();
    const mod = mkModuleWithRequires("blackbox", [{ kind: "hosts", minCount: 1 }]);
    registry.register(mod);
    (registry as unknown as { initialized: Set<string> }).initialized.add("blackbox");
    const sink = createArraySink();
    const core = new CoreDispatcher({ registry, globals: new Datastore(), history: () => [] });
    const driver = new DispatcherDriver({
      base: core,
      cwd: "/tmp",
      print: sink,
      getHostCount: () => 0,
    });
    await driver.handle("use blackbox");
    await driver.handle("set RHOST x");
    const result = await driver.handle("run");
    expect(result.output).toContain("hosts in workspace");
    expect(result.output).toContain("add hosts to the active workspace first");
  });

  it("blocks run when a session requirement is unmet", async () => {
    const registry = new ModuleRegistry();
    const mod = mkModuleWithRequires("lateral", [{ kind: "session", sessionKind: "ssh" }]);
    registry.register(mod);
    (registry as unknown as { initialized: Set<string> }).initialized.add("lateral");
    const sink = createArraySink();
    const core = new CoreDispatcher({ registry, globals: new Datastore(), history: () => [] });
    const driver = new DispatcherDriver({
      base: core,
      cwd: "/tmp",
      print: sink,
      getLiveSessionCount: () => 0,
    });
    await driver.handle("use lateral");
    await driver.handle("set RHOST x");
    const result = await driver.handle("run");
    expect(result.output).toContain("'ssh' live session");
  });

  it("blocks run when an env requirement is unmet", async () => {
    const before = process.env["TEST_KUZUSHI_MISSING"];
    delete process.env["TEST_KUZUSHI_MISSING"];
    try {
      const registry = new ModuleRegistry();
      const mod = mkModuleWithRequires("recon-shodan", [
        { kind: "env", name: "TEST_KUZUSHI_MISSING" },
      ]);
      registry.register(mod);
      (registry as unknown as { initialized: Set<string> }).initialized.add("recon-shodan");
      const sink = createArraySink();
      const core = new CoreDispatcher({ registry, globals: new Datastore(), history: () => [] });
      const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: sink });
      await driver.handle("use recon-shodan");
      await driver.handle("set RHOST x");
      const result = await driver.handle("run");
      expect(result.output).toContain("TEST_KUZUSHI_MISSING");
      expect(result.output).toContain("not set");
    } finally {
      if (before !== undefined) process.env["TEST_KUZUSHI_MISSING"] = before;
    }
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

describe("CoreDispatcher edit", () => {
  it("opens the editor and stores the edited value in the active module store", async () => {
    const registry = new ModuleRegistry();
    const mod = mkModule("sast", [mkTool("sast:scan")]);
    registry.register(mod);
    (registry as unknown as { initialized: Set<string> }).initialized.add("sast");

    const sink = createArraySink();
    const captured: string[] = [];
    const core = new CoreDispatcher({
      registry,
      globals: new Datastore(),
      history: () => [],
      openEditor: async (initial: string) => {
        captured.push(initial);
        return "# edited prompt body\nYou are a careful agent.";
      },
    });
    const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: sink });

    await driver.handle("use sast");
    const result = await driver.handle("edit TRIAGE_PROMPT");
    expect(result.output).toContain("Updated TRIAGE_PROMPT");
    expect(result.output).toContain("scope=module");
    // Editor was called once, seeded with "" (no prior value).
    expect(captured).toEqual([""]);
  });

  it("falls back to the global store when no module is selected", async () => {
    const registry = new ModuleRegistry();
    const sink = createArraySink();
    const core = new CoreDispatcher({
      registry,
      globals: new Datastore(),
      history: () => [],
      openEditor: async () => "new-text",
    });
    const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: sink });
    const result = await driver.handle("edit CONTEXT_PROMPT");
    expect(result.output).toContain("scope=global");
  });

  it("reports a helpful message on cancel", async () => {
    const registry = new ModuleRegistry();
    const sink = createArraySink();
    const core = new CoreDispatcher({
      registry,
      globals: new Datastore(),
      history: () => [],
      openEditor: async () => null,
    });
    const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: sink });
    const result = await driver.handle("edit TRIAGE_PROMPT");
    expect(result.output).toContain("Edit cancelled");
  });

  it("reports gracefully when disabled", async () => {
    const registry = new ModuleRegistry();
    const sink = createArraySink();
    const core = new CoreDispatcher({ registry, globals: new Datastore(), history: () => [] });
    const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: sink });
    const result = await driver.handle("edit FOO");
    expect(result.output).toContain("not enabled");
  });
});

describe("CoreDispatcher recipes", () => {
  it("lists recipes via listRecipes callback", async () => {
    const registry = new ModuleRegistry();
    const sink = createArraySink();
    const core = new CoreDispatcher({
      registry,
      globals: new Datastore(),
      history: () => [],
      listRecipes: () => [
        { name: "quick-scan", path: "/r/quick-scan.kzrc.yaml", description: "context → semgrep" },
        { name: "deep-audit", path: "/r/deep-audit.kzrc.yaml" },
      ],
    });
    const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: sink });
    const result = await driver.handle("recipes");
    expect(result.output).toContain("Available recipes");
    expect(result.output).toContain("quick-scan");
    expect(result.output).toContain("context → semgrep");
    expect(result.output).toContain("deep-audit");
  });

  it("runs a recipe via resolveRecipePath + runResource", async () => {
    const registry = new ModuleRegistry();
    const calls: string[] = [];
    const sink = createArraySink();
    const core = new CoreDispatcher({
      registry,
      globals: new Datastore(),
      history: () => [],
      resolveRecipePath: (name: string) =>
        name === "quick-scan" ? "/r/quick-scan.kzrc.yaml" : undefined,
      runResource: async (file: string) => {
        calls.push(`ran:${file}`);
      },
    });
    const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: sink });
    const ok = await driver.handle("recipes run quick-scan");
    expect(ok.matched).toBe(true);
    expect(calls).toEqual(["ran:/r/quick-scan.kzrc.yaml"]);

    const missing = await driver.handle("recipes run ghost");
    expect(missing.output).toContain("Unknown recipe");
  });

  it("reports graceful errors when recipes are disabled", async () => {
    const registry = new ModuleRegistry();
    const sink = createArraySink();
    const core = new CoreDispatcher({ registry, globals: new Datastore(), history: () => [] });
    const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: sink });
    const list = await driver.handle("recipes");
    expect(list.output).toContain("not enabled");
    const run = await driver.handle("recipes run foo");
    expect(run.output).toContain("not enabled");
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

  it("exposes universal model options without sending synthetic model to tool input", async () => {
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

    const calls: Array<{ input: Record<string, unknown>; model?: unknown }> = [];
    const runTool = async (
      _t: ModuleTool,
      input: Record<string, unknown>,
      _signal?: AbortSignal,
      datastore?: Datastore,
    ): Promise<ToolResult> => {
      calls.push({ input, model: datastore?.get("model") });
      return { ok: true, output: "ran" };
    };

    const core = new CoreDispatcher({
      registry,
      globals: new Datastore(),
      agentRuntimeBackend: "claude",
      history: () => [],
      runTool,
    });
    const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: createArraySink() });

    const globals = await driver.handle("show globals");
    expect(globals.output).toContain("MODEL");
    const invalid = await driver.handle("setg model openai:gpt-4o");
    expect(invalid.output).toContain("Invalid value");
    await driver.handle("setg model anthropic:claude-sonnet-4-6");
    await driver.handle("use sast");
    const options = await driver.handle("show options");
    expect(options.output).toContain("model");
    expect(options.output).toContain("anthropic:claude-sonnet-4-6");

    await driver.handle("set model claude-opus-4-6");
    const result = await driver.handle("run");

    expect(result.output).toBe("ran");
    expect(calls).toHaveLength(1);
    expect(calls[0].model).toBe("claude-opus-4-6");
    expect(calls[0].input).toMatchObject({ TARGET: "." });
    expect(calls[0].input).not.toHaveProperty("model");
  });
});

describe("background jobs", () => {
  function seedWithJobs(): {
    driver: DispatcherDriver;
    jobs: JobManager;
    tool: ModuleTool;
  } {
    const registry = new ModuleRegistry();
    const tool: ModuleTool = {
      name: "sast:scan",
      description: "dummy",
      inputSchema: { type: "object", properties: {} },
      headless: true,
      async execute(): Promise<ToolResult> {
        return { ok: true, output: "scan done" };
      },
    };
    registry.register(mkModule("sast", [tool]));
    (registry as unknown as { initialized: Set<string> }).initialized.add("sast");

    const jobs = new JobManager();
    const runTool = async (t: ModuleTool): Promise<ToolResult> => {
      await new Promise((r) => setImmediate(r));
      return { ok: true, output: `ran ${t.name}` };
    };
    const core = new CoreDispatcher({
      registry,
      globals: new Datastore(),
      history: () => [],
      jobManager: jobs,
      runTool,
    });
    const sink = createArraySink();
    const driver = new DispatcherDriver({
      base: core,
      cwd: "/tmp",
      print: sink,
      jobManager: jobs,
    });
    return { driver, jobs, tool };
  }

  it("`jobs` with no jobs prints the empty-state message", async () => {
    const { driver } = seedWithJobs();
    const result = await driver.handle("jobs");
    expect(result.output).toContain("(no jobs)");
  });

  it("`run --bg` backgrounds the tool and `jobs -i` tails output", async () => {
    const { driver, jobs } = seedWithJobs();
    await driver.handle("use sast");
    const bg = await driver.handle("run --bg");
    expect(bg.output).toContain("Started job");
    expect(jobs.list()).toHaveLength(1);

    // Wait for the background run to terminate.
    await new Promise<void>((resolve) => {
      const poll = () => {
        if (jobs.list().every((j) => j.state !== "running")) resolve();
        else setImmediate(poll);
      };
      poll();
    });

    const id = jobs.list()[0]?.id ?? "";
    const inspect = await driver.handle(`jobs -i ${id}`);
    expect(inspect.output).toContain(`Job ${id}`);
    expect(inspect.output).toContain("sast:scan");
    expect(inspect.output).toContain("completed");
  });

  it("`jobs -k` cancels a running job", async () => {
    const registry = new ModuleRegistry();
    const tool: ModuleTool = {
      name: "sast:scan",
      description: "slow",
      inputSchema: { type: "object", properties: {} },
      headless: true,
      async execute(_input, ctx): Promise<ToolResult> {
        await new Promise((resolve, reject) => {
          ctx.signal?.addEventListener("abort", () => reject(new Error("aborted")));
        });
        return { ok: true, output: "" };
      },
    };
    registry.register(mkModule("sast", [tool]));
    (registry as unknown as { initialized: Set<string> }).initialized.add("sast");

    const jobs = new JobManager();
    // Minimal runner: honor the provided signal so `jobs -k` aborts the run.
    const runTool = (t: ModuleTool, _input: Record<string, unknown>, signal?: AbortSignal) =>
      new Promise<ToolResult>((_resolve, reject) => {
        signal?.addEventListener("abort", () => reject(new Error("aborted")));
      });
    const core = new CoreDispatcher({
      registry,
      globals: new Datastore(),
      history: () => [],
      jobManager: jobs,
      runTool,
    });
    const driver = new DispatcherDriver({
      base: core,
      cwd: "/tmp",
      print: createArraySink(),
      jobManager: jobs,
    });

    await driver.handle("use sast");
    const bg = await driver.handle("run --bg");
    expect(bg.output).toContain("Started job");
    const id = jobs.list()[0]?.id ?? "";
    const killed = await driver.handle(`jobs -k ${id}`);
    expect(killed.output).toContain(`Cancelled job ${id}`);

    await new Promise<void>((resolve) => {
      const poll = () => {
        const j = jobs.get(id);
        if (j && j.state !== "running") resolve();
        else setImmediate(poll);
      };
      poll();
    });
    expect(jobs.get(id)?.state).toBe("cancelled");
  });
});

describe("prompt status providers", () => {
  function basicDriver(): DispatcherDriver {
    const registry = new ModuleRegistry();
    registry.register(mkModule("sast", [mkTool("sast:scan")]));
    (registry as unknown as { initialized: Set<string> }).initialized.add("sast");
    const core = new CoreDispatcher({
      registry,
      globals: new Datastore(),
      history: () => [],
    });
    return new DispatcherDriver({ base: core, cwd: "/tmp", print: createArraySink() });
  }

  it("no providers → plain `kuzushi> ` prompt", () => {
    const driver = basicDriver();
    expect(driver.prompt()).toBe("kuzushi> ");
  });

  it("single provider appears in brackets", () => {
    const driver = basicDriver();
    driver.addStatusProvider(() => "2 jobs");
    expect(driver.prompt()).toBe("kuzushi [2 jobs]> ");
  });

  it("multiple providers join with ` · `", () => {
    const driver = basicDriver();
    driver.addStatusProvider(() => "2 jobs");
    driver.addStatusProvider(() => "$1.40");
    driver.addStatusProvider(() => "ws: acme");
    expect(driver.prompt()).toBe("kuzushi [2 jobs · $1.40 · ws: acme]> ");
  });

  it("undefined / empty providers are skipped", () => {
    const driver = basicDriver();
    driver.addStatusProvider(() => undefined);
    driver.addStatusProvider(() => "");
    driver.addStatusProvider(() => "ws: acme");
    expect(driver.prompt()).toBe("kuzushi [ws: acme]> ");
  });

  it("a throwing provider doesn't break the prompt", () => {
    const driver = basicDriver();
    driver.addStatusProvider(() => {
      throw new Error("boom");
    });
    driver.addStatusProvider(() => "ok");
    expect(driver.prompt()).toBe("kuzushi [ok]> ");
  });

  it("providers show up with a module on the stack too", async () => {
    const driver = basicDriver();
    driver.addStatusProvider(() => "2 jobs");
    await driver.handle("use sast");
    expect(driver.prompt()).toBe("kuzushi/module(sast) [2 jobs]> ");
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

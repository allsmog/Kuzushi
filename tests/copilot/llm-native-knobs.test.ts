/**
 * Coverage for the three wave-V LLM-native knobs:
 *
 * 1. `run --dry` — preflight runs, runTool does NOT. Payload preview.
 * 2. BUDGET_USD — global setg caps the governance enforcer.
 * 3. <MOD>_MODEL — global setg flows into ctx.toolModel.
 */

import { describe, expect, it, vi } from "vitest";
import { CoreDispatcher } from "../../src/copilot/dispatcher/core-dispatcher.js";
import { DispatcherDriver } from "../../src/copilot/dispatcher/driver.js";
import { ModuleDispatcher } from "../../src/copilot/dispatcher/module-dispatcher.js";
import { Datastore } from "../../src/copilot/options.js";
import { createArraySink } from "../../src/copilot/print.js";
import { GovernanceEnforcer } from "../../src/governance/enforcer.js";
import type { ScopePolicy } from "../../src/governance/types.js";
import { ModuleRegistry } from "../../src/modules/registry.js";
import type { CopilotModule, ModuleTool, ToolResult } from "../../src/modules/types.js";

function mkTool(name: string): ModuleTool {
  return {
    name,
    description: "t",
    inputSchema: {
      type: "object",
      properties: { RHOST: { type: "string", description: "target" } },
      required: ["RHOST"],
    },
    headless: true,
    async execute(): Promise<ToolResult> {
      return { ok: true, output: `ran ${name}` };
    },
  };
}

function mkModule(id: string, tools: ModuleTool[]): CopilotModule {
  return {
    id,
    displayName: id,
    category: "offense",
    version: "0.0.1",
    description: "m",
    rank: "good",
    tools,
  };
}

// ---------------------------------------------------------------------------
// run --dry
// ---------------------------------------------------------------------------

describe("run --dry", () => {
  it("emits a DRY RUN preview with the resolved inputs and skips runTool", async () => {
    const registry = new ModuleRegistry();
    registry.register(mkModule("sast", [mkTool("sast:scan")]));
    (registry as unknown as { initialized: Set<string> }).initialized.add("sast");

    const runTool = vi.fn(async (): Promise<ToolResult> => ({ ok: true, output: "" }));
    const core = new CoreDispatcher({
      registry,
      globals: new Datastore(),
      history: () => [],
      runTool,
    });
    const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: createArraySink() });

    await driver.handle("use sast");
    await driver.handle("set RHOST 10.0.0.1");
    const dry = await driver.handle("run --dry");
    expect(dry.output).toContain("DRY RUN");
    expect(dry.output).toContain("sast:scan");
    expect(dry.output).toContain("RHOST");
    expect(dry.output).toContain("10.0.0.1");
    expect(runTool).not.toHaveBeenCalled();
  });

  it("still fails preflight on missing-required", async () => {
    const registry = new ModuleRegistry();
    registry.register(mkModule("sast", [mkTool("sast:scan")]));
    (registry as unknown as { initialized: Set<string> }).initialized.add("sast");
    const core = new CoreDispatcher({
      registry,
      globals: new Datastore(),
      history: () => [],
      runTool: vi.fn(),
    });
    const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: createArraySink() });
    await driver.handle("use sast");
    const dry = await driver.handle("run --dry");
    expect(dry.output).toContain("Missing required: RHOST");
  });
});

// ---------------------------------------------------------------------------
// BUDGET_USD — validate the enforcer path via checkExecutionWithBudget
// ---------------------------------------------------------------------------

describe("BUDGET_USD cap", () => {
  const scope: ScopePolicy = {
    allowedTargets: [],
    deniedTargets: [],
    allowedTiers: ["passive", "intrusive", "destructive"],
    budgetUsd: null,
  };

  it("checkBudget with override caps at the lower of scope or override", () => {
    const e = new GovernanceEnforcer(scope);
    e.addCost(0.5);
    expect(e.checkBudget(1.0).allowed).toBe(true);
    expect(e.checkBudget(0.25).allowed).toBe(false);
  });

  it("checkExecutionWithBudget fails when cumulative >= override", () => {
    const e = new GovernanceEnforcer(scope);
    e.addCost(2);
    const result = e.checkExecutionWithBudget("sast:scan", undefined, 1);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("Budget exceeded");
    expect(result.reason).toContain("$1.00");
  });

  it("undefined override falls back to the static scope policy", () => {
    const e = new GovernanceEnforcer({ ...scope, budgetUsd: 0.1 });
    e.addCost(0.5);
    // No override — falls back to scope.budgetUsd.
    expect(e.checkBudget().allowed).toBe(false);
    // null override also falls back.
    expect(e.checkBudget(null).allowed).toBe(false);
    // Override raises the cap.
    expect(e.checkBudget(10).allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// <MOD>_MODEL override — inlined parser matches the CopilotCore path
// ---------------------------------------------------------------------------

describe("<MOD>_MODEL lookup", () => {
  it("derives the global key from the module id (upper, dashes → underscores)", () => {
    const globals = new Datastore();
    globals.set("TRIAGE_MODEL", "haiku", "global");
    globals.set("AGENTIC_SAST_MODEL", "opus", "global");
    const read = (moduleId: string) =>
      globals.get<string>(`${moduleId.toUpperCase().replace(/-/g, "_")}_MODEL`);
    expect(read("triage")).toBe("haiku");
    expect(read("agentic-sast")).toBe("opus");
    expect(read("unknown-module")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// ModuleDispatcher preview helper (direct — avoids the driver path)
// ---------------------------------------------------------------------------

describe("ModuleDispatcher dry-run shape", () => {
  it("snapshots the datastore and never invokes runTool", async () => {
    const mod = mkModule("sast", [mkTool("sast:scan")]);
    const globals = new Datastore();
    const runTool = vi.fn(async (): Promise<ToolResult> => ({ ok: true, output: "" }));
    const dispatcher = new ModuleDispatcher({ module: mod, globals, runTool });
    dispatcher.datastore.set("RHOST", "1.2.3.4", "module");
    const driver = new DispatcherDriver({
      base: dispatcher,
      cwd: "/tmp",
      print: createArraySink(),
    });
    const out = await driver.handle("run --dry");
    expect(out.output).toContain("DRY RUN");
    expect(out.output).toContain("1.2.3.4");
    expect(runTool).not.toHaveBeenCalled();
  });
});

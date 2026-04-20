import { describe, expect, it } from "vitest";
import { createCoreSastModule } from "../../src/modules/core-sast.js";
import { ModuleRegistry, parseModuleSpecifier } from "../../src/modules/registry.js";
import type { CopilotModule, ModuleTool, ToolResult } from "../../src/modules/types.js";

function makeDummyTool(name: string, headless = true): ModuleTool {
  return {
    name,
    description: `Dummy tool: ${name}`,
    inputSchema: { type: "object" },
    headless,
    async execute(): Promise<ToolResult> {
      return { ok: true, output: `executed ${name}` };
    },
  };
}

function makeDummyModule(id: string, tools: ModuleTool[] = []): CopilotModule {
  return {
    id,
    displayName: `Test Module: ${id}`,
    category: "offense",
    version: "1.0.0",
    description: `Dummy module for testing: ${id}`,
    tools,
  };
}

describe("ModuleRegistry", () => {
  it("registers and retrieves a module", () => {
    const reg = new ModuleRegistry();
    const mod = makeDummyModule("test");
    reg.register(mod);
    expect(reg.has("test")).toBe(true);
    expect(reg.get("test")).toBe(mod);
  });

  it("throws on duplicate registration", () => {
    const reg = new ModuleRegistry();
    reg.register(makeDummyModule("test"));
    expect(() => reg.register(makeDummyModule("test"))).toThrow("already registered");
  });

  it("throws on unknown module get", () => {
    const reg = new ModuleRegistry();
    expect(() => reg.get("nope")).toThrow("Unknown module");
  });

  it("lists registered modules", () => {
    const reg = new ModuleRegistry();
    reg.register(makeDummyModule("a", [makeDummyTool("a:run")]));
    reg.register(makeDummyModule("b"));
    const list = reg.list();
    expect(list).toHaveLength(2);
    expect(list[0].id).toBe("a");
    expect(list[0].toolCount).toBe(1);
    expect(list[1].id).toBe("b");
    expect(list[1].toolCount).toBe(0);
  });

  it("resolves fully-qualified tool names", () => {
    const reg = new ModuleRegistry();
    const tool = makeDummyTool("mymod:action");
    const mod = makeDummyModule("mymod", [tool]);
    reg.register(mod);
    // Must be initialized for allTools, but resolveTool works without init
    const resolved = reg.resolveTool("mymod:action");
    expect(resolved).toBeDefined();
    expect(resolved!.tool.name).toBe("mymod:action");
    expect(resolved!.module.id).toBe("mymod");
  });

  it("returns undefined for unknown tool", () => {
    const reg = new ModuleRegistry();
    reg.register(makeDummyModule("mymod"));
    expect(reg.resolveTool("mymod:nope")).toBeUndefined();
    expect(reg.resolveTool("nope:action")).toBeUndefined();
    expect(reg.resolveTool("nocolon")).toBeUndefined();
  });

  it("resolves tool names via registered alias", () => {
    const reg = new ModuleRegistry();
    const tool = makeDummyTool("semgrep:scan");
    reg.register(makeDummyModule("semgrep", [tool]));
    reg.registerAlias("sast:semgrep", "semgrep:scan");
    const resolved = reg.resolveTool("sast:semgrep");
    expect(resolved).toBeDefined();
    expect(resolved!.tool.name).toBe("semgrep:scan");
    expect(resolved!.module.id).toBe("semgrep");
  });

  it("alias to unknown tool returns undefined cleanly", () => {
    const reg = new ModuleRegistry();
    reg.registerAlias("sast:ghost", "missing:tool");
    expect(reg.resolveTool("sast:ghost")).toBeUndefined();
  });

  it("alias does not shadow a real tool with the same name", () => {
    const reg = new ModuleRegistry();
    const direct = makeDummyTool("sast:scan");
    reg.register(makeDummyModule("sast", [direct]));
    const elsewhere = makeDummyTool("other:scan");
    reg.register(makeDummyModule("other", [elsewhere]));
    reg.registerAlias("sast:scan", "other:scan");
    // Direct lookup wins.
    expect(reg.resolveTool("sast:scan")?.tool).toBe(direct);
  });

  it("listAliases returns all registered redirects", () => {
    const reg = new ModuleRegistry();
    reg.registerAlias("sast:semgrep", "semgrep:scan");
    reg.registerAlias("sast:codeql", "codeql:scan");
    const entries = reg
      .listAliases()
      .map((a) => `${a.from}=>${a.to}`)
      .sort();
    expect(entries).toEqual(["sast:codeql=>codeql:scan", "sast:semgrep=>semgrep:scan"]);
  });

  it("allTools filters by headless", () => {
    const reg = new ModuleRegistry();
    const headlessTool = makeDummyTool("m:headless", true);
    const interactiveTool = makeDummyTool("m:interactive", false);
    const mod = makeDummyModule("m", [headlessTool, interactiveTool]);
    reg.register(mod);
    // Mark as initialized so allTools returns them
    // (we need to use loadModule for proper init tracking, but for unit test we hack it)
    (reg as any).initialized.add("m");

    const all = reg.allTools();
    expect(all).toHaveLength(2);

    const headlessOnly = reg.allTools({ headlessOnly: true });
    expect(headlessOnly).toHaveLength(1);
    expect(headlessOnly[0].tool.name).toBe("m:headless");
  });

  it("unloads a module", async () => {
    const reg = new ModuleRegistry();
    let disposed = false;
    const mod: CopilotModule = {
      ...makeDummyModule("disposable"),
      async dispose() {
        disposed = true;
      },
    };
    reg.register(mod);
    (reg as any).initialized.add("disposable");

    await reg.unloadModule("disposable");
    expect(reg.has("disposable")).toBe(false);
    expect(disposed).toBe(true);
  });

  it("disposeAll disposes in reverse order", async () => {
    const reg = new ModuleRegistry();
    const order: string[] = [];
    for (const id of ["a", "b", "c"]) {
      const mod: CopilotModule = {
        ...makeDummyModule(id),
        async dispose() {
          order.push(id);
        },
      };
      reg.register(mod);
      (reg as any).initialized.add(id);
    }

    await reg.disposeAll();
    expect(order).toEqual(["c", "b", "a"]);
    expect(reg.ids()).toHaveLength(0);
  });
});

describe("parseModuleSpecifier", () => {
  it("parses builtin: prefix", () => {
    expect(parseModuleSpecifier("builtin:sast")).toEqual({ type: "builtin", id: "sast" });
  });

  it("parses file:// prefix", () => {
    expect(parseModuleSpecifier("file:///tmp/my-module")).toEqual({
      type: "local",
      path: "/tmp/my-module",
    });
  });

  it("parses package: prefix", () => {
    expect(parseModuleSpecifier("package:@kuzushi/blackbox")).toEqual({
      type: "package",
      name: "@kuzushi/blackbox",
    });
  });

  it("parses mcp: prefix", () => {
    expect(parseModuleSpecifier("mcp:http://localhost:3000")).toEqual({
      type: "mcp",
      serverUrl: "http://localhost:3000",
    });
  });

  it("treats bare strings as builtin", () => {
    expect(parseModuleSpecifier("sast")).toEqual({ type: "builtin", id: "sast" });
  });
});

describe("createCoreSastModule", () => {
  it("is now a slim umbrella owning only sast:scan", () => {
    const mod = createCoreSastModule();
    expect(mod.id).toBe("sast");
    expect(mod.category).toBe("defense");
    expect(mod.tools).toHaveLength(1);
    expect(mod.tools.map((t) => t.name)).toEqual(["sast:scan"]);
    // All tools should be headless
    for (const tool of mod.tools) {
      expect(tool.headless).toBe(true);
    }
  });

  it("legacy sast:<action> names resolve through aliases to the sub-modules", async () => {
    // Mirror what CopilotCore.init() does: load the family + register aliases.
    const { createSemgrepModule } = await import("../../src/modules/sast/core-semgrep.js");
    const { createCodeqlModule } = await import("../../src/modules/sast/core-codeql.js");
    const { createTriageModule } = await import("../../src/modules/sast/core-triage.js");
    const reg = new ModuleRegistry();
    for (const m of [
      createCoreSastModule(),
      createSemgrepModule(),
      createCodeqlModule(),
      createTriageModule(),
    ]) {
      reg.register(m);
      (reg as any).initialized.add(m.id);
    }
    reg.registerAlias("sast:semgrep", "semgrep:scan");
    reg.registerAlias("sast:codeql", "codeql:scan");
    reg.registerAlias("sast:triage", "triage:run");

    expect(reg.resolveTool("sast:semgrep")?.tool.name).toBe("semgrep:scan");
    expect(reg.resolveTool("sast:codeql")?.tool.name).toBe("codeql:scan");
    expect(reg.resolveTool("sast:triage")?.tool.name).toBe("triage:run");
    // Direct `sast:scan` still wins via direct lookup.
    expect(reg.resolveTool("sast:scan")?.tool.name).toBe("sast:scan");
  });
});

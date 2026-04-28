import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CoreDispatcher } from "../../src/copilot/dispatcher/core-dispatcher.js";
import { DispatcherDriver, splitPipeline } from "../../src/copilot/dispatcher/driver.js";
import { Datastore } from "../../src/copilot/options.js";
import { createArraySink } from "../../src/copilot/print.js";
import { ModuleRegistry } from "../../src/modules/registry.js";
import type { CopilotModule, ModuleTool, ToolResult } from "../../src/modules/types.js";

const tempDirs: string[] = [];
afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

function mkTool(name: string): ModuleTool {
  return {
    name,
    description: `dummy ${name}`,
    inputSchema: { type: "object", properties: {}, required: [] },
    headless: true,
    async execute(): Promise<ToolResult> {
      return { ok: true, output: `ran ${name}` };
    },
  };
}

function mkModule(id: string, opts: Partial<CopilotModule> = {}): CopilotModule {
  return {
    id,
    displayName: id,
    category: "defense",
    version: "0.0.1",
    description: `module ${id}`,
    rank: "good",
    tools: [mkTool(`${id}:run`)],
    ...opts,
  };
}

function seed() {
  const registry = new ModuleRegistry();
  registry.register(mkModule("sast"));
  registry.register(
    mkModule("semgrep", {
      examples: [
        "use semgrep\nset TARGET ./\nrun",
        "# strict\nuse semgrep\nset RULES p/strict\nrun",
      ],
    }),
  );
  (registry as unknown as { initialized: Set<string> }).initialized.add("sast");
  (registry as unknown as { initialized: Set<string> }).initialized.add("semgrep");
  const sink = createArraySink();
  const core = new CoreDispatcher({
    registry,
    globals: new Datastore(),
    history: () => ["modules", "use sast"],
  });
  const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: sink });
  return { driver, sink, registry };
}

describe("splitPipeline", () => {
  it("splits on unquoted pipes and respects quotes", () => {
    expect(splitPipeline("modules")).toEqual(["modules"]);
    expect(splitPipeline("modules | grep sast")).toEqual(["modules", "grep sast"]);
    expect(splitPipeline("modules | grep sast | head 3")).toEqual([
      "modules",
      "grep sast",
      "head 3",
    ]);
    expect(splitPipeline(`echo "a | b" | head 1`)).toEqual([`echo "a | b"`, "head 1"]);
  });
});

describe("output filters", () => {
  it("grep filters lines", async () => {
    const { driver } = seed();
    const result = await driver.handle("modules | grep semgrep");
    expect(result.output).toContain("semgrep");
    expect(result.output).not.toContain("sast ");
  });

  it("head limits lines", async () => {
    const { driver } = seed();
    const result = await driver.handle("modules | head 2");
    const lines = (result.output ?? "").split("\n");
    expect(lines).toHaveLength(2);
  });

  it("tail takes the last N lines", async () => {
    const { driver } = seed();
    const result = await driver.handle("modules | tail 2");
    expect((result.output ?? "").split("\n")).toHaveLength(2);
  });

  it("count reports line count", async () => {
    const { driver } = seed();
    const result = await driver.handle("modules | count");
    expect(result.output).toMatch(/\d+ lines/);
  });

  it("save writes to disk", async () => {
    const { driver } = seed();
    const dir = mkdtempSync(path.join(tmpdir(), "kz-save-"));
    tempDirs.push(dir);
    const file = path.join(dir, "out.txt");
    const result = await driver.handle(`modules | save ${file}`);
    expect(result.output).toContain("Wrote");
    const contents = readFileSync(file, "utf8");
    expect(contents).toContain("semgrep");
  });

  it("chains filters", async () => {
    const { driver } = seed();
    const result = await driver.handle("modules | grep good | head 1");
    expect((result.output ?? "").split("\n")).toHaveLength(1);
  });

  it("grep -v inverts the match", async () => {
    const { driver } = seed();
    const all = await driver.handle("modules");
    const inverted = await driver.handle("modules | grep -v semgrep");
    expect(all.output).toContain("semgrep");
    expect(inverted.output).not.toContain("semgrep");
  });

  it("grep -c prints just the match count", async () => {
    const { driver } = seed();
    const result = await driver.handle("modules | grep -c semgrep");
    expect(result.output).toMatch(/^\d+$/);
  });

  it("grep -A prints trailing context", async () => {
    const { driver } = seed();
    // Match the separator row; -A 1 should include one line after it.
    const result = await driver.handle("modules | grep -A 1 -- ---");
    const lines = (result.output ?? "").split("\n");
    expect(lines.length).toBeGreaterThanOrEqual(2);
  });

  it("grep -C wraps matches with before/after context", async () => {
    const { driver } = seed();
    const result = await driver.handle("modules | grep -C 1 semgrep");
    const lines = (result.output ?? "").split("\n");
    expect(lines.length).toBeGreaterThan(1);
    expect(result.output).toContain("semgrep");
  });

  it("page filter passes text through when stdout is not a TTY", async () => {
    const { driver } = seed();
    // Vitest drives stdout through pipes (non-TTY), so `| page` should return
    // the input unchanged rather than spawn a pager.
    const piped = await driver.handle("modules | page");
    const raw = await driver.handle("modules");
    expect(piped.output).toBe(raw.output);
  });
});

describe("typo correction", () => {
  it("suggests a near-match for unknown commands", async () => {
    const { driver } = seed();
    const result = await driver.handle("usr sast");
    expect(result.output).toContain("Unknown command: usr");
    expect(result.output).toContain("Did you mean: use?");
  });

  it("omits the hint when no command is close", async () => {
    const { driver } = seed();
    const result = await driver.handle("xyzzy foo");
    expect(result.output).toContain("Unknown command: xyzzy");
    expect(result.output).not.toContain("Did you mean");
  });
});

describe("aliases", () => {
  it("defines + expands + lists + removes aliases", async () => {
    const { driver } = seed();
    const define = await driver.handle("alias qs = modules");
    expect(define.output).toContain("Alias set");
    const list = await driver.handle("alias");
    expect(list.output).toContain("qs");
    expect(list.output).toContain("modules");
    // Expansion: typing `qs` runs `modules`.
    const expanded = await driver.handle("qs");
    expect(expanded.output).toContain("semgrep");
    const removed = await driver.handle("unalias qs");
    expect(removed.output).toContain("Removed alias");
  });
});

describe("favorites", () => {
  it("stars a module and creates a !N shortcut", async () => {
    const { driver } = seed();
    const star = await driver.handle("favorite modules");
    expect(star.output).toContain("Starred modules");
    const list = await driver.handle("favorites");
    expect(list.output).toContain("!1  modules");
    const recall = await driver.handle("!1");
    expect(recall.output).toContain("semgrep");
  });
});

describe("examples + tip", () => {
  it("renders registered examples", async () => {
    const { driver } = seed();
    const result = await driver.handle("examples semgrep");
    expect(result.output).toContain("use semgrep");
    expect(result.output).toContain("set RULES p/strict");
  });

  it("reports when a module has no examples", async () => {
    const { driver } = seed();
    const result = await driver.handle("examples sast");
    expect(result.output).toContain("no examples");
  });

  it("tip prints a tip from the canonical list", async () => {
    const { driver } = seed();
    const result = await driver.handle("tip");
    expect(result.output).toMatch(/^\[\*\] Tip: /);
  });
});

describe("why command", () => {
  it("explains missing snapshot prerequisites", async () => {
    const registry = new ModuleRegistry();
    const mod: CopilotModule = {
      ...mkModule("threat-hunt", {}),
      requires: [{ kind: "snapshot", moduleId: "context", field: "appModel" }],
    };
    registry.register(mod);
    (registry as unknown as { initialized: Set<string> }).initialized.add("threat-hunt");
    const sink = createArraySink();
    const core = new CoreDispatcher({ registry, globals: new Datastore(), history: () => [] });
    const driver = new DispatcherDriver({
      base: core,
      cwd: "/tmp",
      print: sink,
      getShellState: () => ({}),
    });
    await driver.handle("use threat-hunt");
    const result = await driver.handle("why");
    // The unmet-snapshot renderer prints `<moduleId>.<field>` so the operator
    // sees which module produces the missing artefact (e.g. "context.appModel")
    // rather than the bare "snapshot.appModel" the older format used.
    expect(result.output).toContain("context.appModel");
    expect(result.output).toContain("'use context' then 'run'");
  });

  it("no-op when no module is active", async () => {
    const { driver } = seed();
    const result = await driver.handle("why");
    expect(result.output).toContain("No module selected");
  });
});

describe("pushm / popm / listm", () => {
  it("saves and restores modules across detours", async () => {
    const { driver } = seed();
    await driver.handle("use sast");
    const pushed = await driver.handle("pushm");
    expect(pushed.output).toContain("Saved sast");
    await driver.handle("back");
    await driver.handle("use semgrep");
    const list = await driver.handle("listm");
    expect(list.output).toContain("sast");
    const popped = await driver.handle("popm");
    expect(popped.output).toContain("Popped sast");
  });

  it("popm on empty stack reports gracefully", async () => {
    const { driver } = seed();
    const result = await driver.handle("popm");
    expect(result.output).toContain("empty");
  });
});

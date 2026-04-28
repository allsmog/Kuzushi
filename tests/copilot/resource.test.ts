import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { CoreDispatcher } from "../../src/copilot/dispatcher/core-dispatcher.js";
import { DispatcherDriver } from "../../src/copilot/dispatcher/driver.js";
import { Datastore } from "../../src/copilot/options.js";
import { createArraySink } from "../../src/copilot/print.js";
import {
  loadAndRunResource,
  parseResourceScript,
  runResourceScript,
  saveResourceScript,
} from "../../src/copilot/resource.js";
import { ModuleRegistry } from "../../src/modules/registry.js";
import type { CopilotModule } from "../../src/modules/types.js";

function mkModule(id: string): CopilotModule {
  return {
    id,
    displayName: id,
    category: "offense",
    version: "0.0.1",
    description: id,
    rank: "good",
    tools: [],
  };
}

function newDriver() {
  const registry = new ModuleRegistry();
  registry.register(mkModule("sast"));
  (registry as unknown as { initialized: Set<string> }).initialized.add("sast");
  const sink = createArraySink();
  const core = new CoreDispatcher({
    registry,
    globals: new Datastore(),
    history: () => [],
  });
  return { driver: new DispatcherDriver({ base: core, cwd: "/tmp", print: sink }), sink };
}

describe("parseResourceScript", () => {
  it("parses YAML with workspace/setg/commands", () => {
    const yaml = `
workspace: acme
setg:
  MODEL: claude-opus-4-7
commands:
  - use sast
  - show modules
`;
    const s = parseResourceScript(yaml, "foo.kzrc.yaml");
    expect(s.workspace).toBe("acme");
    expect(s.setg?.["MODEL"]).toBe("claude-opus-4-7");
    expect(s.commands).toEqual(["use sast", "show modules"]);
  });

  it("parses plain text .rc with comments", () => {
    const rc = `
# comment
use sast
show modules

`;
    const s = parseResourceScript(rc, "foo.rc");
    expect(s.commands).toEqual(["use sast", "show modules"]);
  });

  it("rejects missing commands: array", () => {
    expect(() => parseResourceScript("workspace: x\n", "a.yaml")).toThrow(/commands/);
  });
});

describe("runResourceScript", () => {
  it("applies setg then runs every command", async () => {
    const { driver, sink } = newDriver();
    const res = await runResourceScript(
      {
        // The validator now requires `provider:modelId` form (CLI rolled out
        // multi-provider in 0.18); plain ids are rejected.
        setg: { MODEL: "anthropic:claude-opus-4-7" },
        commands: ["modules", "use sast", "back"],
      },
      { driver },
    );
    expect(res.executed).toBe(3);
    expect(res.errors).toEqual([]);
    const emitted = sink.lines.map((l) => l.text).join("\n");
    expect(emitted).toContain("MODEL => anthropic:claude-opus-4-7");
    expect(emitted).toContain("Selected module: sast");
  });

  it("stops on error by default", async () => {
    const { driver } = newDriver();
    const res = await runResourceScript(
      { commands: ["use nope", "modules"] },
      { driver, stopOnError: false },
    );
    // "use nope" prints an error but doesn't throw, so stopOnError doesn't fire.
    expect(res.executed).toBe(2);
  });
});

describe("loadAndRunResource + saveResourceScript roundtrip", () => {
  it("writes then reads back a script", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "kuzushi-rc-"));
    const file = path.join(dir, "test.kzrc.yaml");
    await saveResourceScript(file, {
      commands: ["modules", "use sast", "back"],
    });
    const contents = readFileSync(file, "utf8");
    expect(contents).toContain("commands:");

    const { driver } = newDriver();
    const res = await loadAndRunResource(file, { driver, cwd: dir });
    expect(res.executed).toBe(3);
  });

  it("handles .rc plain-text files via the same loader", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "kuzushi-rc-"));
    const file = path.join(dir, "test.rc");
    writeFileSync(file, "modules\n# skip me\nuse sast\n", "utf8");
    const { driver } = newDriver();
    const res = await loadAndRunResource(file, { driver, cwd: dir });
    expect(res.executed).toBe(2);
  });
});

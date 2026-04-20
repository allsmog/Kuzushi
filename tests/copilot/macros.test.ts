/**
 * Command macros — record a series of shell commands under a name,
 * replay later. Uses Driver.onCommand() to capture.
 */

import { describe, expect, it } from "vitest";
import { CoreDispatcher } from "../../src/copilot/dispatcher/core-dispatcher.js";
import { DispatcherDriver } from "../../src/copilot/dispatcher/driver.js";
import { Datastore } from "../../src/copilot/options.js";
import { createArraySink } from "../../src/copilot/print.js";
import { ModuleRegistry } from "../../src/modules/registry.js";

function seed(): DispatcherDriver {
  const registry = new ModuleRegistry();
  const core = new CoreDispatcher({
    registry,
    globals: new Datastore(),
    history: () => [],
  });
  return new DispatcherDriver({ base: core, cwd: "/tmp", print: createArraySink() });
}

describe("Driver.onCommand", () => {
  it("fires for every non-empty handled line", async () => {
    const driver = seed();
    const fired: string[] = [];
    const unsub = driver.onCommand((line) => fired.push(line));
    await driver.handle("modules");
    await driver.handle("help");
    expect(fired).toEqual(["modules", "help"]);
    unsub();
    await driver.handle("modules");
    expect(fired).toEqual(["modules", "help"]);
  });

  it("catches unknown commands handled by fallback", async () => {
    const driver = seed();
    const fired: string[] = [];
    driver.onCommand((l) => fired.push(l));
    // Unknown → fallback path; still not matched, so no fire.
    const result = await driver.handle("unknown-xyz");
    expect(result.matched).toBe(false);
    expect(fired).toEqual([]);
  });

  it("swallows observer exceptions", async () => {
    const driver = seed();
    driver.onCommand(() => {
      throw new Error("boom");
    });
    const result = await driver.handle("modules");
    expect(result.matched).toBe(true);
  });
});

describe("macro record / stop / play", () => {
  it("records, stops, and replays via macro play", async () => {
    const driver = seed();
    await driver.handle("macro record warmup");
    await driver.handle("help");
    await driver.handle("modules");
    await driver.handle("macro stop");
    const play = await driver.handle("macro play warmup");
    expect(play.output).toContain("Playing macro 'warmup' (2 lines)");
    // Each replayed command's output should be merged into the play output.
    expect(play.output).toMatch(/Available commands/); // from `help`
  });

  it("macro list surfaces saved macros", async () => {
    const driver = seed();
    await driver.handle("macro record a");
    await driver.handle("help");
    await driver.handle("macro stop");
    const list = await driver.handle("macro list");
    expect(list.output).toContain("a");
    expect(list.output).toContain("1 lines");
  });

  it("macro delete drops the macro", async () => {
    const driver = seed();
    await driver.handle("macro record tmp");
    await driver.handle("help");
    await driver.handle("macro stop");
    expect((await driver.handle("macro delete tmp")).output).toContain("Deleted");
    expect((await driver.handle("macro delete tmp")).output).toContain("No macro");
  });

  it("macro show prints the recorded line buffer", async () => {
    const driver = seed();
    await driver.handle("macro record peek");
    await driver.handle("help");
    await driver.handle("macro stop");
    const show = await driver.handle("macro show peek");
    expect(show.output).toContain("1  help");
  });

  it("rejects starting a recording while one is already active", async () => {
    const driver = seed();
    await driver.handle("macro record a");
    const second = await driver.handle("macro record b");
    expect(second.output).toContain("Already recording 'a'");
  });

  it("macro commands are not captured into the recording buffer", async () => {
    const driver = seed();
    await driver.handle("macro record safe");
    await driver.handle("help");
    await driver.handle("macro stop");
    const show = await driver.handle("macro show safe");
    expect(show.output).not.toContain("macro ");
    expect(show.output).toContain("help");
  });
});

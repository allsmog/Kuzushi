/**
 * Per-session interactive REPL — InteractiveSessionDispatcher pushed by
 * `sessions -I <ref>`. Drives each input line through
 * SessionHandle.interact() until `exit` / `background` / `back` pops.
 */

import { describe, expect, it, vi } from "vitest";
import { DispatcherDriver } from "../../src/copilot/dispatcher/driver.js";
import { InteractiveSessionDispatcher } from "../../src/copilot/dispatcher/session-repl.js";
import type { CommandDispatcher } from "../../src/copilot/dispatcher/types.js";
import { createArraySink } from "../../src/copilot/print.js";
import type { SessionHandle } from "../../src/sessions/manager.js";
import type { SessionRecord } from "../../src/workspace/entities.js";

function mkHandle(alias: string | null = null): {
  handle: SessionHandle;
  interact: ReturnType<typeof vi.fn>;
  id: string;
} {
  const id = "12345678-aaaa-bbbb-cccc-ffffffffffff";
  const interact = vi.fn(async (input: string) => `echo:${input}`);
  const record: SessionRecord = {
    id,
    workspaceId: "ws",
    hostId: null,
    serviceId: null,
    kind: "shell",
    state: "open",
    tunnelPeer: null,
    tunnelLocal: null,
    alias,
    description: null,
    viaModule: null,
    viaTool: null,
    openedAt: new Date().toISOString(),
    closedAt: null,
    metadata: {},
  };
  return {
    handle: { record, close: () => {}, interact },
    interact,
    id,
  };
}

function base(): CommandDispatcher {
  return {
    name: "core",
    commands: {},
    async execute() {
      return { output: "base" };
    },
  };
}

describe("InteractiveSessionDispatcher", () => {
  it("has a session-scoped name (alias preferred)", () => {
    const { handle, id } = mkHandle("acme-web");
    const d1 = new InteractiveSessionDispatcher(handle, id);
    expect(d1.name).toBe("session(acme-web)");
    const noAlias = mkHandle(null);
    const d2 = new InteractiveSessionDispatcher(noAlias.handle, noAlias.id);
    expect(d2.name).toBe(`session(${noAlias.id.slice(0, 8)})`);
  });

  it("forwards unknown lines to handle.interact()", async () => {
    const { handle, interact, id } = mkHandle();
    const driver = new DispatcherDriver({ base: base(), cwd: "/tmp", print: createArraySink() });
    const dispatcher = new InteractiveSessionDispatcher(handle, id);
    driver.push(dispatcher);
    const result = await driver.handle("whoami");
    expect(interact).toHaveBeenCalledWith("whoami", undefined);
    expect(result.output).toBe("echo:whoami");
  });

  it("exit / background / back all pop the dispatcher", async () => {
    const { handle, id } = mkHandle();
    for (const cmd of ["exit", "background", "back"]) {
      const driver = new DispatcherDriver({ base: base(), cwd: "/tmp", print: createArraySink() });
      const dispatcher = new InteractiveSessionDispatcher(handle, id);
      driver.push(dispatcher);
      expect(driver.stack()).toHaveLength(2);
      const result = await driver.handle(cmd);
      expect(result.output).toContain("Left session");
      // The driver consumed the pop so the stack returns to base.
      expect(driver.stack()).toHaveLength(1);
    }
  });

  it("help prints REPL usage", async () => {
    const { handle, id } = mkHandle();
    const driver = new DispatcherDriver({ base: base(), cwd: "/tmp", print: createArraySink() });
    driver.push(new InteractiveSessionDispatcher(handle, id));
    const result = await driver.handle("help");
    expect(result.output).toContain("Interactive session REPL");
  });

  it("reports when the session has no interact method", async () => {
    const { handle, id } = mkHandle();
    delete (handle as unknown as { interact?: unknown }).interact;
    const driver = new DispatcherDriver({ base: base(), cwd: "/tmp", print: createArraySink() });
    driver.push(new InteractiveSessionDispatcher(handle, id));
    const result = await driver.handle("whoami");
    expect(result.output).toContain("does not support interact");
  });

  it("surfaces interact() errors", async () => {
    const { handle, id } = mkHandle();
    (handle.interact as unknown as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("dead"));
    const driver = new DispatcherDriver({ base: base(), cwd: "/tmp", print: createArraySink() });
    driver.push(new InteractiveSessionDispatcher(handle, id));
    const result = await driver.handle("whoami");
    expect(result.output).toContain("dead");
  });
});

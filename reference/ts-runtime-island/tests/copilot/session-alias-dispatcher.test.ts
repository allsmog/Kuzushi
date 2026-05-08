import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { WorkspaceDispatcher } from "../../src/copilot/dispatcher/index.js";
import { createArraySink } from "../../src/copilot/print.js";
import { migration100 } from "../../src/migrations/100_schema_reset.js";
import { migration101 } from "../../src/migrations/101_workspace_entities.js";
import { migration102 } from "../../src/migrations/102_session_aliases.js";
import { WorkspaceManager } from "../../src/workspace/manager.js";

const tempDirs: string[] = [];

function mkDispatcher(): {
  dispatcher: WorkspaceDispatcher;
  mgr: WorkspaceManager;
  wsId: string;
  ctx: import("../../src/copilot/dispatcher/types.js").CommandContext;
} {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kz-session-disp-"));
  tempDirs.push(dir);
  const db = new Database(path.join(dir, "test.sqlite3"));
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  migration100.up(db);
  migration101.up(db);
  migration102.up(db);
  const mgr = new WorkspaceManager(db);
  const ws = mgr.create("disp-test", []);
  const dispatcher = new WorkspaceDispatcher({
    workspaces: mgr,
    activeWorkspaceId: () => ws.id,
  });
  const print = createArraySink();
  const ctx = {
    print,
    cwd: dir,
    driver: {
      // Minimal stub — the `sessions` command doesn't use most driver hooks.
      current: () => dispatcher,
      stack: () => [dispatcher],
      push: () => {},
      pop: () => undefined,
      prompt: () => "kuzushi > ",
      handle: async () => ({}),
      allCommands: () => [],
      complete: () => [],
      print,
    },
  } as unknown as import("../../src/copilot/dispatcher/types.js").CommandContext;
  return { dispatcher, mgr, wsId: ws.id, ctx };
}

afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

describe("WorkspaceDispatcher `sessions -n`", () => {
  it("sets an alias by id prefix", async () => {
    const { dispatcher, mgr, wsId, ctx } = mkDispatcher();
    const s = mgr.sessions.create({ workspaceId: wsId, kind: "shell" });
    const result = await dispatcher.execute("sessions", ["-n", s.id.slice(0, 8), "acme-web"], ctx);
    expect(result?.output).toContain("→ acme-web");
    expect(mgr.sessions.get(s.id)?.alias).toBe("acme-web");
  });

  it("clears an alias when omitted", async () => {
    const { dispatcher, mgr, wsId, ctx } = mkDispatcher();
    const s = mgr.sessions.create({ workspaceId: wsId, kind: "shell" });
    mgr.sessions.setAlias(s.id, "temp");
    const result = await dispatcher.execute("sessions", ["-n", s.id.slice(0, 8)], ctx);
    expect(result?.output).toContain("Cleared alias");
    expect(mgr.sessions.get(s.id)?.alias).toBeNull();
  });

  it("reports unknown refs", async () => {
    const { dispatcher, ctx } = mkDispatcher();
    const result = await dispatcher.execute("sessions", ["-n", "ghost", "x"], ctx);
    expect(result?.output).toContain("No session matches 'ghost'");
  });

  it("renders alias column in the default listing", async () => {
    const { dispatcher, mgr, wsId, ctx } = mkDispatcher();
    const s = mgr.sessions.create({ workspaceId: wsId, kind: "shell" });
    mgr.sessions.setAlias(s.id, "named");
    const result = await dispatcher.execute("sessions", [], ctx);
    expect(result?.output).toContain("Alias");
    expect(result?.output).toContain("named");
  });
});

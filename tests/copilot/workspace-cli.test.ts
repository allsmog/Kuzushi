/**
 * Workspace CRUD + entity write-side CLI coverage.
 *
 * Exercises the new CRUD verbs on `hosts / vulns / loot / notes / creds`
 * and the `creds -o csv|jtr|hcat` exporter. Workspace-level flags
 * (-a/-d/-r/-D/-v/-S) live on the slash-command handler in shell.ts and
 * are smoke-tested through the raw store APIs here.
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { WorkspaceDispatcher } from "../../src/copilot/dispatcher/index.js";
import { createArraySink } from "../../src/copilot/print.js";
import { migration100 } from "../../src/migrations/100_schema_reset.js";
import { migration101 } from "../../src/migrations/101_workspace_entities.js";
import { migration102 } from "../../src/migrations/102_session_aliases.js";
import { exportCreds } from "../../src/workspace/creds-export.js";
import { WorkspaceManager } from "../../src/workspace/manager.js";

const tempDirs: string[] = [];

function mkDispatcher(): {
  dispatcher: WorkspaceDispatcher;
  mgr: WorkspaceManager;
  wsId: string;
  dir: string;
  ctx: import("../../src/copilot/dispatcher/types.js").CommandContext;
} {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kz-ws-cli-"));
  tempDirs.push(dir);
  const db = new Database(path.join(dir, "test.sqlite3"));
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  migration100.up(db);
  migration101.up(db);
  migration102.up(db);
  const mgr = new WorkspaceManager(db);
  const ws = mgr.create("cli-test", []);
  const dispatcher = new WorkspaceDispatcher({ workspaces: mgr, activeWorkspaceId: () => ws.id });
  const print = createArraySink();
  const ctx = {
    print,
    cwd: dir,
    driver: {
      current: () => dispatcher,
      stack: () => [dispatcher],
      push: () => {},
      pop: () => undefined,
      prompt: () => "kuzushi> ",
      handle: async () => ({}),
      allCommands: () => [],
      complete: () => [],
      print,
    },
  } as unknown as import("../../src/copilot/dispatcher/types.js").CommandContext;
  return { dispatcher, mgr, wsId: ws.id, dir, ctx };
}

afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// loot
// ---------------------------------------------------------------------------

describe("loot write-side", () => {
  it("loot add --file stores file contents", async () => {
    const { dispatcher, mgr, wsId, dir, ctx } = mkDispatcher();
    const src = path.join(dir, "payload.bin");
    writeFileSync(src, "evidence");
    const result = await dispatcher.execute(
      "loot",
      ["add", "--type", "creds", "--name", "payload.bin", "--file", src],
      ctx,
    );
    expect(result?.output).toContain("Loot added");
    const rows = mgr.loot.listForWorkspace(wsId);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.data?.toString()).toBe("evidence");
  });

  it("loot add --data stores inline text", async () => {
    const { dispatcher, mgr, wsId, ctx } = mkDispatcher();
    await dispatcher.execute(
      "loot",
      ["add", "--type", "note", "--name", "inline.txt", "--data", "hello"],
      ctx,
    );
    expect(mgr.loot.listForWorkspace(wsId)[0]?.data?.toString()).toBe("hello");
  });

  it("loot save writes the blob back to disk", async () => {
    const { dispatcher, mgr, wsId, dir, ctx } = mkDispatcher();
    const row = mgr.loot.create({
      workspaceId: wsId,
      ltype: "file",
      name: "a.bin",
      data: Buffer.from("abc"),
    });
    const out = path.join(dir, "out.bin");
    const result = await dispatcher.execute("loot", ["save", row.id.slice(0, 8), out], ctx);
    expect(result?.output).toContain("Wrote 3 bytes");
    expect(readFileSync(out, "utf8")).toBe("abc");
  });

  it("loot delete drops the row", async () => {
    const { dispatcher, mgr, wsId, ctx } = mkDispatcher();
    const row = mgr.loot.create({ workspaceId: wsId, ltype: "file", name: "x" });
    await dispatcher.execute("loot", ["delete", row.id.slice(0, 8)], ctx);
    expect(mgr.loot.listForWorkspace(wsId)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// notes
// ---------------------------------------------------------------------------

describe("notes write-side", () => {
  it("notes add --data creates a record", async () => {
    const { dispatcher, mgr, wsId, ctx } = mkDispatcher();
    await dispatcher.execute("notes", ["add", "--type", "triage", "--data", "look here"], ctx);
    const rows = mgr.notes.listForWorkspace(wsId);
    expect(rows).toHaveLength(1);
    expect((rows[0]?.data as { note: string }).note).toBe("look here");
  });

  it("notes delete drops the row", async () => {
    const { dispatcher, mgr, wsId, ctx } = mkDispatcher();
    const row = mgr.notes.create({ workspaceId: wsId, ntype: "x", data: {} });
    await dispatcher.execute("notes", ["delete", row.id.slice(0, 8)], ctx);
    expect(mgr.notes.listForWorkspace(wsId)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// creds
// ---------------------------------------------------------------------------

describe("creds write-side + export", () => {
  it("creds add upserts a public/private pair", async () => {
    const { dispatcher, mgr, wsId, ctx } = mkDispatcher();
    await dispatcher.execute(
      "creds",
      ["add", "--user", "alice", "--private", "hunter2", "--private-type", "password"],
      ctx,
    );
    const rows = mgr.creds.listForWorkspace(wsId);
    expect(rows[0]?.publicUsername).toBe("alice");
    expect(rows[0]?.privateData).toBe("hunter2");
  });

  it("creds delete drops the row", async () => {
    const { dispatcher, mgr, wsId, ctx } = mkDispatcher();
    const row = mgr.creds.upsert({ workspaceId: wsId, publicUsername: "bob" });
    await dispatcher.execute("creds", ["delete", row.id.slice(0, 8)], ctx);
    expect(mgr.creds.listForWorkspace(wsId)).toHaveLength(0);
  });

  it("creds -o csv emits header + rows", async () => {
    const { mgr, wsId } = mkDispatcher();
    mgr.creds.upsert({
      workspaceId: wsId,
      publicUsername: "alice",
      privateType: "password",
      privateData: "hunter2",
    });
    const csv = exportCreds(mgr.creds.listForWorkspace(wsId), "csv");
    expect(csv.split("\n")[0]).toBe(
      "id,username,private_type,private_data,realm_kind,realm_value,origin_type",
    );
    expect(csv).toContain("alice");
    expect(csv).toContain("hunter2");
  });

  it("creds -o jtr emits user:hash lines", async () => {
    const { mgr, wsId } = mkDispatcher();
    mgr.creds.upsert({ workspaceId: wsId, publicUsername: "alice", privateData: "abc" });
    mgr.creds.upsert({ workspaceId: wsId, publicUsername: null, privateData: "orphan" });
    const jtr = exportCreds(mgr.creds.listForWorkspace(wsId), "jtr");
    expect(jtr).toBe("alice:abc\n");
  });

  it("creds -o hcat emits raw hashes only", async () => {
    const { mgr, wsId } = mkDispatcher();
    mgr.creds.upsert({ workspaceId: wsId, publicUsername: "alice", privateData: "h1" });
    mgr.creds.upsert({ workspaceId: wsId, publicUsername: "bob", privateData: "h2" });
    const hcat = exportCreds(mgr.creds.listForWorkspace(wsId), "hcat");
    expect(hcat).toBe("h1\nh2\n");
  });

  it("creds -o <fmt> <file> writes to disk", async () => {
    const { dispatcher, mgr, wsId, dir, ctx } = mkDispatcher();
    mgr.creds.upsert({ workspaceId: wsId, publicUsername: "x", privateData: "y" });
    const out = path.join(dir, "creds.jtr");
    const result = await dispatcher.execute("creds", ["-o", "jtr", out], ctx);
    expect(result?.output).toContain("→");
    expect(readFileSync(out, "utf8")).toBe("x:y\n");
  });
});

// ---------------------------------------------------------------------------
// hosts / vulns delete
// ---------------------------------------------------------------------------

describe("hosts / vulns delete", () => {
  it("hosts -d <addr> removes a host", async () => {
    const { dispatcher, mgr, wsId, ctx } = mkDispatcher();
    mgr.hosts.upsert({ workspaceId: wsId, address: "10.0.0.5" });
    await dispatcher.execute("hosts", ["-d", "10.0.0.5"], ctx);
    expect(mgr.hosts.list(wsId)).toHaveLength(0);
  });

  it("vulns -d <id> removes a vuln", async () => {
    const { dispatcher, mgr, wsId, ctx } = mkDispatcher();
    const v = mgr.vulns.create({ workspaceId: wsId, name: "x", references: [] });
    await dispatcher.execute("vulns", ["-d", v.id.slice(0, 8)], ctx);
    expect(mgr.vulns.listForWorkspace(wsId)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Workspace-level CRUD (via WorkspaceManager — slash-command handler thin)
// ---------------------------------------------------------------------------

describe("WorkspaceManager CRUD helpers", () => {
  it("delete + rename round-trip", () => {
    const { mgr } = mkDispatcher();
    const a = mgr.create("alpha", []);
    expect(mgr.getByName("alpha")?.id).toBe(a.id);
    mgr.update(a.id, { name: "alpha-renamed" });
    expect(mgr.getByName("alpha")).toBeNull();
    expect(mgr.getByName("alpha-renamed")?.id).toBe(a.id);
    mgr.delete(a.id);
    expect(mgr.getByName("alpha-renamed")).toBeNull();
  });
});

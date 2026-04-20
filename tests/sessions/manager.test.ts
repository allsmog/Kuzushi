import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { migration100 } from "../../src/migrations/100_schema_reset.js";
import { migration101 } from "../../src/migrations/101_workspace_entities.js";
import { migration102 } from "../../src/migrations/102_session_aliases.js";
import { SessionManager } from "../../src/sessions/manager.js";
import type { SessionRecord } from "../../src/workspace/entities.js";
import { SessionStore } from "../../src/workspace/entities.js";
import { WorkspaceManager } from "../../src/workspace/manager.js";

const tempDirs: string[] = [];

function createTestDb(): Database.Database {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-sessmgr-test-"));
  tempDirs.push(dir);
  const db = new Database(path.join(dir, "test.sqlite3"));
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  migration100.up(db);
  migration101.up(db);
  migration102.up(db);
  return db;
}

afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

describe("SessionManager", () => {
  it("opens a session, tracks the live handle, and closes with state=closed", async () => {
    const db = createTestDb();
    const wsMgr = new WorkspaceManager(db);
    const ws = wsMgr.create("e", []);
    const store = new SessionStore(db);
    const mgr = new SessionManager(store);

    let closed = false;
    const record = await mgr.open(
      { workspaceId: ws.id, kind: "honeypot", viaTool: "honeypot:run" },
      (rec: SessionRecord) => ({
        record: rec,
        close: () => {
          closed = true;
        },
      }),
    );

    const live = mgr.getLive(record.id);
    expect(live).toBeTruthy();
    await mgr.close(record.id, "closed");
    expect(closed).toBe(true);
    const reloaded = wsMgr.sessions.get(record.id);
    expect(reloaded?.state).toBe("closed");
    expect(mgr.getLive(record.id)).toBeUndefined();
  });

  it("emits session:open and session:close events", async () => {
    const db = createTestDb();
    const ws = new WorkspaceManager(db).create("e", []);
    const store = new SessionStore(db);
    const mgr = new SessionManager(store);
    const events: string[] = [];
    mgr.on("session:open", (r) => events.push(`open:${r.kind}`));
    mgr.on("session:close", (r, why) => events.push(`close:${r.kind}:${why}`));
    const rec = await mgr.open({ workspaceId: ws.id, kind: "ssh" }, (r: SessionRecord) => ({
      record: r,
      close: () => {},
    }));
    await mgr.close(rec.id, "closed");
    expect(events).toEqual(["open:ssh", "close:ssh:closed"]);
  });

  it("closeAll drains every live handle", async () => {
    const db = createTestDb();
    const ws = new WorkspaceManager(db).create("e", []);
    const mgr = new SessionManager(new SessionStore(db));
    const closes: string[] = [];
    const factory = (id: string) => (rec: SessionRecord) => ({
      record: rec,
      close: () => {
        closes.push(id);
      },
    });
    const a = await mgr.open({ workspaceId: ws.id, kind: "ssh" }, factory("a"));
    const b = await mgr.open({ workspaceId: ws.id, kind: "browser" }, factory("b"));
    expect(mgr.liveForWorkspace(ws.id)).toHaveLength(2);
    await mgr.closeAll();
    expect(closes.sort()).toEqual(["a", "b"]);
    expect(mgr.liveForWorkspace(ws.id)).toHaveLength(0);
    // Records preserved in DB with state=closed.
    const wsMgr = new WorkspaceManager(db);
    expect(wsMgr.sessions.get(a.id)?.state).toBe("closed");
    expect(wsMgr.sessions.get(b.id)?.state).toBe("closed");
  });
});

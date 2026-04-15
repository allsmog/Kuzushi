import { afterEach, describe, expect, it } from "vitest";
import os from "node:os";
import path from "node:path";
import { mkdtempSync, rmSync } from "node:fs";
import Database from "better-sqlite3";
import { WorkspaceManager } from "../../src/workspace/manager.js";
import { migration025 } from "../../src/migrations/025_add_workspaces_table.js";
import type { ContextSnapshot } from "../../src/ui/state.js";

const tempDirs: string[] = [];

function createTestDb(): Database.Database {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-ws-test-"));
  tempDirs.push(dir);
  const db = new Database(path.join(dir, "test.sqlite3"));
  db.pragma("journal_mode = WAL");
  migration025.up(db);
  return db;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("WorkspaceManager", () => {
  it("creates and retrieves workspaces", () => {
    const db = createTestDb();
    const mgr = new WorkspaceManager(db);

    const ws = mgr.create("acme-pentest", ["./acme-api"]);
    expect(ws.id).toBeTruthy();
    expect(ws.name).toBe("acme-pentest");
    expect(ws.targets).toEqual(["./acme-api"]);

    const fetched = mgr.get(ws.id);
    expect(fetched).not.toBeNull();
    expect(fetched!.name).toBe("acme-pentest");

    const byName = mgr.getByName("acme-pentest");
    expect(byName).not.toBeNull();
    expect(byName!.id).toBe(ws.id);
  });

  it("getOrCreate returns existing or creates new", () => {
    const db = createTestDb();
    const mgr = new WorkspaceManager(db);

    const ws1 = mgr.getOrCreate("test-ws");
    const ws2 = mgr.getOrCreate("test-ws");
    expect(ws1.id).toBe(ws2.id);

    const ws3 = mgr.getOrCreate("other-ws", ["./repo"]);
    expect(ws3.id).not.toBe(ws1.id);
    expect(ws3.targets).toEqual(["./repo"]);
  });

  it("lists workspaces ordered by last access", () => {
    const db = createTestDb();
    const mgr = new WorkspaceManager(db);

    const ws1 = mgr.create("alpha");
    const ws2 = mgr.create("beta");
    mgr.touchAccessed(ws1.id);

    const list = mgr.list();
    expect(list).toHaveLength(2);
    expect(list[0]!.id).toBe(ws1.id);
    expect(list[1]!.id).toBe(ws2.id);
  });

  it("updates workspace fields", () => {
    const db = createTestDb();
    const mgr = new WorkspaceManager(db);

    const ws = mgr.create("test");
    mgr.update(ws.id, { targets: ["./a", "./b"], metadata: { cost: 1.5 } });

    const updated = mgr.get(ws.id)!;
    expect(updated.targets).toEqual(["./a", "./b"]);
    expect(updated.metadata).toEqual({ cost: 1.5 });
  });

  it("addTarget appends without duplicates", () => {
    const db = createTestDb();
    const mgr = new WorkspaceManager(db);

    const ws = mgr.create("test", ["./a"]);
    mgr.addTarget(ws.id, "./b");
    mgr.addTarget(ws.id, "./a");

    const updated = mgr.get(ws.id)!;
    expect(updated.targets).toEqual(["./a", "./b"]);
  });

  it("deletes workspaces and cascades snapshots", () => {
    const db = createTestDb();
    const mgr = new WorkspaceManager(db);

    const ws = mgr.create("doomed");
    const snapshot: ContextSnapshot = {
      target: "./repo",
      timestamp: Date.now(),
      discovery: "flat",
      options: { enrichment: true, threatModel: true, scenarios: true },
    };
    mgr.saveSnapshot(ws.id, snapshot);

    mgr.delete(ws.id);
    expect(mgr.get(ws.id)).toBeNull();

    const rows = db.prepare("SELECT * FROM workspace_snapshots WHERE workspace_id = ?").all(ws.id);
    expect(rows).toHaveLength(0);
  });

  it("persists and loads context snapshots", () => {
    const db = createTestDb();
    const mgr = new WorkspaceManager(db);

    const ws = mgr.create("snapshot-test");
    expect(mgr.loadLatestSnapshot(ws.id)).toBeNull();

    const snapshot1: ContextSnapshot = {
      target: "./repo",
      timestamp: 1000,
      discovery: "flat",
      options: { enrichment: true, threatModel: false, scenarios: false },
      repoContext: { languages: ["TypeScript"] },
    };
    mgr.saveSnapshot(ws.id, snapshot1);

    const snapshot2: ContextSnapshot = {
      target: "./repo",
      timestamp: 2000,
      discovery: "flat",
      options: { enrichment: true, threatModel: true, scenarios: true },
      repoContext: { languages: ["TypeScript", "Go"] },
    };
    mgr.saveSnapshot(ws.id, snapshot2);

    const latest = mgr.loadLatestSnapshot(ws.id);
    expect(latest).not.toBeNull();
    expect(latest!.timestamp).toBe(2000);
    expect((latest!.repoContext as Record<string, unknown>).languages).toEqual(["TypeScript", "Go"]);
  });
});

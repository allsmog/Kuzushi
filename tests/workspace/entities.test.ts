import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { migration100 } from "../../src/migrations/100_schema_reset.js";
import { migration101 } from "../../src/migrations/101_workspace_entities.js";
import { WorkspaceManager } from "../../src/workspace/manager.js";

const tempDirs: string[] = [];

function createTestDb(): Database.Database {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-entities-test-"));
  tempDirs.push(dir);
  const db = new Database(path.join(dir, "test.sqlite3"));
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  migration100.up(db);
  migration101.up(db);
  return db;
}

afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

describe("hosts/services/vulns", () => {
  it("upserts hosts and services with unique constraints", () => {
    const db = createTestDb();
    const mgr = new WorkspaceManager(db);
    const ws = mgr.create("e", []);
    const h1 = mgr.hosts.upsert({ workspaceId: ws.id, address: "10.0.0.1", osName: "linux" });
    const h2 = mgr.hosts.upsert({
      workspaceId: ws.id,
      address: "10.0.0.1",
      osName: "linux",
      osVersion: "6.1",
    });
    expect(h1.id).toBe(h2.id);
    expect(h2.osVersion).toBe("6.1");

    const s1 = mgr.services.upsert({ hostId: h1.id, port: 22, proto: "tcp", name: "ssh" });
    const s2 = mgr.services.upsert({ hostId: h1.id, port: 22, proto: "tcp", state: "filtered" });
    expect(s1.id).toBe(s2.id);
    expect(s2.state).toBe("filtered");

    const list = mgr.services.listForHost(h1.id);
    expect(list).toHaveLength(1);
  });

  it("records vulns linked to host + finding fingerprint", () => {
    const db = createTestDb();
    const mgr = new WorkspaceManager(db);
    const ws = mgr.create("e", []);
    const host = mgr.hosts.create({ workspaceId: ws.id, address: "10.0.0.2" });
    const v = mgr.vulns.create({
      workspaceId: ws.id,
      hostId: host.id,
      name: "MS17-010",
      description: "SMB RCE",
      severity: "critical",
      references: [{ type: "CVE", value: "2017-0143" }],
      checkCode: "vulnerable",
      checkReason: "SMB1 banner + exploitable",
    });
    expect(v.checkCode).toBe("vulnerable");
    const loaded = mgr.vulns.get(v.id);
    expect(loaded?.references?.[0]).toEqual({ type: "CVE", value: "2017-0143" });
  });
});

describe("loot + notes", () => {
  it("stores inline loot data with type", () => {
    const db = createTestDb();
    const mgr = new WorkspaceManager(db);
    const ws = mgr.create("e", []);
    const loot = mgr.loot.create({
      workspaceId: ws.id,
      ltype: "file.config",
      name: "web.config",
      data: Buffer.from("<config/>"),
      info: "exfil from webapp",
    });
    expect(loot.data?.toString()).toContain("<config/>");
    const list = mgr.loot.listForWorkspace(ws.id, "file.config");
    expect(list).toHaveLength(1);
  });

  it("stores notes filterable by ntype", () => {
    const db = createTestDb();
    const mgr = new WorkspaceManager(db);
    const ws = mgr.create("e", []);
    mgr.notes.create({ workspaceId: ws.id, ntype: "observation", data: { what: "x" } });
    mgr.notes.create({ workspaceId: ws.id, ntype: "plan", data: { next: "y" } });
    expect(mgr.notes.listForWorkspace(ws.id)).toHaveLength(2);
    expect(mgr.notes.listForWorkspace(ws.id, "plan")).toHaveLength(1);
  });
});

describe("creds + logins", () => {
  it("dedupes identical creds on upsert", () => {
    const db = createTestDb();
    const mgr = new WorkspaceManager(db);
    const ws = mgr.create("e", []);
    const c1 = mgr.creds.upsert({
      workspaceId: ws.id,
      publicUsername: "admin",
      privateType: "password",
      privateData: "hunter2",
    });
    const c2 = mgr.creds.upsert({
      workspaceId: ws.id,
      publicUsername: "admin",
      privateType: "password",
      privateData: "hunter2",
    });
    expect(c1.id).toBe(c2.id);
    expect(mgr.creds.listForWorkspace(ws.id)).toHaveLength(1);
  });

  it("records cred×service logins", () => {
    const db = createTestDb();
    const mgr = new WorkspaceManager(db);
    const ws = mgr.create("e", []);
    const host = mgr.hosts.create({ workspaceId: ws.id, address: "10.0.0.9" });
    const svc = mgr.services.create({ hostId: host.id, port: 22, proto: "tcp", name: "ssh" });
    const cred = mgr.creds.create({
      workspaceId: ws.id,
      publicUsername: "root",
      privateType: "ssh_key",
      privateData: "PEM...",
    });
    const login = mgr.creds.recordLogin({
      credId: cred.id,
      serviceId: svc.id,
      status: "successful",
    });
    expect(login.status).toBe("successful");
    const all = mgr.creds.loginsFor(cred.id);
    expect(all).toHaveLength(1);
  });
});

describe("sessions", () => {
  it("opens, updates, and closes a session", () => {
    const db = createTestDb();
    const mgr = new WorkspaceManager(db);
    const ws = mgr.create("e", []);
    const sess = mgr.sessions.create({
      workspaceId: ws.id,
      kind: "ssh",
      tunnelPeer: "10.0.0.9:22",
      viaTool: "blackbox:ssh-connect",
    });
    expect(sess.state).toBe("open");
    mgr.sessions.update(sess.id, { description: "root shell" });
    const reloaded = mgr.sessions.get(sess.id);
    expect(reloaded?.description).toBe("root shell");
    mgr.sessions.close(sess.id);
    const closed = mgr.sessions.get(sess.id);
    expect(closed?.state).toBe("closed");
    expect(closed?.closedAt).toBeTruthy();
    expect(mgr.sessions.listForWorkspace(ws.id, { openOnly: true })).toHaveLength(0);
  });
});

describe("cascade delete", () => {
  it("removes child rows when workspace is deleted", () => {
    const db = createTestDb();
    const mgr = new WorkspaceManager(db);
    const ws = mgr.create("e", []);
    const host = mgr.hosts.create({ workspaceId: ws.id, address: "10.0.0.3" });
    mgr.services.create({ hostId: host.id, port: 80 });
    mgr.vulns.create({ workspaceId: ws.id, hostId: host.id, name: "X" });
    mgr.notes.create({ workspaceId: ws.id, ntype: "t", data: {} });
    mgr.delete(ws.id);
    expect(mgr.hosts.list(ws.id)).toHaveLength(0);
    expect(mgr.vulns.listForWorkspace(ws.id)).toHaveLength(0);
    expect(mgr.notes.listForWorkspace(ws.id)).toHaveLength(0);
  });
});

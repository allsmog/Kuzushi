import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { migration100 } from "../../src/migrations/100_schema_reset.js";
import { migration101 } from "../../src/migrations/101_workspace_entities.js";
import type { WorkspaceVulnStore } from "../../src/modules/host-handles.js";
import { createMockWorkspace } from "../../src/testing/mocks/workspace.js";
import { WorkspaceManager } from "../../src/workspace/manager.js";

const tempDirs: string[] = [];
afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

function mkManager(): WorkspaceManager {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-vulns-"));
  tempDirs.push(dir);
  const db = new Database(path.join(dir, "ws.sqlite3"));
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  migration100.up(db);
  migration101.up(db);
  return new WorkspaceManager(db);
}

describe("WorkspaceVulnStore.create (HOST extension)", () => {
  it("the host VulnStore satisfies the narrow create() contract", () => {
    const mgr = mkManager();
    const handle: WorkspaceVulnStore = mgr.vulns;
    expect(typeof handle.create).toBe("function");
    expect(typeof handle.listForWorkspace).toBe("function");
  });

  it("a third-party module can persist a finding via the narrow handle", () => {
    const mgr = mkManager();
    const ws = mgr.create("tw", []);
    const handle: WorkspaceVulnStore = mgr.vulns;
    const created = handle.create?.({
      workspaceId: ws.id,
      name: "Hardcoded credential",
      severity: "high",
    });
    expect(created).toBeTruthy();
    const list = handle.listForWorkspace(ws.id);
    expect(list).toHaveLength(1);
  });

  it("MockWorkspace records vulns.create calls and reflects them in reads", () => {
    const ws = createMockWorkspace();
    expect(ws.vulnCreates).toHaveLength(0);
    const created = ws.vulns.create?.({
      workspaceId: "w-1",
      name: "x",
      severity: "low",
    });
    expect(created).toEqual({ workspaceId: "w-1", name: "x", severity: "low" });
    expect(ws.vulnCreates).toHaveLength(1);
    expect(ws.vulns.listForWorkspace("w-1")).toHaveLength(1);
  });

  it("MockWorkspace.clear() also resets vulnCreates", () => {
    const ws = createMockWorkspace();
    ws.vulns.create?.({ workspaceId: "w", name: "y" });
    ws.clear();
    expect(ws.vulnCreates).toHaveLength(0);
  });

  it("create() is optional on the narrow handle so legacy implementations still type-check", () => {
    const minimal: WorkspaceVulnStore = {
      listForWorkspace: () => [],
    };
    expect(minimal.create).toBeUndefined();
  });
});

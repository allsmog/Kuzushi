import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { migration100 } from "../../src/migrations/100_schema_reset.js";
import { migration101 } from "../../src/migrations/101_workspace_entities.js";
import { migration102 } from "../../src/migrations/102_session_aliases.js";
import { WorkspaceManager } from "../../src/workspace/manager.js";

const tempDirs: string[] = [];

function mkWorkspace(): { mgr: WorkspaceManager; wsId: string } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kz-session-alias-"));
  tempDirs.push(dir);
  const db = new Database(path.join(dir, "test.sqlite3"));
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  migration100.up(db);
  migration101.up(db);
  migration102.up(db);
  const mgr = new WorkspaceManager(db);
  const ws = mgr.create("alias-test", []);
  return { mgr, wsId: ws.id };
}

afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

describe("SessionStore alias + resolveRef", () => {
  it("new rows default alias to null", () => {
    const { mgr, wsId } = mkWorkspace();
    const s = mgr.sessions.create({ workspaceId: wsId, kind: "shell" });
    expect(s.alias).toBeNull();
  });

  it("setAlias + resolveRef by alias", () => {
    const { mgr, wsId } = mkWorkspace();
    const s = mgr.sessions.create({ workspaceId: wsId, kind: "shell" });
    mgr.sessions.setAlias(s.id, "acme-web");
    expect(mgr.sessions.get(s.id)?.alias).toBe("acme-web");
    const resolved = mgr.sessions.resolveRef(wsId, "acme-web");
    expect(resolved).toEqual({ id: s.id });
  });

  it("resolveRef by id prefix", () => {
    const { mgr, wsId } = mkWorkspace();
    const s = mgr.sessions.create({ workspaceId: wsId, kind: "shell" });
    const resolved = mgr.sessions.resolveRef(wsId, s.id.slice(0, 8));
    expect(resolved).toEqual({ id: s.id });
  });

  it("resolveRef reports ambiguity when two aliases match", () => {
    const { mgr, wsId } = mkWorkspace();
    const a = mgr.sessions.create({ workspaceId: wsId, kind: "shell" });
    const b = mgr.sessions.create({ workspaceId: wsId, kind: "shell" });
    mgr.sessions.setAlias(a.id, "same");
    mgr.sessions.setAlias(b.id, "same");
    const resolved = mgr.sessions.resolveRef(wsId, "same");
    expect(resolved && "ambiguous" in resolved && resolved.ambiguous.sort()).toEqual(
      [a.id, b.id].sort(),
    );
  });

  it("resolveRef returns null when nothing matches", () => {
    const { mgr, wsId } = mkWorkspace();
    expect(mgr.sessions.resolveRef(wsId, "ghost")).toBeNull();
  });

  it("clearing an alias sets the column back to null", () => {
    const { mgr, wsId } = mkWorkspace();
    const s = mgr.sessions.create({ workspaceId: wsId, kind: "shell" });
    mgr.sessions.setAlias(s.id, "temp");
    mgr.sessions.setAlias(s.id, null);
    expect(mgr.sessions.get(s.id)?.alias).toBeNull();
  });
});

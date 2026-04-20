import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { migration100 } from "../../src/migrations/100_schema_reset.js";
import { migration101 } from "../../src/migrations/101_workspace_entities.js";
import { createReconModule } from "../../src/modules/recon/core-recon.js";
import type { ToolExecutionContext } from "../../src/modules/types.js";
import type { KuzushiConfig } from "../../src/types.js";
import { WorkspaceManager } from "../../src/workspace/manager.js";

const tempDirs: string[] = [];
afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

function mkWorkspace(): { mgr: WorkspaceManager; wsId: string } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-recon-"));
  tempDirs.push(dir);
  const db = new Database(path.join(dir, "test.sqlite3"));
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  migration100.up(db);
  migration101.up(db);
  const mgr = new WorkspaceManager(db);
  const ws = mgr.create("e", []);
  return { mgr, wsId: ws.id };
}

function mkCtx(mgr: WorkspaceManager, wsId: string): ToolExecutionContext {
  return {
    cwd: "/tmp",
    runtime: { id: "test", async *query() {} },
    bus: {} as ToolExecutionContext["bus"],
    config: {
      model: "anthropic:claude-sonnet-4-6",
      busBackend: "in-process",
      triageBatchSize: 5,
      triageConcurrency: 2,
      scanMode: "parallel",
      tasks: [],
      severity: [],
      excludePatterns: [],
      taskConfig: {},
    } as KuzushiConfig,
    workspace: mgr,
    workspaceId: wsId,
  };
}

describe("recon module", () => {
  it("has expected id + tools + metadata", () => {
    const mod = createReconModule();
    expect(mod.id).toBe("recon");
    expect(mod.category).toBe("intel");
    expect(mod.tools.map((t) => t.name).sort()).toEqual([
      "recon:http-fingerprint",
      "recon:nmap",
      "recon:subdomain",
    ]);
    expect(mod.examples?.length).toBeGreaterThan(0);
  });

  it("recon:http-fingerprint writes host + service into workspace", async () => {
    const { mgr, wsId } = mkWorkspace();
    const tool = createReconModule().tools.find((t) => t.name === "recon:http-fingerprint")!;
    const result = await tool.execute({ target: "https://acme.example" }, mkCtx(mgr, wsId));
    expect(result.ok).toBe(true);

    const hosts = mgr.hosts.list(wsId);
    expect(hosts).toHaveLength(1);
    expect(hosts[0].address).toBe("acme.example");

    const services = mgr.services.listForHost(hosts[0].id);
    expect(services).toHaveLength(1);
    expect(services[0].port).toBe(443);
    expect(services[0].name).toBe("https");
  });

  it("recon:subdomain records a pending note when no live source is wired", async () => {
    const { mgr, wsId } = mkWorkspace();
    const tool = createReconModule().tools.find((t) => t.name === "recon:subdomain")!;
    const result = await tool.execute({ domain: "acme.example" }, mkCtx(mgr, wsId));
    expect(result.ok).toBe(true);
    const notes = mgr.notes.listForWorkspace(wsId, "recon:subdomain-pending");
    expect(notes).toHaveLength(1);
    expect(notes[0].data).toMatchObject({ domain: "acme.example" });
  });

  it("fails gracefully without a workspace", async () => {
    const tool = createReconModule().tools.find((t) => t.name === "recon:http-fingerprint")!;
    const result = await tool.execute({ target: "acme.example" }, {
      cwd: "/tmp",
      runtime: { id: "test", async *query() {} },
      bus: {} as ToolExecutionContext["bus"],
      config: {} as KuzushiConfig,
    } as ToolExecutionContext);
    expect(result.ok).toBe(false);
    expect(result.output).toContain("active workspace");
  });
});

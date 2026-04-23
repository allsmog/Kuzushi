import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { migration100 } from "../../src/migrations/100_schema_reset.js";
import { migration101 } from "../../src/migrations/101_workspace_entities.js";
import { createFindingsModule } from "../../src/modules/findings/findings.js";
import type { ToolExecutionContext } from "../../src/modules/types.js";
import type { KuzushiConfig } from "../../src/types.js";
import { WorkspaceManager } from "../../src/workspace/manager.js";

const tempDirs: string[] = [];
afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

function mkWorkspace(): { mgr: WorkspaceManager; wsId: string } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-findings-list-"));
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

describe("findings:list tool", () => {
  it("returns an error when no workspace is active", async () => {
    const mod = createFindingsModule();
    const tool = mod.tools.find((t) => t.name === "findings:list");
    const result = await tool!.execute({}, {
      cwd: "/tmp",
      runtime: { id: "test", async *query() {} },
      bus: {} as ToolExecutionContext["bus"],
      config: {} as KuzushiConfig,
    } as ToolExecutionContext);
    expect(result.ok).toBe(false);
    expect(result.output).toContain("active workspace");
  });

  it("lists vulns from the active workspace", async () => {
    const { mgr, wsId } = mkWorkspace();
    mgr.vulns.create({
      workspaceId: wsId,
      name: "SSRF in /fetch",
      severity: "critical",
      checkCode: "vulnerable",
    });
    mgr.vulns.create({
      workspaceId: wsId,
      name: "Hardcoded token in tests",
      severity: "low",
      checkCode: "detected",
    });
    const tool = createFindingsModule().tools.find((t) => t.name === "findings:list")!;
    const result = await tool.execute({}, mkCtx(mgr, wsId));
    expect(result.ok).toBe(true);
    expect(result.output).toContain("SSRF in /fetch");
    expect(result.output).toContain("Hardcoded token in tests");
    const data = result.data as { count: number };
    expect(data.count).toBe(2);
  });

  it("filters by severity", async () => {
    const { mgr, wsId } = mkWorkspace();
    mgr.vulns.create({ workspaceId: wsId, name: "A", severity: "critical" });
    mgr.vulns.create({ workspaceId: wsId, name: "B", severity: "low" });
    mgr.vulns.create({ workspaceId: wsId, name: "C", severity: "high" });
    const tool = createFindingsModule().tools.find((t) => t.name === "findings:list")!;
    const result = await tool.execute({ severity: ["critical", "high"] }, mkCtx(mgr, wsId));
    const data = result.data as { count: number };
    expect(data.count).toBe(2);
    expect(result.output).toContain("A");
    expect(result.output).toContain("C");
    expect(result.output).not.toContain(" B ");
  });

  it("filters by verdict (derived from checkCode)", async () => {
    const { mgr, wsId } = mkWorkspace();
    mgr.vulns.create({ workspaceId: wsId, name: "tp-finding", checkCode: "vulnerable" });
    mgr.vulns.create({ workspaceId: wsId, name: "fp-finding", checkCode: "safe" });
    mgr.vulns.create({ workspaceId: wsId, name: "review-finding", checkCode: "appears" });
    const tool = createFindingsModule().tools.find((t) => t.name === "findings:list")!;
    const tps = await tool.execute({ verdict: ["tp"] }, mkCtx(mgr, wsId));
    expect((tps.data as { count: number }).count).toBe(1);
    expect(tps.output).toContain("tp-finding");
    const reviews = await tool.execute({ verdict: ["needs_review"] }, mkCtx(mgr, wsId));
    expect((reviews.data as { count: number }).count).toBe(1);
    expect(reviews.output).toContain("review-finding");
  });

  it("respects limit", async () => {
    const { mgr, wsId } = mkWorkspace();
    for (let i = 0; i < 10; i++) {
      mgr.vulns.create({ workspaceId: wsId, name: `v-${i}`, severity: "high" });
    }
    const tool = createFindingsModule().tools.find((t) => t.name === "findings:list")!;
    const result = await tool.execute({ limit: 3 }, mkCtx(mgr, wsId));
    const data = result.data as { count: number; findings: unknown[] };
    expect(data.count).toBe(10);
    expect(data.findings).toHaveLength(3);
  });
});

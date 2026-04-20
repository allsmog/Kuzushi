/**
 * Wave-V lifecycle hooks — the three events CopilotCore.executeTool emits
 * around each tool invocation. Modules subscribe via ctx.events.on() in
 * their init() hook.
 */

import { describe, expect, it, vi } from "vitest";
import type { AgentRuntime } from "../../src/agent-runtime/types.js";
import type { MessageBus } from "../../src/bus/types.js";
import { CopilotCore } from "../../src/copilot/core.ts";
import type {
  CopilotModule,
  ModuleContext,
  ModuleTool,
  ToolResult,
} from "../../src/modules/types.js";
import type { KuzushiConfig } from "../../src/types.js";

function mkCore(): CopilotCore {
  const runtime = {} as unknown as AgentRuntime;
  const bus = {
    publish: async () => {},
    subscribe: () => {},
    unsubscribe: () => {},
    waitFor: async () => ({}) as never,
    close: async () => {},
  } as unknown as MessageBus;
  return new CopilotCore({
    runtime,
    bus,
    config: { model: "anthropic:claude-sonnet-4-6" } as KuzushiConfig,
    dataDir: "/tmp",
    loadCoreSast: false,
  });
}

function hookModule(
  captured: Record<string, unknown[]>,
  behavior: "ok" | "throw" = "ok",
): CopilotModule {
  const tool: ModuleTool = {
    name: "hooked:run",
    description: "t",
    inputSchema: { type: "object", properties: {} },
    headless: true,
    async execute(): Promise<ToolResult> {
      if (behavior === "throw") throw new Error("boom");
      return { ok: true, output: "done" };
    },
  };
  return {
    id: "hooked",
    displayName: "hooked",
    category: "offense",
    version: "0.0.1",
    description: "m",
    tools: [tool],
    init(_config: Record<string, unknown>, ctx: ModuleContext) {
      const scope = ctx.events;
      if (!scope) return;
      scope.on("tool:before_run", (p) => captured.before?.push(p));
      scope.on("tool:after_run", (p) => captured.after?.push(p));
      scope.on("tool:on_error", (p) => captured.error?.push(p));
    },
  };
}

describe("module lifecycle hooks", () => {
  it("fires tool:before_run + tool:after_run on success", async () => {
    const captured = { before: [] as unknown[], after: [] as unknown[], error: [] as unknown[] };
    const core = mkCore();
    await (core as unknown as { loadWithScope: (m: CopilotModule) => Promise<void> }).loadWithScope(
      hookModule(captured),
    );
    const result = await core.executeTool("hooked:run", {});
    expect(result.ok).toBe(true);
    expect(captured.before).toHaveLength(1);
    expect((captured.before[0] as { qualifiedName: string }).qualifiedName).toBe("hooked:run");
    expect(captured.after).toHaveLength(1);
    expect(captured.error).toHaveLength(0);
  });

  it("fires tool:on_error when the tool throws", async () => {
    const captured = { before: [] as unknown[], after: [] as unknown[], error: [] as unknown[] };
    const core = mkCore();
    await (core as unknown as { loadWithScope: (m: CopilotModule) => Promise<void> }).loadWithScope(
      hookModule(captured, "throw"),
    );
    await expect(core.executeTool("hooked:run", {})).rejects.toThrow("boom");
    expect(captured.before).toHaveLength(1);
    expect(captured.after).toHaveLength(0);
    expect(captured.error).toHaveLength(1);
    expect((captured.error[0] as { error: string }).error).toBe("boom");
  });

  it("other modules can observe another module's lifecycle via the same bus", async () => {
    const captured = { before: [] as unknown[], after: [] as unknown[], error: [] as unknown[] };
    const core = mkCore();
    await (core as unknown as { loadWithScope: (m: CopilotModule) => Promise<void> }).loadWithScope(
      hookModule({ before: [], after: [], error: [] }),
    );
    const observer: CopilotModule = {
      id: "observer",
      displayName: "observer",
      category: "governance",
      version: "0.0.1",
      description: "watches",
      tools: [],
      init(_config, ctx) {
        ctx.events?.on("tool:before_run", (p) => captured.before.push(p));
      },
    };
    await (core as unknown as { loadWithScope: (m: CopilotModule) => Promise<void> }).loadWithScope(
      observer,
    );
    await core.executeTool("hooked:run", {});
    expect(captured.before).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Markdown export — shape check
// ---------------------------------------------------------------------------

describe("exportMarkdown", () => {
  it("renders a workspace with hosts/vulns/creds into readable sections", async () => {
    const { WorkspaceManager } = await import("../../src/workspace/manager.js");
    const { migration100 } = await import("../../src/migrations/100_schema_reset.js");
    const { migration101 } = await import("../../src/migrations/101_workspace_entities.js");
    const { migration102 } = await import("../../src/migrations/102_session_aliases.js");
    const Database = (await import("better-sqlite3")).default;
    const { mkdtempSync, rmSync } = await import("node:fs");
    const os = await import("node:os");
    const path = await import("node:path");
    const dir = mkdtempSync(path.join(os.tmpdir(), "kz-md-"));
    try {
      const db = new Database(path.join(dir, "x.sqlite3"));
      db.pragma("journal_mode = WAL");
      db.pragma("foreign_keys = ON");
      migration100.up(db);
      migration101.up(db);
      migration102.up(db);
      const mgr = new WorkspaceManager(db);
      const ws = mgr.create("acme", ["https://acme.example"]);
      const host = mgr.hosts.upsert({
        workspaceId: ws.id,
        address: "10.0.0.5",
        hostname: "web",
      });
      mgr.services.upsert({ hostId: host.id, port: 443, proto: "tcp", name: "https" });
      mgr.vulns.create({
        workspaceId: ws.id,
        name: "sql-injection",
        severity: "high",
        references: [{ type: "CWE", value: "CWE-89" }],
        description: "SQLi in login flow",
      });
      mgr.creds.upsert({ workspaceId: ws.id, publicUsername: "admin", privateData: "redacted" });

      const { exportMarkdown } = await import("../../src/workspace/io/export.js");
      const md = exportMarkdown(mgr, ws.id);
      expect(md).toContain("# Engagement report — acme");
      expect(md).toContain("## Summary");
      expect(md).toContain("## Hosts");
      expect(md).toContain("web");
      expect(md).toContain("10.0.0.5");
      expect(md).toContain("| 443 | tcp | https");
      expect(md).toContain("## Vulnerabilities");
      expect(md).toContain("### HIGH (1)");
      expect(md).toContain("sql-injection");
      expect(md).toContain("CWE:CWE-89");
      expect(md).toContain("## Credentials");
      expect(md).toContain("admin");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    // Suppress unused-vi import complaint.
    expect(vi).toBeDefined();
  });
});

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { AgentRuntime } from "../../src/agent-runtime/types.js";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import { __carliniThreatHuntInternals } from "../../src/modules/carlini-threat-hunt/carlini-threat-hunt.js";
import type { ExecutionContext } from "../../src/modules/types.js";
import type { KuzushiConfig } from "../../src/types.js";

const { resolveConfig } = __carliniThreatHuntInternals;

const tempDirs: string[] = [];
afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

function mkCtx(taskConfig: Record<string, unknown> = {}): ExecutionContext {
  const bus = new InProcessBus();
  const runtime: AgentRuntime = {
    id: "stub",
    async *query() {
      /* not used */
    },
  };
  return {
    cwd: "/tmp/repo",
    runtime,
    bus,
    config: {
      model: "anthropic:claude-sonnet-4-6",
      busBackend: "in-process",
      triageBatchSize: 5,
      triageConcurrency: 2,
      scanMode: "parallel",
      tasks: ["carlini-threat-hunt"],
      severity: ["ERROR"],
      excludePatterns: [],
      taskConfig: { "carlini-threat-hunt": taskConfig },
    } as KuzushiConfig,
    target: "/tmp/repo",
    dag: {
      runId: "test-run",
      repoRoot: "/tmp/repo",
      repoName: "repo",
      upstreamOutputs: new Map(),
    },
  };
}

describe("carlini-threat-hunt resolves CARLINI_THREAT_HUNT_PROMPT across input, file, and taskConfig", () => {
  it("reads an inline override from tool input", async () => {
    const ctx = mkCtx();
    const config = await resolveConfig(
      { target: "/tmp/repo", CARLINI_THREAT_HUNT_PROMPT: "be extra careful" },
      ctx,
    );
    expect(config.promptOverride).toBe("be extra careful");
  });

  it("reads a file path and forwards the file contents", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "kz-prompt-"));
    tempDirs.push(dir);
    const file = path.join(dir, "hunt.md");
    writeFileSync(file, "# file-backed prompt\n", "utf8");

    const ctx = mkCtx();
    const config = await resolveConfig(
      { target: "/tmp/repo", CARLINI_THREAT_HUNT_PROMPT: file },
      ctx,
    );
    expect(config.promptOverride).toContain("file-backed prompt");
  });

  it("reads CARLINI_THREAT_HUNT_PROMPT from taskConfig when no input field is supplied", async () => {
    const ctx = mkCtx({ CARLINI_THREAT_HUNT_PROMPT: "from-task-config" });
    const config = await resolveConfig({ target: "/tmp/repo" }, ctx);
    expect(config.promptOverride).toBe("from-task-config");
  });

  it("omits promptOverride when no value is set anywhere", async () => {
    const ctx = mkCtx();
    const config = await resolveConfig({ target: "/tmp/repo" }, ctx);
    expect(config.promptOverride).toBeUndefined();
  });
});

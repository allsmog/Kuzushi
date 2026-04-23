import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock the heavy dependencies before anything imports them transitively.
const triageFindingsBatchMock = vi.hoisted(() => vi.fn());
const verifyFindingWithAgentMock = vi.hoisted(() => vi.fn());
const runPatchPipelineMock = vi.hoisted(() => vi.fn());

vi.mock("../../src/triage.js", async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return { ...actual, triageFindingsBatch: triageFindingsBatchMock };
});
vi.mock("../../src/verify.js", async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return { ...actual, verifyFindingWithAgent: verifyFindingWithAgentMock };
});
vi.mock("../../src/patch.js", async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return { ...actual, runPatchPipeline: runPatchPipelineMock };
});

// Imports must come after the vi.mock calls so the module graph picks up the stubs.
import { createPatchModule } from "../../src/modules/patch/patch.js";
import { createTriageModule } from "../../src/modules/triage/triage.js";
import type { ToolExecutionContext } from "../../src/modules/types.js";
import { createVerifyModule } from "../../src/modules/verify/verify.js";
import { initDb } from "../../src/store.js";
import type { KuzushiConfig } from "../../src/types.js";
import { WorkspaceManager } from "../../src/workspace/manager.js";

const tempDirs: string[] = [];

beforeEach(() => {
  triageFindingsBatchMock.mockReset();
  verifyFindingWithAgentMock.mockReset();
  runPatchPipelineMock.mockReset();
});

afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

function mkWorkspace(): { mgr: WorkspaceManager } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-tvp-"));
  tempDirs.push(dir);
  const db = initDb(path.join(dir, "findings.sqlite3"));
  const mgr = new WorkspaceManager(db);
  return { mgr };
}

function seedFinding(mgr: WorkspaceManager, fingerprint: string): void {
  const db = mgr.rawDb();
  db.prepare(
    `INSERT INTO findings (
      fingerprint, task_id, repo, ref, rule_id, file_path, start_line, severity,
      message, verdict, confidence, rationale, verification_steps
    ) VALUES (?, 'semgrep', '/tmp/repo', 'HEAD', 'rule-1', 'src/a.ts', 10, 'high',
      'test finding', 'needs_review', 0.5, 'initial', '[]')`,
  ).run(fingerprint);
}

function mkCtx(mgr: WorkspaceManager): ToolExecutionContext {
  return {
    cwd: "/tmp",
    target: "/tmp/repo",
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
  };
}

describe("triage:run", () => {
  it("requires an active workspace", async () => {
    const tool = createTriageModule().tools.find((t) => t.name === "triage:run")!;
    const result = await tool.execute({}, {
      cwd: "/tmp",
      runtime: { id: "test", async *query() {} },
      bus: {} as ToolExecutionContext["bus"],
      config: {} as KuzushiConfig,
    } as ToolExecutionContext);
    expect(result.ok).toBe(false);
    expect(result.output).toContain("active workspace");
  });

  it("reports when no findings match", async () => {
    const { mgr } = mkWorkspace();
    const tool = createTriageModule().tools.find((t) => t.name === "triage:run")!;
    const result = await tool.execute({}, mkCtx(mgr));
    expect(result.ok).toBe(false);
    expect(result.output).toContain("No findings match");
  });

  it("triages findings via triageFindingsBatch and summarizes verdicts", async () => {
    const { mgr } = mkWorkspace();
    seedFinding(mgr, "fp1");
    seedFinding(mgr, "fp2");

    triageFindingsBatchMock.mockResolvedValue({
      results: new Map([
        ["fp1", { fingerprint: "fp1", verdict: "tp", confidence: 0.9 }],
        ["fp2", { fingerprint: "fp2", verdict: "fp", confidence: 0.8 }],
      ]),
      costUsd: 0.12,
      missingFingerprints: [],
      incomplete: false,
      recoveredByRetry: [],
    });

    const tool = createTriageModule().tools.find((t) => t.name === "triage:run")!;
    const result = await tool.execute({}, mkCtx(mgr));
    expect(result.ok).toBe(true);
    expect(result.output).toContain("Triaged 2 of 2");
    expect(result.output).toContain("tp=1");
    expect(result.output).toContain("fp=1");
    const data = result.data as { tp: number; fp: number };
    expect(data.tp).toBe(1);
    expect(data.fp).toBe(1);
    expect(triageFindingsBatchMock).toHaveBeenCalledTimes(1);
  });

  it("forwards TRIAGE_PROMPT as the batch template", async () => {
    const { mgr } = mkWorkspace();
    seedFinding(mgr, "fp3");
    triageFindingsBatchMock.mockResolvedValue({
      results: new Map(),
      costUsd: 0,
      missingFingerprints: [],
      incomplete: false,
      recoveredByRetry: [],
    });
    const tool = createTriageModule().tools.find((t) => t.name === "triage:run")!;
    await tool.execute({ TRIAGE_PROMPT: "be extra thorough" }, mkCtx(mgr));
    const call = triageFindingsBatchMock.mock.calls[0];
    // The batchTemplate is the 8th positional arg (index 7).
    expect(call[7]).toBe("be extra thorough");
  });
});

describe("verify:finding", () => {
  it("fails without a fingerprint", async () => {
    const { mgr } = mkWorkspace();
    const tool = createVerifyModule().tools.find((t) => t.name === "verify:finding")!;
    const result = await tool.execute({}, mkCtx(mgr));
    expect(result.ok).toBe(false);
    expect(result.output).toContain("requires a fingerprint");
  });

  it("fails when the fingerprint is unknown", async () => {
    const { mgr } = mkWorkspace();
    const tool = createVerifyModule().tools.find((t) => t.name === "verify:finding")!;
    const result = await tool.execute({ fingerprint: "ghost" }, mkCtx(mgr));
    expect(result.ok).toBe(false);
    expect(result.output).toContain("No finding with fingerprint");
  });

  it("calls verifyFindingWithAgent and reports exploitability", async () => {
    const { mgr } = mkWorkspace();
    seedFinding(mgr, "fp-verify");
    verifyFindingWithAgentMock.mockResolvedValue({
      result: { exploitable: true, attackVector: "curl POST /admin", proofLevel: "confirmed" },
      costUsd: 0.42,
    });

    const tool = createVerifyModule().tools.find((t) => t.name === "verify:finding")!;
    const result = await tool.execute({ fingerprint: "fp-verify" }, mkCtx(mgr));
    expect(result.ok).toBe(true);
    expect(result.output).toContain("VULNERABLE");
    expect(result.output).toContain("curl POST /admin");
    expect(result.costUsd).toBe(0.42);
    expect(verifyFindingWithAgentMock).toHaveBeenCalledTimes(1);
  });
});

describe("patch:finding", () => {
  it("fails without a fingerprint", async () => {
    const { mgr } = mkWorkspace();
    const tool = createPatchModule().tools.find((t) => t.name === "patch:finding")!;
    const result = await tool.execute({}, mkCtx(mgr));
    expect(result.ok).toBe(false);
    expect(result.output).toContain("requires a fingerprint");
  });

  it("reports SOUND + diff when the patch pipeline succeeds", async () => {
    const { mgr } = mkWorkspace();
    seedFinding(mgr, "fp-patch");
    runPatchPipelineMock.mockResolvedValue({
      patchResult: {
        status: "SOUND",
        iterations: 2,
        patchRunId: "run-xyz",
        diff: "--- a/src/a.ts\n+++ b/src/a.ts\n@@ -1 +1 @@\n-bad\n+good\n",
      },
      costUsd: 1.23,
    });
    const tool = createPatchModule().tools.find((t) => t.name === "patch:finding")!;
    const result = await tool.execute({ fingerprint: "fp-patch" }, mkCtx(mgr));
    expect(result.ok).toBe(true);
    expect(result.output).toContain("SOUND");
    expect(result.output).toContain("--- a/src/a.ts");
    expect(result.costUsd).toBe(1.23);
  });

  it("reports non-sound status without failing the call", async () => {
    const { mgr } = mkWorkspace();
    seedFinding(mgr, "fp-patch-fail");
    runPatchPipelineMock.mockResolvedValue({
      patchResult: {
        status: "BUILD_FAILED",
        iterations: 3,
        patchRunId: "run-xyz",
        diff: null,
        validatorLog: "tsc error TS2304",
      },
      costUsd: 0.55,
    });
    const tool = createPatchModule().tools.find((t) => t.name === "patch:finding")!;
    const result = await tool.execute({ fingerprint: "fp-patch-fail" }, mkCtx(mgr));
    expect(result.ok).toBe(false);
    expect(result.output).toContain("BUILD_FAILED");
    expect(result.output).toContain("tsc error");
  });
});

import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type {
  AgentMessage,
  AgentQueryRequest,
  AgentRuntime,
} from "../../src/agent-runtime/types.js";
import {
  createXRayPiAiCustomTools,
  createXRayToolGuard,
  readXRayReportArtifacts,
  type XRayReportData,
} from "../../src/agents/tasks/x-ray/runner.js";
import {
  buildRuntimeAdapterText,
  buildXRayPrompt,
  detectXRayRuntimeMode,
  loadXRaySkillPack,
} from "../../src/agents/tasks/x-ray/skill-pack.js";
import { artifactKbPath, searchArtifactKb } from "../../src/modules/_shared/artifact-kb/index.js";
import { type ExecutionContext, isDagTool, type ModuleTool } from "../../src/modules/types.js";
import { createXRayModule } from "../../src/modules/x-ray/x-ray.js";
import { createMockToolContext } from "../../src/testing/index.js";

function tempRepo(): string {
  return mkdtempSync(path.join(tmpdir(), "kuzushi-x-ray-"));
}

function writeArtifacts(root: string): void {
  const dir = path.join(root, "x-ray");
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    path.join(dir, "x-ray.md"),
    [
      "# X-Ray",
      "",
      "## X-Ray Verdict",
      "READY",
      "The protocol has clear core flows and reviewable invariants.",
      "",
    ].join("\n"),
  );
  writeFileSync(
    path.join(dir, "entry-points.md"),
    [
      "# Entry Points",
      "",
      "> TinyVault | 4 entry points | 2 permissionless | 1 role-gated | 1 admin-only",
      "",
      "## Permissionless Entry Points",
      "### deposit(uint256 amount)",
      "",
      "| Aspect | Detail |",
      "|--------|--------|",
      "| Visibility | external |",
      "| Caller | User |",
      "",
      "### withdraw(uint256 shares)",
      "",
      "## Role-Gated Entry Points",
      "### owner",
      "### rebalance()",
      "",
      "## Admin-Only Entry Points",
      "### pause()",
    ].join("\n"),
  );
  writeFileSync(
    path.join(dir, "invariants.md"),
    [
      "# Invariants",
      "",
      "### G-1 Total assets cover shares",
      "### G-2 No stale accounting",
      "### I-1 Oracle integration bounds",
      "### X-1 Bridge replay protection",
      "### E-1 Fee conservation",
    ].join("\n"),
  );
  writeFileSync(path.join(dir, "architecture.svg"), '<svg xmlns="http://www.w3.org/2000/svg" />\n');
}

function resultMessage(costUsd = 0.25): AgentMessage {
  return {
    type: "result",
    subtype: "success",
    result: "done",
    totalCostUsd: costUsd,
  };
}

function fakeRuntime(
  id: string,
  onQuery: (request: AgentQueryRequest) => void | Promise<void>,
): AgentRuntime {
  return {
    id,
    async *query(request: AgentQueryRequest): AsyncIterable<AgentMessage> {
      await onQuery(request);
      yield resultMessage();
    },
  };
}

function getRunTool(): ModuleTool {
  const tool = createXRayModule().tools.find((candidate) => candidate.name === "x-ray:run");
  if (!tool) throw new Error("missing x-ray:run");
  return tool;
}

function createCtx(root: string, runtime: AgentRuntime): ExecutionContext {
  return createMockToolContext({
    cwd: root,
    target: root,
    runtime,
    config: { model: "test:model" },
  });
}

describe("x-ray module", () => {
  it("exposes run/read plus a hidden report DAG tool", () => {
    const mod = createXRayModule();
    expect(mod.id).toBe("x-ray");
    expect(mod.category).toBe("intel");

    const visible = mod.tools.filter((tool) => !tool.hidden);
    expect(visible.map((tool) => tool.name)).toEqual(["x-ray:run", "x-ray:read"]);

    const hidden = mod.tools.find((tool) => tool.name === "x-ray:x-ray");
    expect(hidden).toBeDefined();
    expect(hidden!.hidden).toBe(true);
    expect(isDagTool(hidden!)).toBe(true);
    if (isDagTool(hidden!)) {
      expect(hidden.dag.outputKind).toBe("report");
      expect(hidden.dag.dependsOn).toContain("context:context-gatherer");
    }
  });

  it("parses existing artifacts for x-ray:read", async () => {
    const root = tempRepo();
    writeArtifacts(root);

    const read = createXRayModule().tools.find((tool) => tool.name === "x-ray:read");
    const result = await read!.execute(
      { target: root },
      createCtx(
        root,
        fakeRuntime("codex", () => {}),
      ),
    );

    expect(result.ok).toBe(true);
    const data = result.data as XRayReportData;
    expect(data.verdict.tier).toBe("READY");
    expect(data.verdict.summary).toBe(
      "The protocol has clear core flows and reviewable invariants.",
    );
    expect(data.entryPointCounts).toMatchObject({
      permissionless: 2,
      roleGated: 1,
      adminOnly: 1,
      total: 4,
    });
    expect(data.invariantCounts).toMatchObject({
      global: 2,
      integration: 1,
      crossChain: 1,
      economic: 1,
      total: 5,
    });
    expect(data).not.toHaveProperty("artifactKb");
  });

  it("parses live-style X-Ray count summaries and compact invariant IDs", () => {
    const root = tempRepo();
    const dir = path.join(root, "x-ray");
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      path.join(dir, "x-ray.md"),
      "# X-Ray\n\n## X-Ray Verdict\nWATCH\nLive-style report.\n",
    );
    writeFileSync(
      path.join(dir, "entry-points.md"),
      [
        "# Entry Point Map",
        "",
        "> Live Fixture | 2 entry points | 0 permissionless | 1 role-gated | 1 admin-only",
        "",
        "## Role-Gated",
        "### Authenticated user",
        "",
        "## Admin-Only",
        "### Admin",
      ].join("\n"),
    );
    writeFileSync(
      path.join(dir, "invariants.md"),
      ["# Invariants", "", "### G1: Amount positive", "", "### I1: Conservation"].join("\n"),
    );
    writeFileSync(
      path.join(dir, "architecture.svg"),
      '<svg xmlns="http://www.w3.org/2000/svg" />\n',
    );

    const data = readXRayReportArtifacts({ repoRoot: root });

    expect(data.verdict.tier).toBe("WATCH");
    expect(data.entryPointCounts).toMatchObject({
      permissionless: 0,
      roleGated: 1,
      adminOnly: 1,
      total: 2,
    });
    expect(data.invariantCounts).toMatchObject({
      global: 1,
      integration: 1,
      total: 2,
    });
  });

  it("parses template verdict tiers emitted by live X-Ray runs", () => {
    const root = tempRepo();
    const dir = path.join(root, "x-ray");
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      path.join(dir, "x-ray.md"),
      ["# X-Ray", "", "## X-Ray Verdict", "**FRAGILE** - Fixture-stage code with no tests."].join(
        "\n",
      ),
    );
    writeFileSync(path.join(dir, "entry-points.md"), "# Entry Points\n\n### deposit()\n");
    writeFileSync(path.join(dir, "invariants.md"), "# Invariants\n\n### G-1 Conservation\n");
    writeFileSync(
      path.join(dir, "architecture.svg"),
      '<svg xmlns="http://www.w3.org/2000/svg" />\n',
    );

    const data = readXRayReportArtifacts({ repoRoot: root });

    expect(data.verdict).toMatchObject({
      tier: "FRAGILE",
      summary: "Fixture-stage code with no tests.",
    });
  });

  it("indexes existing x-ray:read artifacts when requested", async () => {
    const root = tempRepo();
    writeArtifacts(root);

    const read = createXRayModule().tools.find((tool) => tool.name === "x-ray:read");
    const result = await read!.execute(
      { target: root, index: true },
      createCtx(
        root,
        fakeRuntime("codex", () => {}),
      ),
    );

    expect(result.ok).toBe(true);
    expect(
      (result.data as XRayReportData & { artifactKb?: { path: string } }).artifactKb?.path,
    ).toBe(artifactKbPath(root));
    expect(
      searchArtifactKb(artifactKbPath(root), { query: "deposit", moduleId: "x-ray" }).results,
    ).toHaveLength(1);
  });

  it("builds runtime-specific prompts and plugin options", () => {
    const root = tempRepo();
    const skillPack = loadXRaySkillPack();

    expect(detectXRayRuntimeMode("claude")).toBe("claude");
    expect(detectXRayRuntimeMode("pi-ai")).toBe("pi-ai");
    expect(detectXRayRuntimeMode("codex")).toBe("codex");

    const claude = buildXRayPrompt({
      runtimeMode: "claude",
      targetRoot: root,
      repoName: "repo",
      skillPack,
    });
    expect(claude.plugins?.[0]?.path).toBe(skillPack.pluginRoot);
    expect(claude.systemPromptPrefix).toBeUndefined();
    expect(claude.prompt).toContain("/pashov-xray:x-ray");

    const codex = buildXRayPrompt({
      runtimeMode: "codex",
      targetRoot: root,
      repoName: "repo",
      skillPack,
    });
    expect(codex.systemPromptPrefix).toContain("Vendored Pashov X-Ray Skill Pack");
    expect(codex.systemPromptPrefix).toContain("do not call a TodoWrite tool");
    expect(codex.systemPromptPrefix).toContain("sequential sub-analysis");
    expect(buildRuntimeAdapterText("pi-ai")).toContain(
      "Compatibility tools named TodoWrite and Task",
    );
  });

  it("guards read/write/bash access for the harness", () => {
    const root = tempRepo();
    const skillPack = loadXRaySkillPack();
    const guard = createXRayToolGuard({ repoRoot: root, skillDir: skillPack.skillDir });

    expect(
      guard.checkTool("Write", { file_path: path.join(root, "x-ray", "x-ray.md") }).behavior,
    ).toBe("allow");
    expect(guard.checkTool("Write", { file_path: path.join(root, "README.md") }).behavior).toBe(
      "deny",
    );
    expect(guard.checkTool("Read", { path: skillPack.skillPath }).behavior).toBe("allow");
    expect(guard.checkTool("Read", { path: "/etc/passwd" }).behavior).toBe("deny");
    expect(guard.checkTool("Bash", { command: "rm -rf x-ray" }).behavior).toBe("deny");
    expect(
      guard.checkTool("Bash", {
        command: `cd ${root} && python3 ${skillPack.skillDir}/scripts/analyze_git_security.py --repo . --src-dir src --json x-ray/git-security-analysis.json 2>&1 && cat x-ray/git-security-analysis.json`,
      }).behavior,
    ).toBe("allow");
  });

  it("implements pi-ai TodoWrite and bounded Task compatibility tools", async () => {
    const root = tempRepo();
    const skillPack = loadXRaySkillPack();
    const guard = createXRayToolGuard({ repoRoot: root, skillDir: skillPack.skillDir });
    const requests: AgentQueryRequest[] = [];
    const runtime = fakeRuntime("pi-ai", (request) => {
      requests.push(request);
    });
    const tools = createXRayPiAiCustomTools({
      runtime,
      model: "test:model",
      repoRoot: root,
      repoName: "repo",
      skillPack,
      guard,
    });

    const todo = tools.find((tool) => tool.name === "TodoWrite")!;
    expect(
      todo.execute(
        { todos: [{ content: "Phase 1", status: "in_progress" }] },
        { cwd: root, toolUseId: "todo-1" },
      ),
    ).toContain("Todo list updated");
    expect(() =>
      todo.execute(
        {
          todos: [
            { content: "Phase 1", status: "in_progress" },
            { content: "Phase 2", status: "in_progress" },
          ],
        },
        { cwd: root, toolUseId: "todo-2" },
      ),
    ).toThrow(/at most one/);

    const task = tools.find((tool) => tool.name === "Task")!;
    const output = await task.execute(
      { prompt: "Read the entry points." },
      { cwd: root, toolUseId: "task-1" },
    );
    expect(output).toContain("done");
    expect(requests[0]!.options.allowedTools).not.toContain("Write");
  });

  it.each([
    ["claude", "claude"],
    ["pi-ai", "pi-ai"],
    ["codex", "codex"],
  ] as const)("runs through the %s adapter and validates artifacts", async (runtimeId, mode) => {
    const root = tempRepo();
    const requests: AgentQueryRequest[] = [];
    const runtime = fakeRuntime(runtimeId, (request) => {
      requests.push(request);
      writeArtifacts(root);
    });

    const result = await getRunTool().execute({ target: root }, createCtx(root, runtime));

    expect(result.ok).toBe(true);
    const data = result.data as XRayReportData;
    expect(data.runtimeMode).toBe(mode);
    expect(data.costUsd).toBeCloseTo(0.25);
    expect(data.artifactPaths.architectureSvg).toBe(path.join(root, "x-ray", "architecture.svg"));

    const options = requests[0]!.options;
    if (mode === "claude") {
      expect(options.plugins?.[0]?.path).toContain("assets/pashov-xray");
      expect(options.allowedTools).toEqual([
        "Read",
        "Glob",
        "Grep",
        "Bash",
        "Write",
        "Task",
        "TodoWrite",
      ]);
    } else if (mode === "pi-ai") {
      expect(options.systemPromptPrefix).toContain("Compatibility tools named TodoWrite and Task");
      expect(options.customTools?.map((tool) => tool.name)).toEqual(["TodoWrite", "Task"]);
    } else {
      expect(options.systemPromptPrefix).toContain("Kuzushi Codex adapter");
      expect(options.plugins).toBeUndefined();
      expect(options.customTools).toBeUndefined();
      expect(options.allowedTools).toEqual(["Bash", "Write"]);
    }
  });

  it("fails artifact parsing when required files are missing", () => {
    const root = tempRepo();
    mkdirSync(path.join(root, "x-ray"));
    writeFileSync(path.join(root, "x-ray", "x-ray.md"), "# X-Ray\n");
    expect(() => readXRayReportArtifacts({ repoRoot: root })).toThrow(/missing required artifact/);
  });
});

import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AgentRuntime } from "../../src/agent-runtime/types.js";
import type { CopilotCore } from "../../src/copilot/core.js";
import type { ShellOptions } from "../../src/copilot/shell.js";
import {
  __shellInternals,
  buildShellPrompt,
  createShellSession,
  loadShellCommandHistory,
  saveShellCommandHistory,
} from "../../src/copilot/shell.js";
import { createCoreSastModule } from "../../src/modules/core-sast.js";
import type { KuzushiConfig } from "../../src/types.js";
import type { ShellState } from "../../src/ui/state.js";

const tempDirs: string[] = [];

const baseConfig: KuzushiConfig = {
  model: "anthropic:claude-sonnet-4-6",
  busBackend: "in-process",
  triageBatchSize: 15,
  triageConcurrency: 2,
  scanMode: "parallel",
  tasks: ["semgrep"],
  severity: ["ERROR"],
  excludePatterns: [],
  taskConfig: { semgrep: {} },
};

async function createMockCore() {
  const { createSemgrepModule } = await import("../../src/modules/sast/core-semgrep.js");
  const { createThreatHuntModule } = await import("../../src/modules/sast/core-threat-hunt.js");
  const { createContextModule } = await import("../../src/modules/sast/core-context.js");

  const sast = createCoreSastModule();
  const semgrep = createSemgrepModule();
  const threatHunt = createThreatHuntModule();
  const context = createContextModule();
  const mods = [sast, semgrep, threatHunt, context];
  const module = sast; // back-compat name; older assertions still reference `module`

  const executeTool = vi.fn(async (_toolName: string, input: unknown) => ({
    ok: true,
    output: JSON.stringify(input),
  }));

  // Legacy aliases so code dispatching on `sast:semgrep` still finds a tool.
  const aliases: Record<string, string> = {
    "sast:semgrep": "semgrep:scan",
    "sast:threat-hunt": "threat-hunt:run",
    "sast:context": "context:build",
  };

  const allTools = () => mods.flatMap((m) => m.tools.map((tool) => ({ module: m, tool })));

  const resolveTool = (name: string) => {
    for (const m of mods) {
      const tool = m.tools.find((t) => t.name === name);
      if (tool) return { module: m, tool };
    }
    const aliased = aliases[name];
    if (aliased) return resolveTool(aliased);
    return undefined;
  };

  const core = {
    listModules: () =>
      mods.map((m) => ({
        id: m.id,
        displayName: m.displayName,
        category: m.category,
        version: m.version,
        description: m.description,
        toolCount: m.tools.length,
        taskCount: 0,
        loaded: true,
      })),
    hasModule: (id: string) => mods.some((m) => m.id === id),
    executeTool,
    registry: {
      get: (id: string) => mods.find((m) => m.id === id) ?? module,
      allTools,
      moduleTools: (id: string) =>
        (mods.find((m) => m.id === id)?.tools ?? []) as ReadonlyArray<
          (typeof module.tools)[number]
        >,
      resolveTool,
    },
  } as unknown as CopilotCore;

  return { core, module, executeTool };
}

function createShellOptions(): ShellOptions {
  return {
    config: baseConfig,
    runtime: {
      id: "test",
      async *query() {},
    } as AgentRuntime,
    target: ".",
  };
}

function createShellState(toolNames: string[]): ShellState {
  return {
    modules: ["sast"],
    tools: toolNames,
    focusedModule: null,
    target: ".",
    workspace: null,
    history: [],
    commandHistory: [],
    moduleOptions: {},
    processing: false,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("shell prompt", () => {
  it("renders top-level and focused prompts consistently", async () => {
    expect(buildShellPrompt(null)).toBe("kuzushi> ");
    expect(buildShellPrompt("sast")).toBe("kuzushi/sast> ");
  });
});

describe("artifact visibility", () => {
  function makeTempRepo(withKuzushi: boolean, files: string[] = []): string {
    const { mkdirSync, writeFileSync } = require("node:fs") as typeof import("node:fs");
    const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-banner-"));
    tempDirs.push(dir);
    if (withKuzushi) {
      mkdirSync(path.join(dir, ".kuzushi"), { recursive: true });
      for (const rel of files) {
        writeFileSync(path.join(dir, ".kuzushi", rel), "{}", "utf-8");
      }
    }
    return dir;
  }

  it("emits an empty banner and trailer in a fresh directory", async () => {
    const dir = makeTempRepo(false);
    expect(__shellInternals.formatArtifactBanner(dir)).toBe("");
    expect(__shellInternals.formatContextTrailer(dir)).toBe("");
    expect(__shellInternals.loadArtifactManifest(dir)).toEqual([]);
  });

  it("banner lists scan-context + threat-model when present, with a /ask pointer", async () => {
    const dir = makeTempRepo(true, ["scan-context.json", "threat-model.json"]);
    const banner = __shellInternals.formatArtifactBanner(dir);
    expect(banner).toContain("Prior artifacts in .kuzushi/:");
    expect(banner).toContain("scan-context.json");
    expect(banner).toContain("threat-model.json");
    expect(banner).toContain("/ask uses these as context.");
  });

  it("trailer is a compact filename list — keeps tool-summary readable", async () => {
    const dir = makeTempRepo(true, ["scan-context.json", "threat-model.json", "findings.sqlite3"]);
    const trailer = __shellInternals.formatContextTrailer(dir);
    expect(trailer).toContain("(context:");
    expect(trailer).toContain("scan-context.json");
    expect(trailer).toContain("threat-model.json");
    expect(trailer).toContain("findings.sqlite3");
    // No expanded "modified YYYY-MM-DD" tags in the trailer — keep it one line.
    expect(trailer).not.toContain("modified");
  });
});

describe("local shell commands", () => {
  it("uses slash-prefixed commands for workspace, focus, and help", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    const shellState = createShellState(module.tools.map((tool) => tool.name));
    const ctx = { focusedModule: null };

    const workspaceResult = __shellInternals.handleLocalCommand(
      "/workspace acme-pentest",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(workspaceResult).toEqual({ output: "Workspace set to: acme-pentest" });
    expect(opts.workspace).toBe("acme-pentest");

    const useResult = __shellInternals.handleLocalCommand("/use sast", core, opts, ctx, shellState);
    expect(useResult?.setFocus).toBe("sast");

    ctx.focusedModule = "sast";
    const toolsResult = __shellInternals.handleLocalCommand("/tools", core, opts, ctx, shellState);
    // Post-split the sast umbrella only lists its own `scan` tool; threat-hunt
    // lives in its own module now. Exercising that here would require focusing
    // on `threat-hunt`, which is covered by the dispatcher tests.
    expect(toolsResult?.output).toContain("scan");

    const backResult = __shellInternals.handleLocalCommand("/back", core, opts, ctx, shellState);
    expect(backResult?.setFocus).toBeNull();
    expect(backResult?.output).toBe("Returned to top level.");
    // The v2 "modules calmed" redesign adds a shellStateUpdater on /back so
    // the shell-view + openFindingId fields reset alongside focus.
    expect(typeof backResult?.shellStateUpdater).toBe("function");

    // After the NL-fallback removal, bare `help` (no slash) no longer falls
    // through to the agent — it surfaces an "Unknown command" pointer to the
    // new `/help` / `/ask` paths instead.
    const bareHelp = __shellInternals.handleLocalCommand("help", core, opts, ctx, shellState);
    expect(bareHelp?.output).toContain("Unknown command");
    expect(bareHelp?.output).toContain("/ask");
  });

  it("routes /ask through askQuestion with current screen context", async () => {
    const { core } = await createMockCore();
    const opts = createShellOptions();
    const shellState: ShellState = {
      ...createShellState([]),
      focusedModule: "threat-hunt",
      shellView: "module",
      target: "./demo-target",
      lastUsedTool: "threat-hunt:run",
    };
    const ctx = { focusedModule: "threat-hunt" };

    const ask = __shellInternals.handleLocalCommand(
      "/ask what findings stand out?",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(ask?.askQuestion).toBeDefined();
    // Context preamble should mention the focused module, shell view, and
    // the actual question so the agent has both framing and intent.
    expect(ask?.askQuestion).toContain("focused module: threat-hunt");
    expect(ask?.askQuestion).toContain("shell view: module");
    expect(ask?.askQuestion).toContain("last tool: threat-hunt:run");
    expect(ask?.askQuestion).toContain("Loaded artifacts (.kuzushi/)");
    expect(ask?.askQuestion).toContain("what findings stand out?");
  });

  it("routes ? prefix through askQuestion", async () => {
    const { core } = await createMockCore();
    const opts = createShellOptions();
    const shellState = createShellState([]);
    const ctx = { focusedModule: null };

    const ask = __shellInternals.handleLocalCommand(
      "?how do I triage",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(ask?.askQuestion).toBeDefined();
    expect(ask?.askQuestion).toContain("how do I triage");
  });

  it("/ask with no question prints usage instead of streaming", async () => {
    const { core } = await createMockCore();
    const opts = createShellOptions();
    const shellState = createShellState([]);
    const ctx = { focusedModule: null };

    const ask = __shellInternals.handleLocalCommand("/ask", core, opts, ctx, shellState);
    expect(ask?.askQuestion).toBeUndefined();
    expect(ask?.output).toContain("Usage: /ask <question>");
  });

  it("renders options tables and stores per-tool settings", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    let shellState = createShellState(module.tools.map((tool) => tool.name));
    const ctx = { focusedModule: "sast" };

    const optionsResult = __shellInternals.handleLocalCommand(
      "/options threat-hunt",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(optionsResult?.output).toContain("sast:threat-hunt options");
    expect(optionsResult?.output).toContain("maxActors");
    expect(optionsResult?.output).toContain("5");

    shellState = optionsResult?.shellStateUpdater
      ? optionsResult.shellStateUpdater(shellState)
      : shellState;
    expect(shellState.lastUsedTool).toBe("sast:threat-hunt");

    const setResult = __shellInternals.handleLocalCommand(
      "/set maxActors 7",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(setResult?.output).toBe("Set sast:threat-hunt.maxActors = 7");

    shellState = setResult?.shellStateUpdater
      ? setResult.shellStateUpdater(shellState)
      : shellState;
    expect(shellState.moduleOptions["sast:threat-hunt"]).toEqual({ maxActors: 7 });

    const optionsAgain = __shellInternals.handleLocalCommand(
      "/options",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(optionsAgain?.output).toContain("* 7");
  });

  it("errors on unknown slash commands and missing /set context", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    const shellState = createShellState(module.tools.map((tool) => tool.name));
    const ctx = { focusedModule: "sast" };

    const unknown = __shellInternals.handleLocalCommand("/foo", core, opts, ctx, shellState);
    expect(unknown).toEqual({
      output: "Unknown command: /foo. Type /help for available commands.",
    });

    const setResult = __shellInternals.handleLocalCommand(
      "/set maxActors 7",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(setResult).toEqual({ output: "No active tool selected. Use /options <tool> first." });
  });

  it("supports clear/history and bare exit aliases", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    const shellState = {
      ...createShellState(module.tools.map((tool) => tool.name)),
      history: [{ type: "output" as const, text: "old output", timestamp: 1 }],
      commandHistory: ["/help", "/use sast", "scan ."],
    };
    const ctx = { focusedModule: null };

    const historyResult = __shellInternals.handleLocalCommand(
      "/history",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(historyResult?.output).toContain("/use sast");
    expect(historyResult?.output).toContain("scan .");

    const clearResult = __shellInternals.handleLocalCommand("/clear", core, opts, ctx, shellState);
    expect(clearResult?.clearHistory).toBe(true);
    expect(clearResult?.resetSession).toBe(true);
    expect(clearResult?.output).toBe("Conversation cleared.");

    expect(__shellInternals.handleLocalCommand("quit", core, opts, ctx, shellState)).toEqual({
      exit: true,
    });
  });

  it("resolves direct tool execution and merges stored options", async () => {
    const { core, module, executeTool } = await createMockCore();
    const opts = createShellOptions();
    const ctx = { focusedModule: "sast" };
    const shellState = {
      ...createShellState(module.tools.map((tool) => tool.name)),
      focusedModule: "sast" as const,
      moduleOptions: {
        "sast:threat-hunt": {
          target: "/stored-target",
          maxActors: 5,
        },
      },
      contextSnapshot: {
        target: ".",
        timestamp: Date.now(),
        discovery: "flat" as const,
        options: { enrichment: true, threatModel: true, scenarios: true },
      },
    };

    const qualified = __shellInternals.handleLocalCommand(
      "sast:semgrep .",
      core,
      opts,
      { focusedModule: null },
      shellState,
    );
    expect(qualified?.executedToolName).toBe("semgrep:scan");

    // "semgrep" as a bare word no longer resolves (post-split it's a module id,
    // not a tool action). The qualified form above covers that path; the bare
    // `scan .` in focused mode below covers the shorthand path.
    const global = __shellInternals.handleLocalCommand(
      "semgrep:scan .",
      core,
      opts,
      { focusedModule: null },
      shellState,
    );
    expect(global?.executedToolName).toBe("semgrep:scan");

    const focused = __shellInternals.handleLocalCommand("scan .", core, opts, ctx, shellState);
    expect(focused?.executedToolName).toBe("sast:scan");

    const threatHunt = __shellInternals.handleLocalCommand(
      "threat-hunt /repo maxActors=7",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(threatHunt?.executedToolName).toBe("threat-hunt:run");
    expect(threatHunt?.asyncExecute).toBeTypeOf("function");

    await threatHunt?.asyncExecute?.();

    expect(executeTool).toHaveBeenCalledWith(
      "threat-hunt:run",
      expect.objectContaining({
        target: "/repo",
        maxActors: 7,
      }),
      expect.objectContaining({
        workspaceId: undefined,
      }),
    );
  });
});

describe("context system", () => {
  const mockSnapshot = {
    target: "/resolved/repo",
    timestamp: Date.now(),
    discovery: "flat" as const,
    options: { enrichment: true, threatModel: true, scenarios: true },
    repoContext: {
      languages: ["TypeScript"],
      frameworks: ["Express"],
      authPatterns: ["JWT"],
      ormOrDb: ["PostgreSQL"],
      entryPoints: ["src/index.ts"],
      sanitizationLibs: [],
    },
    appModel: {
      routes: [
        { method: "POST", path: "/auth/login", middleware: [], authMechanisms: [] },
        { method: "GET", path: "/api/users/:id", middleware: ["auth"], authMechanisms: ["jwt"] },
      ],
      outboundClients: [{ kind: "axios" }],
      serviceBoundaries: [{}],
      dataStores: [{}],
      backgroundJobs: [],
    },
    threatModel: {
      summary: { total: 3, bySeverity: { critical: 1, high: 1, medium: 1 } },
      threats: [
        { title: "SSRF via webhook", impact: "critical" },
        { title: "IDOR on users", impact: "high" },
        { title: "Missing rate limit", impact: "medium" },
      ],
    },
  };

  it("/context with no target returns error", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    opts.target = undefined;
    const shellState = createShellState(module.tools.map((t) => t.name));
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand("/context", core, opts, ctx, shellState);
    expect(result?.output).toContain("No target set");
  });

  it("/context with existing snapshot returns formatted summary", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    opts.target = "/resolved/repo";
    const shellState = {
      ...createShellState(module.tools.map((t) => t.name)),
      contextSnapshot: mockSnapshot,
    };
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand("/context", core, opts, ctx, shellState);
    expect(result?.output).toContain("Context:");
    expect(result?.output).toContain("TypeScript");
    expect(result?.output).toContain("Express");
    expect(result?.output).toContain("Routes (2)");
    expect(result?.output).toContain("SSRF via webhook");
  });

  it("/context without snapshot dispatches sast:context tool", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    opts.target = "./repo";
    const shellState = createShellState(module.tools.map((t) => t.name));
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand("/context", core, opts, ctx, shellState);
    expect(result?.executedToolName).toBe("context:build");
    expect(result?.asyncExecute).toBeTypeOf("function");
  });

  it("/context regenerate always dispatches tool", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    opts.target = "/resolved/repo";
    const shellState = {
      ...createShellState(module.tools.map((t) => t.name)),
      contextSnapshot: mockSnapshot,
    };
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand(
      "/context regenerate",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(result?.executedToolName).toBe("context:build");
    expect(result?.asyncExecute).toBeTypeOf("function");
  });

  it("context gating blocks threat-hunt without snapshot", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    const ctx = { focusedModule: "sast" };
    const shellState = createShellState(module.tools.map((t) => t.name));

    const result = __shellInternals.handleLocalCommand(
      "threat-hunt .",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(result?.output).toContain("Context required");
    expect(result?.executedToolName).toBeUndefined();
  });

  it("context gating allows threat-hunt with snapshot", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    const ctx = { focusedModule: "sast" };
    const shellState = {
      ...createShellState(module.tools.map((t) => t.name)),
      contextSnapshot: mockSnapshot,
    };

    const result = __shellInternals.handleLocalCommand(
      "threat-hunt .",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(result?.executedToolName).toBe("threat-hunt:run");
  });

  it("semgrep is not gated regardless of context", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    const ctx = { focusedModule: null };
    const shellState = createShellState(module.tools.map((t) => t.name));

    const result = __shellInternals.handleLocalCommand(
      "sast:semgrep .",
      core,
      opts,
      ctx,
      shellState,
    );
    // sast:semgrep resolves through the registry alias to semgrep:scan.
    expect(result?.executedToolName).toBe("semgrep:scan");
  });

  it("/target invalidates context when changed", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    opts.target = "/old";
    const shellState = {
      ...createShellState(module.tools.map((t) => t.name)),
      contextSnapshot: mockSnapshot,
    };
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand("/target /new", core, opts, ctx, shellState);
    expect(result?.output).toContain("Context invalidated");
    expect(result?.shellStateUpdater).toBeTypeOf("function");

    const updated = result!.shellStateUpdater!(shellState);
    expect(updated.contextSnapshot).toBeNull();
  });

  it("/target does not invalidate when unchanged", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    opts.target = "/same";
    const shellState = {
      ...createShellState(module.tools.map((t) => t.name)),
      contextSnapshot: mockSnapshot,
    };
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand(
      "/target /same",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(result?.output).toBe("Target set to: /same");
    expect(result?.shellStateUpdater).toBeUndefined();
  });
});

describe("assistant streaming", () => {
  it("prefers streamed assistant text over the final result payload", async () => {
    const streamedText = __shellInternals.extractAssistantText([
      { type: "text", text: "Investigating " },
      { type: "text", text: "the repo" },
      { type: "tool_use", name: "ignored" },
    ]);

    expect(streamedText).toBe("Investigating the repo");
    expect(__shellInternals.finalizeAssistantText(streamedText, "fallback result")).toBe(
      "Investigating the repo",
    );
    expect(__shellInternals.finalizeAssistantText(undefined, "fallback result")).toBe(
      "fallback result",
    );
  });
});

describe("session creation", () => {
  it("surfaces createSession failures without crashing", async () => {
    const runtime = {
      id: "test",
      async *query() {},
      createSession() {
        throw new Error("bad api key format");
      },
    } as AgentRuntime;

    const outcome = createShellSession(runtime, {
      cwd: process.cwd(),
      model: baseConfig.model,
    });

    expect(outcome.session).toBeUndefined();
    expect(outcome.error).toContain("bad api key format");
  });
});

describe("shell history persistence", () => {
  it("persists capped shell history to disk", async () => {
    const tempDir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-shell-history-"));
    tempDirs.push(tempDir);

    const commands = Array.from({ length: 1005 }, (_, index) => `cmd-${index}`);
    saveShellCommandHistory(tempDir, commands);

    const loaded = loadShellCommandHistory(tempDir);
    expect(loaded).toHaveLength(1000);
    expect(loaded[0]).toBe("cmd-5");
    expect(loaded.at(-1)).toBe("cmd-1004");
  });
});

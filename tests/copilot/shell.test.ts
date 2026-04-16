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

function createMockCore() {
  const module = createCoreSastModule();
  const executeTool = vi.fn(async (_toolName: string, input: unknown) => ({
    ok: true,
    output: JSON.stringify(input),
  }));

  const core = {
    listModules: () => [
      {
        id: module.id,
        displayName: module.displayName,
        category: module.category,
        version: module.version,
        description: module.description,
        toolCount: module.tools.length,
        taskCount: 0,
        loaded: true,
      },
    ],
    hasModule: (id: string) => id === module.id,
    executeTool,
    registry: {
      get: () => module,
      allTools: () => module.tools.map((tool) => ({ module, tool })),
      moduleTools: () => module.tools,
      resolveTool: (name: string) => {
        const tool = module.tools.find((entry) => entry.name === name);
        return tool ? { module, tool } : undefined;
      },
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
  it("renders top-level and focused prompts consistently", () => {
    expect(buildShellPrompt(null)).toBe("kuzushi> ");
    expect(buildShellPrompt("sast")).toBe("kuzushi/sast> ");
  });
});

describe("local shell commands", () => {
  it("uses slash-prefixed commands for workspace, focus, and help", () => {
    const { core, module } = createMockCore();
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
    expect(toolsResult?.output).toContain("threat-hunt");
    expect(toolsResult?.output).not.toContain("sast:threat-hunt");

    const backResult = __shellInternals.handleLocalCommand("/back", core, opts, ctx, shellState);
    expect(backResult).toEqual({ setFocus: null, output: "Returned to top level." });

    expect(
      __shellInternals.handleLocalCommand("help", core, opts, ctx, shellState),
    ).toBeUndefined();
  });

  it("renders options tables and stores per-tool settings", () => {
    const { core, module } = createMockCore();
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

  it("errors on unknown slash commands and missing /set context", () => {
    const { core, module } = createMockCore();
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

  it("supports clear/history and bare exit aliases", () => {
    const { core, module } = createMockCore();
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
    const { core, module, executeTool } = createMockCore();
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
    expect(qualified?.executedToolName).toBe("sast:semgrep");

    const global = __shellInternals.handleLocalCommand(
      "semgrep .",
      core,
      opts,
      { focusedModule: null },
      shellState,
    );
    expect(global?.executedToolName).toBe("sast:semgrep");

    const focused = __shellInternals.handleLocalCommand("scan .", core, opts, ctx, shellState);
    expect(focused?.executedToolName).toBe("sast:scan");

    const threatHunt = __shellInternals.handleLocalCommand(
      "threat-hunt /repo maxActors=7",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(threatHunt?.executedToolName).toBe("sast:threat-hunt");
    expect(threatHunt?.asyncExecute).toBeTypeOf("function");

    await threatHunt?.asyncExecute?.();

    expect(executeTool).toHaveBeenCalledWith(
      "sast:threat-hunt",
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

  it("/context with no target returns error", () => {
    const { core, module } = createMockCore();
    const opts = createShellOptions();
    opts.target = undefined;
    const shellState = createShellState(module.tools.map((t) => t.name));
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand("/context", core, opts, ctx, shellState);
    expect(result?.output).toContain("No target set");
  });

  it("/context with existing snapshot returns formatted summary", () => {
    const { core, module } = createMockCore();
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

  it("/context without snapshot dispatches sast:context tool", () => {
    const { core, module } = createMockCore();
    const opts = createShellOptions();
    opts.target = "./repo";
    const shellState = createShellState(module.tools.map((t) => t.name));
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand("/context", core, opts, ctx, shellState);
    expect(result?.executedToolName).toBe("sast:context");
    expect(result?.asyncExecute).toBeTypeOf("function");
  });

  it("/context regenerate always dispatches tool", () => {
    const { core, module } = createMockCore();
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
    expect(result?.executedToolName).toBe("sast:context");
    expect(result?.asyncExecute).toBeTypeOf("function");
  });

  it("context gating blocks threat-hunt without snapshot", () => {
    const { core, module } = createMockCore();
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

  it("context gating allows threat-hunt with snapshot", () => {
    const { core, module } = createMockCore();
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
    expect(result?.executedToolName).toBe("sast:threat-hunt");
  });

  it("semgrep is not gated regardless of context", () => {
    const { core, module } = createMockCore();
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
    expect(result?.executedToolName).toBe("sast:semgrep");
  });

  it("/target invalidates context when changed", () => {
    const { core, module } = createMockCore();
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

  it("/target does not invalidate when unchanged", () => {
    const { core, module } = createMockCore();
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
  it("prefers streamed assistant text over the final result payload", () => {
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
  it("surfaces createSession failures without crashing", () => {
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
  it("persists capped shell history to disk", () => {
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

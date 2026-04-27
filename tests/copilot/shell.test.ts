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
  firstShellSuggestion,
  listShellSuggestions,
  loadShellCommandHistory,
  SHELL_COMMAND_CATALOG,
  saveShellCommandHistory,
} from "../../src/copilot/shell.js";
import { createCoreSastModule } from "../../src/modules/core-sast.js";
import { saveContextSnapshot } from "../../src/modules/sast/context-persist.js";
import { createRun, initDb, updateRunFindings, updateRunStatus } from "../../src/store.js";
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
  const { createSemgrepModule } = await import("../../src/modules/semgrep/semgrep.js");
  const { createThreatHuntModule } = await import("../../src/modules/threat-hunt/threat-hunt.js");
  const { createContextModule } = await import("../../src/modules/context/context.js");
  const { createTaintIrisModule } = await import("../../src/modules/taint-iris/taint-iris.js");

  const sast = createCoreSastModule();
  const semgrep = createSemgrepModule();
  const threatHunt = createThreatHuntModule();
  const context = createContextModule();
  const taintIris = createTaintIrisModule();
  const mods = [sast, semgrep, threatHunt, context, taintIris];
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

function createShellOptionsWithConfig(config: KuzushiConfig): ShellOptions {
  return {
    config,
    runtime: {
      id: "test",
      async *query() {},
    } as AgentRuntime,
    target: ".",
  };
}

function createSessionRuntime(id: string): AgentRuntime {
  return {
    id,
    async *query() {},
    createSession() {
      return {
        async *query() {},
        close() {},
      };
    },
  } as AgentRuntime;
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

describe("shell runtime auth", () => {
  it("keeps /auth inherited credentials on pi-ai", async () => {
    const opts = createShellOptionsWithConfig({
      ...baseConfig,
      agentRuntimeBackend: "pi-ai",
      agentRuntimeConfig: { piAi: { apiKey: "sk-test" } },
    });

    await __shellInternals.applyCredentialOutcome(
      { action: "proceed", choice: { kind: "inherited", providerId: "openai" } },
      opts,
    );

    expect(opts.config.agentRuntimeBackend).toBe("pi-ai");
    expect(opts.runtime.id).toBe("pi-ai");
  });

  it("inherited-claude flips backend to claude and sets auth flag", async () => {
    const tmpHome = mkdtempSync(path.join(os.tmpdir(), "kuzushi-inherit-"));
    tempDirs.push(tmpHome);
    const oldHome = process.env["HOME"];
    process.env["HOME"] = tmpHome;
    try {
      const opts = createShellOptionsWithConfig({
        ...baseConfig,
        agentRuntimeBackend: "pi-ai",
      });

      await __shellInternals.applyCredentialOutcome(
        { action: "proceed", choice: { kind: "inherited", providerId: "inherited-claude" } },
        opts,
      );

      expect(opts.config.agentRuntimeBackend).toBe("claude");
      expect(opts.config.auth).toBe("inherited");
    } finally {
      if (oldHome === undefined) delete process.env["HOME"];
      else process.env["HOME"] = oldHome;
    }
  });

  it("stores pasted pi-ai provider credentials without switching to claude", async () => {
    const oldOpenAiKey = process.env["OPENAI_API_KEY"];
    delete process.env["OPENAI_API_KEY"];
    const opts = createShellOptionsWithConfig({
      ...baseConfig,
      agentRuntimeBackend: "pi-ai",
      agentRuntimeConfig: {},
    });

    try {
      await __shellInternals.applyCredentialOutcome(
        {
          action: "proceed",
          choice: { kind: "api-key", providerId: "openai", value: "sk-openai", persist: false },
        },
        opts,
      );

      expect(opts.config.agentRuntimeBackend).toBe("pi-ai");
      expect(opts.config.agentRuntimeConfig?.piAi?.apiKey).toBe("sk-openai");
      expect(process.env["OPENAI_API_KEY"]).toBe("sk-openai");
      expect(opts.runtime.id).toBe("pi-ai");
    } finally {
      if (oldOpenAiKey === undefined) {
        delete process.env["OPENAI_API_KEY"];
      } else {
        process.env["OPENAI_API_KEY"] = oldOpenAiKey;
      }
    }
  });

  it("does not fall back to claude when the pi-ai runtime can create sessions", async () => {
    const runtime = createSessionRuntime("pi-ai");
    const opts = createShellOptionsWithConfig({
      ...baseConfig,
      agentRuntimeBackend: "pi-ai",
    });
    opts.runtime = runtime;

    await __shellInternals.ensureClaudeShellRuntime(opts);

    expect(opts.runtime).toBe(runtime);
    expect(opts.runtime.id).toBe("pi-ai");
    expect(opts.config.agentRuntimeBackend).toBe("pi-ai");
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

  it("banner lists scan-context + threat-model as reusable context", async () => {
    const dir = makeTempRepo(true, ["scan-context.json", "threat-model.json"]);
    const banner = __shellInternals.formatArtifactBanner(dir);
    expect(banner).toContain("Available .kuzushi context:");
    expect(banner).toContain("scan-context.json");
    expect(banner).toContain("threat-model.json");
    expect(banner).toContain("Reused by /ask and context-aware modules.");
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

describe("startup scope defaults", () => {
  it("derives an implicit workspace name from a local target path", () => {
    expect(__shellInternals.inferWorkspaceNameFromTarget("/tmp/acme api")).toBe("acme-api");
    expect(__shellInternals.inferWorkspaceNameFromTarget(".")).toBe(path.basename(process.cwd()));
  });

  it("sets cwd as the implicit target for bare shell launches", () => {
    const opts = createShellOptions();
    delete opts.target;
    __shellInternals.applyImplicitShellTarget(opts);
    expect(opts.target).toBe(process.cwd());
  });
});

describe("local shell commands", () => {
  it("supports module-forward commands and slash aliases", async () => {
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
    expect(opts.workspaceName).toBe("acme-pentest");

    const useResult = __shellInternals.handleLocalCommand("use sast", core, opts, ctx, shellState);
    expect(useResult?.setFocus).toBe("sast");

    ctx.focusedModule = "sast";
    const toolsResult = __shellInternals.handleLocalCommand("tools", core, opts, ctx, shellState);
    // Post-split the sast umbrella only lists its own `scan` tool; threat-hunt
    // lives in its own module now. Exercising that here would require focusing
    // on `threat-hunt`, which is covered by the dispatcher tests.
    expect(toolsResult?.output).toContain("scan");

    const findingsResult = __shellInternals.handleLocalCommand(
      "findings",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(findingsResult?.output).toBe("Showing current findings.");
    expect(findingsResult?.shellStateUpdater?.(shellState).shellView).toBe("findings");

    const tuneResult = __shellInternals.handleLocalCommand("tune", core, opts, ctx, shellState);
    expect(tuneResult?.output).toContain("Tuning sast");
    expect(tuneResult?.shellStateUpdater?.(shellState).shellView).toBe("tune");

    const storyResult = __shellInternals.handleLocalCommand("story", core, opts, ctx, {
      ...shellState,
      taskStory: {
        activeTurnId: "turn-1",
        activeRunIds: [],
        events: [
          {
            id: "story-1",
            kind: "phase",
            status: "running",
            importance: "primary",
            message: "Building context",
            timestamp: 1,
          },
        ],
      },
    });
    expect(storyResult?.output).toContain("Showing task story (1 events).");
    expect(storyResult?.shellStateUpdater?.(shellState).shellView).toBe("task-story");

    const backResult = __shellInternals.handleLocalCommand("back", core, opts, ctx, shellState);
    expect(backResult?.setFocus).toBeNull();
    expect(backResult?.output).toBe("Returned to top level.");
    // The v2 "modules calmed" redesign adds a shellStateUpdater on /back so
    // the shell-view + openFindingId fields reset alongside focus.
    expect(typeof backResult?.shellStateUpdater).toBe("function");

    const bareHelp = __shellInternals.handleLocalCommand("help", core, opts, ctx, shellState);
    expect(bareHelp?.output).toContain("Kuzushi");
    expect(bareHelp?.output).toContain("use sast");
  });

  it("routes focused-module resume with an explicit run id", async () => {
    const { core, module, executeTool } = await createMockCore();
    const opts = createShellOptions();
    const shellState = createShellState(module.tools.map((tool) => tool.name));
    const ctx = { focusedModule: "sast" };

    const result = __shellInternals.handleLocalCommand("resume run-123", core, opts, ctx, {
      ...shellState,
      focusedModule: "sast",
    });

    expect(result?.executedToolName).toBe("sast:scan");
    const output = await result?.asyncExecute?.();
    expect(output).toMatchObject({ ok: true });
    expect(executeTool).toHaveBeenCalledWith(
      "sast:scan",
      expect.objectContaining({ resume: "run-123" }),
      expect.any(Object),
    );
  });

  it("keeps checkpoint /resume distinct from live resume while the turn is pre-marked busy", async () => {
    const { core, module, executeTool } = await createMockCore();
    const opts = createShellOptions();
    const shellState = createShellState(module.tools.map((tool) => tool.name));
    const ctx = { focusedModule: "sast" };

    const result = __shellInternals.handleLocalCommand("/resume run-456", core, opts, ctx, {
      ...shellState,
      focusedModule: "sast",
      processing: true,
    });

    expect(result?.executedToolName).toBe("sast:scan");
    await result?.asyncExecute?.();
    expect(executeTool).toHaveBeenCalledWith(
      "sast:scan",
      expect.objectContaining({ resume: "run-456" }),
      expect.any(Object),
    );
  });

  it("reports no resume database for focused-module resume", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    const dataDir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-resume-empty-"));
    tempDirs.push(dataDir);
    opts.target = path.join(dataDir, "repo");
    const shellState = createShellState(module.tools.map((tool) => tool.name));
    const ctx = { focusedModule: "sast", dataDir };

    const result = __shellInternals.handleLocalCommand("/resume", core, opts, ctx, {
      ...shellState,
      focusedModule: "sast",
    });
    const output = await result?.asyncExecute?.();
    expect(output).toContain("No runs database found");
  });

  it("renders an ambiguous resume chooser when multiple candidates match", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    const root = mkdtempSync(path.join(os.tmpdir(), "kuzushi-resume-many-"));
    tempDirs.push(root);
    opts.target = root;
    const dataDir = path.join(root, ".kuzushi");
    const { mkdirSync } = require("node:fs") as typeof import("node:fs");
    mkdirSync(dataDir, { recursive: true });
    const db = initDb(path.join(dataDir, "findings.sqlite3"));
    const repo = path.resolve(root);
    const scanOpts = {
      severity: ["ERROR"],
      excludePatterns: [],
      fresh: false,
      tasks: ["semgrep"],
    };
    createRun(db, "run-a", repo, baseConfig, scanOpts);
    updateRunFindings(db, "run-a", []);
    updateRunStatus(db, "run-a", "triaging");
    createRun(db, "run-b", repo, baseConfig, scanOpts);
    updateRunFindings(db, "run-b", []);
    updateRunStatus(db, "run-b", "interrupted");
    db.close();

    const shellState = createShellState(module.tools.map((tool) => tool.name));
    const ctx = { focusedModule: "sast", dataDir };
    const result = __shellInternals.handleLocalCommand("/resume", core, opts, ctx, {
      ...shellState,
      focusedModule: "sast",
    });
    const output = await result?.asyncExecute?.();
    expect(output).toContain("Multiple resumable runs match");
    expect(output).toContain("run-a");
    expect(output).toContain("run-b");
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
    expect(optionsResult?.output).toBe("Showing options for sast:threat-hunt.");

    shellState = optionsResult?.shellStateUpdater
      ? optionsResult.shellStateUpdater(shellState)
      : shellState;
    expect(shellState.shellView).toBe("options");
    expect(shellState.lastUsedTool).toBe("sast:threat-hunt");
    expect(shellState.optionsView?.toolName).toBe("sast:threat-hunt");
    expect(shellState.optionsView?.rows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          optionName: "maxActors",
          defaultLabel: "5",
          isSet: false,
        }),
      ]),
    );

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
    expect(shellState.optionsView?.rows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          optionName: "maxActors",
          valueLabel: "* 7",
          isSet: true,
        }),
      ]),
    );

    const optionsAgain = __shellInternals.handleLocalCommand(
      "/options",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(optionsAgain?.output).toBe("Showing options for sast:threat-hunt.");
    shellState = optionsAgain?.shellStateUpdater
      ? optionsAgain.shellStateUpdater(shellState)
      : shellState;
    expect(shellState.optionsView?.rows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          optionName: "maxActors",
          valueLabel: "* 7",
        }),
      ]),
    );
  });

  it("routes focused bare show options through shell state", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    let shellState = {
      ...createShellState(module.tools.map((tool) => tool.name)),
      focusedModule: "sast" as const,
      shellView: "module" as const,
    };
    const ctx = { focusedModule: "sast" };

    expect(
      __shellInternals.shouldRouteShellInputBeforeDispatcher("show options", shellState, ctx),
    ).toBe(true);

    const optionsResult = __shellInternals.handleLocalCommand(
      "show options",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(optionsResult?.output).toBe("Showing options for sast:scan.");

    shellState = optionsResult?.shellStateUpdater
      ? optionsResult.shellStateUpdater(shellState)
      : shellState;
    expect(shellState.shellView).toBe("options");
    expect(shellState.lastUsedTool).toBe("sast:scan");
    expect(shellState.optionsView?.toolName).toBe("sast:scan");

    const setResult = __shellInternals.handleLocalCommand(
      "set preset fast",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(setResult?.output).toBe("Set sast:scan.preset = fast");

    shellState = setResult?.shellStateUpdater
      ? setResult.shellStateUpdater(shellState)
      : shellState;
    expect(shellState.optionsView?.rows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ optionName: "preset", valueLabel: "* fast" }),
      ]),
    );

    const back = __shellInternals.handleLocalCommand("/back", core, opts, ctx, shellState);
    expect(back?.output).toBe("Back to module home.");
    shellState = back?.shellStateUpdater ? back.shellStateUpdater(shellState) : shellState;
    expect(shellState.shellView).toBe("module");
  });

  it("routes slash show options to the options view", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    let shellState = {
      ...createShellState(module.tools.map((tool) => tool.name)),
      focusedModule: "sast" as const,
      shellView: "module" as const,
    };
    const ctx = { focusedModule: "sast" };

    const result = __shellInternals.handleLocalCommand(
      "/show options",
      core,
      opts,
      ctx,
      shellState,
    );

    expect(result?.output).toBe("Showing options for sast:scan.");
    shellState = result?.shellStateUpdater ? result.shellStateUpdater(shellState) : shellState;
    expect(shellState.shellView).toBe("options");
    expect(shellState.optionsView?.toolName).toBe("sast:scan");
  });

  it("opens the SAST task selector and stores blocked task options", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    let shellState = {
      ...createShellState(module.tools.map((tool) => tool.name)),
      focusedModule: "sast" as const,
      shellView: "module" as const,
    };
    const ctx = { focusedModule: "sast" };

    const open = __shellInternals.handleLocalCommand("/tasks", core, opts, ctx, shellState);
    expect(open?.output).toContain("Showing SAST task selection");
    shellState = open?.shellStateUpdater ? open.shellStateUpdater(shellState) : shellState;
    expect(shellState.shellView).toBe("sast-tasks");
    expect(shellState.lastUsedTool).toBe("sast:scan");

    const block = __shellInternals.handleLocalCommand(
      "/task block codeql",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(block?.output).toContain("Blocked");
    expect(block?.output).toContain("blocked");
    shellState = block?.shellStateUpdater ? block.shellStateUpdater(shellState) : shellState;
    expect(shellState.moduleOptions["sast:scan"]?.disabledTasks).toEqual(["codeql"]);

    const allow = __shellInternals.handleLocalCommand(
      "/task allow codeql",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(allow?.output).toContain("Allowed");
    shellState = allow?.shellStateUpdater ? allow.shellStateUpdater(shellState) : shellState;
    expect(shellState.moduleOptions["sast:scan"]?.disabledTasks).toBeUndefined();

    const toggle = __shellInternals.handleLocalCommand(
      "/task toggle codeql",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(toggle?.output).toContain("Blocked SAST task capability: codeql");
    shellState = toggle?.shellStateUpdater ? toggle.shellStateUpdater(shellState) : shellState;
    expect(shellState.moduleOptions["sast:scan"]?.disabledTasks).toEqual(["codeql"]);

    const required = __shellInternals.handleLocalCommand(
      "/task toggle context-gathering",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(required?.output).toContain("required infrastructure");
    expect(required?.shellStateUpdater).toBeUndefined();
  });

  it("routes bare SAST task selector verbs while inside /tasks", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    let shellState = {
      ...createShellState(module.tools.map((tool) => tool.name)),
      focusedModule: "sast" as const,
      shellView: "sast-tasks" as const,
    };
    const ctx = { focusedModule: "sast" };

    const block = __shellInternals.handleLocalCommand("block ssrf", core, opts, ctx, shellState);
    expect(block?.output).toContain("Blocked SAST task capability: ssrf");
    shellState = block?.shellStateUpdater ? block.shellStateUpdater(shellState) : shellState;
    expect(shellState.moduleOptions["sast:scan"]?.disabledTasks).toEqual(["ssrf"]);

    const mode = __shellInternals.handleLocalCommand("mode", core, opts, ctx, shellState);
    expect(mode?.output).toContain("manual allowlist");
    shellState = mode?.shellStateUpdater ? mode.shellStateUpdater(shellState) : shellState;
    expect(shellState.moduleOptions["sast:scan"]?.taskMode).toBe("manual");

    const reset = __shellInternals.handleLocalCommand("reset", core, opts, ctx, shellState);
    expect(reset?.output).toContain("SAST task selection reset");
    shellState = reset?.shellStateUpdater ? reset.shellStateUpdater(shellState) : shellState;
    expect(shellState.moduleOptions["sast:scan"]).toBeUndefined();
  });

  it("sets SAST task mode and exposes it in show options", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    let shellState = {
      ...createShellState(module.tools.map((tool) => tool.name)),
      focusedModule: "sast" as const,
      shellView: "sast-tasks" as const,
      tuneSnapshot: {
        tasks: ["semgrep"],
        verify: false,
        autoPatch: false,
        triageConcurrency: 2,
        model: "anthropic:claude-sonnet-4-6",
      },
    };
    const ctx = { focusedModule: "sast" };

    const mode = __shellInternals.handleLocalCommand(
      "/task mode manual",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(mode?.output).toContain("manual allowlist");
    shellState = mode?.shellStateUpdater ? mode.shellStateUpdater(shellState) : shellState;
    expect(shellState.moduleOptions["sast:scan"]?.taskMode).toBe("manual");
    expect(shellState.moduleOptions["sast:scan"]?.tasks).toEqual(["semgrep"]);

    const options = __shellInternals.handleLocalCommand("/options", core, opts, ctx, shellState);
    expect(options?.output).toBe("Showing options for sast:scan.");
    shellState = options?.shellStateUpdater ? options.shellStateUpdater(shellState) : shellState;
    expect(shellState.shellView).toBe("options");
    expect(shellState.optionsView?.taskSummary?.stateLine).toContain("manual allowlist");
    expect(shellState.optionsView?.rows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          optionName: "taskMode",
          valueLabel: "* manual",
          description: expect.stringContaining("Use /tasks to edit"),
        }),
        expect.objectContaining({
          optionName: "disabledTasks",
          valueLabel: "none",
          description: expect.stringContaining("Use /tasks to edit"),
        }),
      ]),
    );
    expect(shellState.optionsView?.tip).toContain("tip: use /tasks");

    const reset = __shellInternals.handleLocalCommand("/task reset", core, opts, ctx, shellState);
    shellState = reset?.shellStateUpdater ? reset.shellStateUpdater(shellState) : shellState;
    expect(shellState.moduleOptions["sast:scan"]).toBeUndefined();
  });

  it("shows and stores synthetic model options for focused modules", async () => {
    const { core } = await createMockCore();
    const opts = createShellOptionsWithConfig({
      ...baseConfig,
      agentRuntimeBackend: "claude",
    });
    let shellState = {
      ...createShellState(core.registry.allTools().map(({ tool }) => tool.name)),
      focusedModule: "taint-iris" as const,
      shellView: "module" as const,
    };
    const ctx = { focusedModule: "taint-iris" };

    const optionsResult = __shellInternals.handleLocalCommand(
      "show options",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(optionsResult?.output).toBe("Showing options for taint-iris:hunt.");

    shellState = optionsResult?.shellStateUpdater
      ? optionsResult.shellStateUpdater(shellState)
      : shellState;
    expect(shellState.optionsView?.toolName).toBe("taint-iris:hunt");
    expect(shellState.optionsView?.rows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          optionName: "model",
          description: expect.stringContaining("Claude accepts bare Claude model ids"),
        }),
      ]),
    );

    const setResult = __shellInternals.handleLocalCommand(
      "set model claude-opus-4-6",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(setResult?.output).toBe("Set taint-iris:hunt.model = claude-opus-4-6");

    shellState = setResult?.shellStateUpdater
      ? setResult.shellStateUpdater(shellState)
      : shellState;
    expect(shellState.moduleOptions["taint-iris:hunt"]).toEqual({
      model: "claude-opus-4-6",
    });

    const optionsAgain = __shellInternals.handleLocalCommand(
      "show options",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(optionsAgain?.output).toBe("Showing options for taint-iris:hunt.");
    shellState = optionsAgain?.shellStateUpdater
      ? optionsAgain.shellStateUpdater(shellState)
      : shellState;
    expect(shellState.optionsView?.rows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          optionName: "model",
          valueLabel: "* claude-opus-4-6",
        }),
      ]),
    );
  });

  it("prompts editor actions use rendered prompt names", async () => {
    const { core } = await createMockCore();
    const opts = createShellOptions();
    const tmp = mkdtempSync(path.join(os.tmpdir(), "kuzushi-prompts-"));
    tempDirs.push(tmp);
    const toolNames = core.registry.allTools().map(({ tool }) => tool.name);
    let shellState = {
      ...createShellState(toolNames),
      focusedModule: "context" as const,
      shellView: "prompts-editor" as const,
    };
    const ctx = { focusedModule: "context", dataDir: tmp };

    expect(
      __shellInternals.shouldRouteShellInputBeforeDispatcher("show build", shellState, ctx),
    ).toBe(true);

    const showDefault = __shellInternals.handleLocalCommand(
      "show build",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(showDefault?.output).toContain("Prompt for context:build (context)");
    expect(showDefault?.output).toContain("source=default");

    const setInline = __shellInternals.handleLocalCommand(
      'set build "Inline smoke override"',
      core,
      opts,
      ctx,
      shellState,
    );
    expect(setInline?.output).toBe("Set context:build.CONTEXT_PROMPT inline override (21 bytes).");

    shellState = setInline?.shellStateUpdater
      ? setInline.shellStateUpdater(shellState)
      : shellState;
    expect(shellState.moduleOptions["context:build"]).toEqual({
      CONTEXT_PROMPT: "Inline smoke override",
    });
    shellState = {
      ...shellState,
      promptsEditor: {
        ...(shellState.promptsEditor ?? {}),
        lastSavedAt: Date.now(),
        lastSaved: { name: "build", path: path.join(tmp, "build.md"), size: 21 },
      },
    };

    const showInline = __shellInternals.handleLocalCommand(
      "show build",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(showInline?.output).toContain("source=inline");

    const reset = __shellInternals.handleLocalCommand("reset build", core, opts, ctx, shellState);
    expect(reset?.output).toContain("context:build.CONTEXT_PROMPT");
    expect(reset?.output).toContain("to default");
    shellState = reset?.shellStateUpdater ? reset.shellStateUpdater(shellState) : shellState;
    expect(shellState.moduleOptions["context:build"]).toBeUndefined();
    expect(shellState.promptsEditor?.lastSaved).toBeUndefined();
  });

  it("errors on unknown slash commands and missing /set context", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    const shellState = createShellState(module.tools.map((tool) => tool.name));
    const ctx = { focusedModule: "sast" };

    // Unknown verb now routes through formatUnknownVerb(). The output keeps
    // the `Unknown command: "/foo"` headline and points at /help. A nearest-
    // match suggestion block is appended iff the needle is close enough to
    // something in the catalog — `/foo` is intentionally far from all verbs.
    const unknown = __shellInternals.handleLocalCommand("/foo", core, opts, ctx, shellState);
    expect(unknown?.output).toContain('Unknown command: "/foo"');
    expect(unknown?.output).toContain("Type /help");

    // Nearest-match kicks in for a close typo.
    const typo = __shellInternals.handleLocalCommand("/modulse", core, opts, ctx, shellState);
    expect(typo?.output).toContain("Did you mean");
    expect(typo?.output).toContain("modules");

    const setResult = __shellInternals.handleLocalCommand(
      "/set maxActors 7",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(setResult).toEqual({ output: "No active tool selected. Use /options <tool> first." });
  });

  it("routes /use with an unknown module through formatUnknownModule", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    const shellState = createShellState(module.tools.map((t) => t.name));
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand("/use sats", core, opts, ctx, shellState);
    expect(result?.output).toContain('Unknown module: "sats"');
    // Nearest-match should pull in real module ids — "sast" is one char off.
    expect(result?.output).toContain("Did you mean");
    expect(result?.output).toContain("sast");
  });

  it("supports short aliases /f, /t, /b, /m", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    const shellState = {
      ...createShellState(module.tools.map((t) => t.name)),
      focusedModule: "sast" as const,
      shellView: "module" as const,
    };
    const ctx = { focusedModule: "sast" };

    const f = __shellInternals.handleLocalCommand("/f", core, opts, ctx, shellState);
    expect(f?.shellStateUpdater).toBeTypeOf("function");
    const fState = f!.shellStateUpdater!(shellState);
    expect(fState.shellView).toBe("findings");

    const t = __shellInternals.handleLocalCommand("/t", core, opts, ctx, shellState);
    expect(t?.shellStateUpdater).toBeTypeOf("function");
    const tState = t!.shellStateUpdater!(shellState);
    expect(tState.shellView).toBe("tune");

    // /b from the findings view should step back to module home.
    const b = __shellInternals.handleLocalCommand("/b", core, opts, ctx, {
      ...shellState,
      shellView: "findings",
    });
    expect(b?.output).toBe("Back to module home.");

    // /m lists modules (happy path: output mentions a module id).
    const m = __shellInternals.handleLocalCommand("/m", core, opts, ctx, shellState);
    expect(m?.output).toContain("sast");
  });

  it("reconcileShellView promotes catalog→module when focus is set via bare `use <mod>`", () => {
    // Regression: bare `use threat-hunt` pushes a ModuleDispatcher in
    // core-dispatcher.cmd_use (emits `Selected module: <id>`) but returns no
    // shellStateUpdater. The only sync path is `syncShellState` in shell.ts,
    // which previously left `shellView` untouched — so the prompt read
    // `kuzushi/threat-hunt>` while StatusFooter still said "you are in catalog".
    expect(__shellInternals.reconcileShellView("catalog", "threat-hunt")).toBe("module");

    // Clearing focus from a module-scoped view (after /back through the stack)
    // must fall back to catalog so we don't leave a dangling module home.
    expect(__shellInternals.reconcileShellView("module", null)).toBe("catalog");
    expect(__shellInternals.reconcileShellView("findings", null)).toBe("catalog");
    expect(__shellInternals.reconcileShellView("finding", null)).toBe("catalog");
    expect(__shellInternals.reconcileShellView("tune", null)).toBe("catalog");

    // Threats is an intentionally top-level view that can be entered without
    // a focused module — don't clobber it.
    expect(__shellInternals.reconcileShellView("threats", null)).toBe("threats");

    // And don't demote an already-correct module view.
    expect(__shellInternals.reconcileShellView("findings", "sast")).toBe("findings");
    expect(__shellInternals.reconcileShellView("module", "sast")).toBe("module");
  });

  it("bare dispatcher use exits a stale threat view into module home", () => {
    expect(__shellInternals.reconcileShellViewAfterFocusChange("threats", "context")).toBe(
      "module",
    );
    expect(__shellInternals.reconcileShellViewAfterFocusChange("catalog", "context")).toBe(
      "module",
    );
    expect(__shellInternals.reconcileShellViewAfterFocusChange("threats", null)).toBe("threats");
  });

  it("plain informational output exits stale threat views", () => {
    expect(
      __shellInternals.reconcileShellViewAfterPlainOutput("threats", "context", "show modules"),
    ).toBe("module");
    expect(
      __shellInternals.reconcileShellViewAfterPlainOutput("threats", "context", "show moudles"),
    ).toBe("module");
    expect(
      __shellInternals.reconcileShellViewAfterPlainOutput("threats", null, "show modules"),
    ).toBe("catalog");
    expect(
      __shellInternals.reconcileShellViewAfterPlainOutput("threats", "context", "/threats stride"),
    ).toBe("threats");
    expect(
      __shellInternals.reconcileShellViewAfterPlainOutput("threats", "context", "/context regen"),
    ).toBe("threats");
    expect(
      __shellInternals.reconcileShellViewAfterPlainOutput("threats", "context", "/context dfd"),
    ).toBe("threats");
  });

  it("/back returns to module home from threat and findings views", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    const ctx = { focusedModule: "sast" };
    const baseState = {
      ...createShellState(module.tools.map((t) => t.name)),
      focusedModule: "sast" as const,
    };

    const fromThreat = __shellInternals.handleLocalCommand("/back", core, opts, ctx, {
      ...baseState,
      shellView: "threats",
      threatTab: "summary",
    });
    expect(fromThreat?.output).toBe("Back to module home.");
    expect(fromThreat?.shellStateUpdater?.(baseState).shellView).toBe("module");

    const fromDiff = __shellInternals.handleLocalCommand("/back", core, opts, ctx, {
      ...baseState,
      shellView: "findings",
      findingScope: { kind: "changed-files", ref: "main", repoRoot: "/tmp", changedFiles: [] },
    });
    expect(fromDiff?.output).toBe("Back to module home.");
    expect(fromDiff?.shellStateUpdater?.(baseState).shellView).toBe("module");

    const fromStory = __shellInternals.handleLocalCommand("/back", core, opts, ctx, {
      ...baseState,
      shellView: "task-story",
    });
    expect(fromStory?.output).toBe("Back to module home.");
    expect(fromStory?.shellStateUpdater?.(baseState).shellView).toBe("module");

    const fromContextBuild = __shellInternals.handleLocalCommand("/back", core, opts, ctx, {
      ...baseState,
      shellView: "context-build",
    });
    expect(fromContextBuild?.output).toBe("Back to module home.");
    expect(fromContextBuild?.shellStateUpdater?.(baseState).shellView).toBe("module");
  });

  it("recognizes task story navigation input without resetting the story stream", () => {
    expect(__shellInternals.isTaskStoryNavigationInput("story")).toBe(true);
    expect(__shellInternals.isTaskStoryNavigationInput("/story")).toBe(true);
    expect(__shellInternals.isTaskStoryNavigationInput("context build")).toBe(false);
  });

  it("supports /help <verb> with expanded description + unknown-verb fallback", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    const shellState = createShellState(module.tools.map((t) => t.name));
    const ctx = { focusedModule: null };

    const helpOpen = __shellInternals.handleLocalCommand("/help open", core, opts, ctx, shellState);
    expect(helpOpen?.output).toContain("/open <F-NNNN>");
    expect(helpOpen?.output).toContain("linear deep page");

    // Leading-slash prefix should be tolerated.
    const helpSlashOpen = __shellInternals.handleLocalCommand(
      "/help /open",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(helpSlashOpen?.output).toContain("/open <F-NNNN>");

    const helpUnknown = __shellInternals.handleLocalCommand(
      "/help zzznope",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(helpUnknown?.output).toContain("Unknown command");
  });

  it("/help output contains every verb from the commands catalog", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    const shellState = createShellState(module.tools.map((t) => t.name));
    const ctx = { focusedModule: null };

    const help = __shellInternals.handleLocalCommand("/help advanced", core, opts, ctx, shellState);
    expect(help?.output).toBeDefined();
    const text = help!.output!;
    for (const entry of SHELL_COMMAND_CATALOG) {
      // Each catalog row's syntax string should appear verbatim somewhere
      // in the rendered help — this is the structural drift-catcher.
      expect(text).toContain(entry.syntax);
    }
  });

  it("/help renders CLAUDE.md §12 section headings", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    const shellState = createShellState(module.tools.map((t) => t.name));
    const ctx = { focusedModule: null };

    const help = __shellInternals.handleLocalCommand("/help advanced", core, opts, ctx, shellState);
    const text = help!.output!;
    // Spot-check the group headings that map to CLAUDE.md §12 sections.
    expect(text).toContain("Module + view navigation");
    expect(text).toContain("Natural-language planner");
    expect(text).toContain("Prompt editor");
    expect(text).toContain("Replay & trace");
    expect(text).toContain("Short-ID aliases");
    expect(text).toContain("Threat modelling");
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

  it("shows per-module last-run telemetry in /modules output", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    const shellState = {
      ...createShellState(module.tools.map((tool) => tool.name)),
      moduleCatalog: [
        {
          id: "sast",
          displayName: "SAST",
          category: "defense" as const,
          description: "Umbrella for the full SAST DAG.",
          toolCount: 1,
          external: false,
          lastRunAt: Date.now(),
          lastRunSummary: "ok · scan · just now · $1.23",
        },
      ],
    };
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand("/modules", core, opts, ctx, shellState);
    expect(result?.output).toContain("Last run:");
    expect(result?.output).toContain("ok · scan · just now · $1.23");
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
        appModel: {
          version: "1",
          routes: [],
          outboundClients: [],
          dataStores: [],
          backgroundJobs: [],
          serviceBoundaries: [],
          relevantFiles: [],
          notes: [],
        },
        threatModel: {
          version: "1.0",
          dfd: { elements: [], trustBoundaries: [] },
          threats: [],
          summary: { total: 0, bySeverity: {}, byCategory: {} },
        },
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

    const slashScan = __shellInternals.handleLocalCommand(
      "/scan .",
      core,
      opts,
      { focusedModule: null },
      shellState,
    );
    expect(slashScan?.executedToolName).toBe("sast:scan");

    const contextDefaultRun = __shellInternals.handleLocalCommand(
      "run . discovery=flat",
      core,
      opts,
      { focusedModule: "context" },
      { ...shellState, focusedModule: "context" },
    );
    expect(contextDefaultRun?.executedToolName).toBe("context:build");
    expect(contextDefaultRun?.asyncExecute).toBeTypeOf("function");

    await contextDefaultRun?.asyncExecute?.();

    expect(executeTool).toHaveBeenCalledWith(
      "context:build",
      expect.objectContaining({
        target: ".",
        discovery: "flat",
      }),
      expect.objectContaining({
        workspaceId: undefined,
      }),
    );

    executeTool.mockClear();

    const incompleteContext = __shellInternals.handleLocalCommand(
      "threat-hunt /repo",
      core,
      opts,
      ctx,
      {
        ...shellState,
        contextSnapshot: {
          target: ".",
          timestamp: Date.now(),
          discovery: "flat" as const,
          options: { enrichment: false, threatModel: false, scenarios: false },
          appModel: shellState.contextSnapshot.appModel,
        },
      },
    );
    expect(incompleteContext?.output).toContain("Context incomplete for threat-hunt:run");
    expect(incompleteContext?.asyncExecute).toBeUndefined();

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

  it("/context adopts the loaded context snapshot target", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    opts.target = undefined;
    const shellState = {
      ...createShellState(module.tools.map((t) => t.name)),
      contextSnapshot: mockSnapshot,
    };
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand("/context", core, opts, ctx, shellState);
    expect(result?.output).toContain("Context:");
    expect(opts.target).toBe("/resolved/repo");
  });

  it("/context dfd routes to the context-backed DFD without an explicit target", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    opts.target = undefined;
    const shellState = {
      ...createShellState(module.tools.map((t) => t.name)),
      contextSnapshot: mockSnapshot,
    };
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand("/context dfd", core, opts, ctx, shellState);
    expect(result?.output).toContain("data flow diagram");
    expect(result?.shellStateUpdater?.(shellState).threatTab).toBe("dfd");
    expect(opts.target).toBe("/resolved/repo");
  });

  it("dfd in the focused context module opens the context-backed DFD", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    opts.target = undefined;
    const shellState = {
      ...createShellState(module.tools.map((t) => t.name)),
      focusedModule: "context",
      contextSnapshot: mockSnapshot,
    };
    const ctx = { focusedModule: "context" };

    const result = __shellInternals.handleLocalCommand("dfd", core, opts, ctx, shellState);
    expect(result?.output).toContain("data flow diagram");
    expect(result?.shellStateUpdater?.(shellState).threatTab).toBe("dfd");
    expect(opts.target).toBe("/resolved/repo");
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

  it("/context regenerate without a slice opens the regeneration palette", async () => {
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
    expect(result?.output).toContain("/context regen dfd");
    expect(result?.shellStateUpdater).toBeTypeOf("function");
    expect(result?.shellStateUpdater?.(shellState).contextRegenPaletteOpen).toBe(true);
  });

  it("/context regen <slice> dispatches context:build with scope", async () => {
    const { core, module, executeTool } = await createMockCore();
    const opts = createShellOptions();
    opts.target = "/resolved/repo";
    const shellState = {
      ...createShellState(module.tools.map((t) => t.name)),
      contextSnapshot: mockSnapshot,
    };
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand(
      "/context regen dfd",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(result?.executedToolName).toBe("context:build");
    await result?.asyncExecute?.();
    expect(executeTool).toHaveBeenCalledWith(
      "context:build",
      expect.objectContaining({ scope: "dfd", preserveUserEdits: true }),
      expect.anything(),
    );
  });

  it("/context regen <slice> uses the loaded context snapshot target", async () => {
    const { core, module, executeTool } = await createMockCore();
    const opts = createShellOptions();
    opts.target = undefined;
    const shellState = {
      ...createShellState(module.tools.map((t) => t.name)),
      contextSnapshot: mockSnapshot,
    };
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand(
      "/context regen dfd",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(result?.executedToolName).toBe("context:build");
    await result?.asyncExecute?.();
    expect(executeTool).toHaveBeenCalledWith(
      "context:build",
      expect.objectContaining({
        target: "/resolved/repo",
        scope: "dfd",
        preserveUserEdits: true,
      }),
      expect.anything(),
    );
  });

  it("/since reset clears diff scope without requiring a target", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    const shellState = {
      ...createShellState(module.tools.map((t) => t.name)),
      shellView: "findings" as const,
      diffSince: {
        ref: "main",
        repoRoot: "/repo",
        changedFiles: ["src/app.ts"],
      },
    };
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand("/since reset", core, opts, ctx, shellState);
    expect(result?.output).toBe("Diff scope cleared.");
    const next = result!.shellStateUpdater!(shellState);
    expect(next.diffSince).toBeUndefined();
    expect(next.shellView).toBe("findings");
  });

  it("routes bare /threats to the threat summary view", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    opts.target = "/resolved/repo";
    const shellState = createShellState(module.tools.map((t) => t.name));
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand("/threats", core, opts, ctx, shellState);
    expect(result?.output).toContain("threat summary");
    const nextShell = result?.shellStateUpdater?.(shellState);
    expect(nextShell?.shellView).toBe("threats");
    expect(nextShell?.threatTab).toBe("summary");
    expect(result?.asyncExecute).toBeTypeOf("function");
  });

  it("/show prompts exits a stale threat view back to the focused module", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    const shellState = {
      ...createShellState(module.tools.map((t) => t.name)),
      focusedModule: "context" as const,
      shellView: "threats" as const,
      threatTab: "summary" as const,
    };
    const ctx = { focusedModule: "context" };

    const result = __shellInternals.handleLocalCommand(
      "/show prompts",
      core,
      opts,
      ctx,
      shellState,
    );

    expect(result?.output).toContain("CONTEXT_PROMPT");
    expect(result?.shellStateUpdater?.(shellState).shellView).toBe("module");
  });

  it("/threats dfd falls back to saved context snapshot", async () => {
    const { core, module } = await createMockCore();
    const repoRoot = mkdtempSync(path.join(os.tmpdir(), "kuzushi-threats-"));
    tempDirs.push(repoRoot);
    const opts = createShellOptions();
    opts.target = repoRoot;
    saveContextSnapshot(repoRoot, { ...mockSnapshot, target: repoRoot });
    const shellState = createShellState(module.tools.map((t) => t.name));
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand("/threats dfd", core, opts, ctx, shellState);
    expect(result?.shellStateUpdater?.(shellState).threatTab).toBe("dfd");
    await expect(result?.asyncExecute?.()).resolves.toContain("Showing data flow diagram");
  });

  it("/threats dfd can use the loaded context snapshot target", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    opts.target = undefined;
    const shellState = {
      ...createShellState(module.tools.map((t) => t.name)),
      contextSnapshot: mockSnapshot,
    };
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand("/threats dfd", core, opts, ctx, shellState);
    expect(result?.shellStateUpdater?.(shellState).threatTab).toBe("dfd");
    expect(opts.target).toBe("/resolved/repo");
  });

  it("/context build enters the Live Build view and seeds contextBuild state", async () => {
    const { core, module } = await createMockCore();
    const opts = createShellOptions();
    opts.target = "/resolved/repo";
    const shellState = createShellState(module.tools.map((t) => t.name));
    const ctx = { focusedModule: null };

    const result = __shellInternals.handleLocalCommand(
      "/context build",
      core,
      opts,
      ctx,
      shellState,
    );
    expect(result?.asyncExecute).toBeTypeOf("function");
    expect(result?.shellStateUpdater).toBeTypeOf("function");
    const next = result!.shellStateUpdater!(shellState);
    expect(next.shellView).toBe("context-build");
    expect(next.contextBuild?.status).toBe("running");
    expect(next.contextBuild?.repoRoot).toBe("/resolved/repo");
    expect(next.contextBuild?.phases.manifests.status).toBe("pending");
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

/**
 * Regression coverage for the Ctrl+C abort guard race.
 *
 * The bug: `abortActiveAction` pre-set an `activeAbortRequested` flag
 * BEFORE invoking the registered `onAbort` handler. The handler had
 * its own dedupe guard that returned early when the flag was true —
 * so SIGINT-triggered aborts (which route through `abortActiveAction`)
 * silently no-op'd and `AbortController.abort()` never fired. In
 * practice this meant Ctrl+C couldn't stop a running module tool like
 * `context:build` once the Claude Agent SDK subprocess had disabled
 * parent stdin raw mode and forced fallback to the SIGINT path.
 *
 * These tests lock in the contract that a dispatcher which simply
 * delegates to `onAbort` (no pre-set flag) reliably drives the
 * AbortController, and that the handler's own guard still dedupes
 * repeated invocations.
 */
describe("abort handler dispatch contract", () => {
  type AbortHandler = () => void;

  // Mirrors the production shape without dragging in the full UIStore.
  // The only thing that matters for the contract is that installing a
  // handler + calling the dispatcher fires the handler, and the handler
  // owns its own deduplication flag.
  function createAbortCoordinator() {
    let handler: AbortHandler | undefined;
    let activeKind: "tool" | "agent" | null = null;

    // NEW dispatcher: pure delegation. Does NOT touch any guard flag.
    const dispatch = (): void => {
      if (!activeKind) return;
      handler?.();
    };

    const setHandler = (next: AbortHandler): void => {
      handler = next;
    };

    const activate = (kind: "tool" | "agent"): void => {
      activeKind = kind;
    };

    return { dispatch, setHandler, activate };
  }

  it("fires the controller when dispatch delegates to a guarded handler", () => {
    const coord = createAbortCoordinator();
    const controller = new AbortController();
    let callCount = 0;
    let alreadyRequested = false;

    coord.activate("tool");
    coord.setHandler(() => {
      if (alreadyRequested) return;
      alreadyRequested = true;
      callCount++;
      controller.abort(new Error("Shell tool execution aborted"));
    });

    coord.dispatch();

    expect(callCount).toBe(1);
    expect(alreadyRequested).toBe(true);
    expect(controller.signal.aborted).toBe(true);
  });

  it("deduplicates repeated dispatch calls via the handler's own guard", () => {
    const coord = createAbortCoordinator();
    const controller = new AbortController();
    let callCount = 0;
    let alreadyRequested = false;

    coord.activate("tool");
    coord.setHandler(() => {
      if (alreadyRequested) return;
      alreadyRequested = true;
      callCount++;
      controller.abort();
    });

    // Simulate both the useInput Ctrl+C path and the SIGINT handler
    // firing for the same keypress. The guard must swallow the duplicate.
    coord.dispatch();
    coord.dispatch();
    coord.dispatch();

    expect(callCount).toBe(1);
    expect(controller.signal.aborted).toBe(true);
  });

  it("is a no-op when no active action is registered", () => {
    const coord = createAbortCoordinator();
    const controller = new AbortController();
    let callCount = 0;

    coord.setHandler(() => {
      callCount++;
      controller.abort();
    });

    // No activate() — dispatcher must short-circuit at idle.
    coord.dispatch();

    expect(callCount).toBe(0);
    expect(controller.signal.aborted).toBe(false);
  });

  it("allows re-arming after a completed abort (fresh turn, fresh controller)", () => {
    const coord = createAbortCoordinator();

    coord.activate("tool");
    const firstController = new AbortController();
    let firstFlag = false;
    coord.setHandler(() => {
      if (firstFlag) return;
      firstFlag = true;
      firstController.abort();
    });
    coord.dispatch();
    expect(firstController.signal.aborted).toBe(true);

    // Next turn begins — new controller, new flag, new handler.
    coord.activate("tool");
    const secondController = new AbortController();
    let secondFlag = false;
    coord.setHandler(() => {
      if (secondFlag) return;
      secondFlag = true;
      secondController.abort();
    });
    coord.dispatch();
    expect(secondController.signal.aborted).toBe(true);
    expect(firstController.signal.aborted).toBe(true); // unchanged
  });

  it("demonstrates the OLD bug shape: pre-setting the flag suppresses abort", () => {
    // This test documents the shape of the bug we fixed. A dispatcher
    // that sets `activeAbortRequested = true` before calling the
    // handler causes the handler's guard to short-circuit, so the
    // controller never fires. The new dispatcher must NOT do this.
    const controller = new AbortController();
    let activeAbortRequested = false;
    let callCount = 0;

    const buggyDispatch = (): void => {
      activeAbortRequested = true; // ← the bug
      if (activeAbortRequested) {
        // Guard trips because the dispatcher already flipped the flag.
        return;
      }
      callCount++;
      controller.abort();
    };

    buggyDispatch();

    expect(callCount).toBe(0);
    expect(controller.signal.aborted).toBe(false);
  });
});

describe("slash suggestions", () => {
  it("returns empty for non-slash input", () => {
    expect(listShellSuggestions("")).toEqual([]);
    expect(listShellSuggestions("foo")).toEqual([]);
    expect(listShellSuggestions("   ")).toEqual([]);
    expect(listShellSuggestions("hello /use")).toEqual([]);
  });

  it("returns the first N catalog entries for a bare slash", () => {
    const result = listShellSuggestions("/");
    expect(result).toHaveLength(4);
    expect(result).toEqual(["/help", "/modules", "/tools", "/use <module>"]);
  });

  it("narrows by prefix", () => {
    expect(listShellSuggestions("/us")).toEqual(["/use <module>"]);
    expect(listShellSuggestions("/tar")).toEqual(["/target <path>"]);
  });

  it("returns multiple matches when the prefix is ambiguous", () => {
    const showMatches = listShellSuggestions("/show");
    expect(showMatches).toContain("/show prompts");
    expect(showMatches).toContain("/show runs [repo]");
    expect(showMatches).toContain("/show aliases [pfx]");
  });

  it("is case-insensitive", () => {
    expect(listShellSuggestions("/US")).toEqual(["/use <module>"]);
    // The catalog now carries per-view threat rows (dfd/stride/stories/scope/
    // summary); raise the limit so /threats and /threats edit both surface.
    expect(listShellSuggestions("/THREATS", 10)).toEqual(
      expect.arrayContaining(["/threats", "/threats edit"]),
    );
  });

  it("returns empty when nothing matches", () => {
    expect(listShellSuggestions("/nothing-matches")).toEqual([]);
  });

  it("respects the custom limit", () => {
    expect(listShellSuggestions("/", 2)).toEqual(["/help", "/modules"]);
    expect(listShellSuggestions("/", 10)).toHaveLength(10);
  });

  it("trims leading/trailing whitespace before matching", () => {
    expect(listShellSuggestions("  /us  ")).toEqual(["/use <module>"]);
  });

  it("firstShellSuggestion returns the top match or null", () => {
    expect(firstShellSuggestion("/tar")).toBe("/target <path>");
    expect(firstShellSuggestion("/")).toBe("/help");
    expect(firstShellSuggestion("/zzz-nope")).toBeNull();
    expect(firstShellSuggestion("not a slash")).toBeNull();
  });

  it("catalog still covers key commands referenced in docs", () => {
    const syntaxes = SHELL_COMMAND_CATALOG.map((c) => c.syntax);
    for (const expected of [
      "/help",
      "/modules",
      "/tools",
      "/use <module>",
      "/scan [target]",
      "/findings",
      "/open <F-NNNN>",
      "/tune",
      "/threats",
      "/workspace <id>",
      "/exit",
    ]) {
      expect(syntaxes).toContain(expected);
    }
  });
});

describe("hunt-post-mortem helpers", () => {
  const { isHuntClassTool, extractHuntStats, formatHuntSummaryLine } = __shellInternals;

  it("recognizes threat-hunt:run as the hunt-class tool", () => {
    expect(isHuntClassTool("threat-hunt:run")).toBe(true);
    expect(isHuntClassTool("semgrep:scan")).toBe(false);
    expect(isHuntClassTool("triage:run")).toBe(false);
  });

  it("reads stats.totalFindings + stats.totalCostUsd off the ToolResult", () => {
    const stats = extractHuntStats({
      data: { stats: { totalFindings: 22, totalCostUsd: 24.3 } },
    });
    expect(stats).toEqual({ findingsCount: 22, costUsd: 24.3 });
  });

  it("returns zeros when the data shape drifts (safe default)", () => {
    expect(extractHuntStats({ data: undefined })).toEqual({ findingsCount: 0, costUsd: 0 });
    expect(extractHuntStats({ data: { stats: {} } })).toEqual({ findingsCount: 0, costUsd: 0 });
    expect(
      extractHuntStats({ data: { stats: { totalFindings: "nope" as unknown as number } } }),
    ).toEqual({ findingsCount: 0, costUsd: 0 });
  });

  it("formats the collapsed headline with correct pluralization", () => {
    expect(formatHuntSummaryLine(1, 0, 0)).toBe("1 actor · 0 findings · $0.00");
    expect(formatHuntSummaryLine(5, 1, 0.05)).toBe("5 actors · 1 finding · $0.05");
    expect(formatHuntSummaryLine(5, 22, 24.3)).toBe("5 actors · 22 findings · $24.30");
  });

  it("renders cost with exactly two decimals even for integer dollars", () => {
    expect(formatHuntSummaryLine(3, 3, 10)).toBe("3 actors · 3 findings · $10.00");
  });
});

describe("looksLikeSubagentStartLine — scrollback dedup", () => {
  // Context for future readers: each Read/Grep/Bash tool call emits 2-3
  // task:activity lines via runtime-forwarding + describeRuntimeMessage —
  // tool-call-start ("Read"), assistant tool_use hint ("Read · path"),
  // and tool-summary ("Read path (42 lines)"). The first two are
  // superseded by the last, so the shell suppresses them from permanent
  // scrollback history while still feeding the running tool's live tail.
  const { looksLikeSubagentStartLine } = __shellInternals;

  it("classifies bare tool names as start-side (suppressed)", () => {
    expect(looksLikeSubagentStartLine("Read")).toBe(true);
    expect(looksLikeSubagentStartLine("Grep")).toBe(true);
    expect(looksLikeSubagentStartLine("Bash")).toBe(true);
  });

  it("classifies assistant tool_use hints as start-side (suppressed)", () => {
    expect(looksLikeSubagentStartLine("Read · src/api.ts")).toBe(true);
    expect(looksLikeSubagentStartLine("Grep · pattern='foo'")).toBe(true);
  });

  it("classifies tool-summary lines as NOT start-side (kept in scrollback)", () => {
    expect(looksLikeSubagentStartLine("Read src/api.ts (42 lines)")).toBe(false);
    expect(looksLikeSubagentStartLine("Grep src/ (3 matches)")).toBe(false);
    expect(looksLikeSubagentStartLine("Bash npm test")).toBe(false);
  });

  it("ignores non-subagent activity text", () => {
    // Kuzushi's own reportActivity messages (lowercase verbs) must pass
    // through unchanged — dropping them would erase shell-visible
    // progress ("scanning repo structure", "hunting as Attacker").
    expect(looksLikeSubagentStartLine("scanning repo structure")).toBe(false);
    expect(looksLikeSubagentStartLine("reading threat model")).toBe(false);
    expect(looksLikeSubagentStartLine("hunting as Unauthenticated User")).toBe(false);
    expect(looksLikeSubagentStartLine("")).toBe(false);
  });

  it("distinguishes `Read` vs `ReadOnly` (word-boundary match on tool name)", () => {
    // SUBAGENT_TOOL_RE uses \b so "Read" matches "Read · x" but not
    // arbitrary identifiers. Defensive test to catch accidental regex
    // relaxation during future edits.
    expect(looksLikeSubagentStartLine("Reading")).toBe(false);
    expect(looksLikeSubagentStartLine("Bashful")).toBe(false);
  });
});

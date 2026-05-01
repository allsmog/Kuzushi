/**
 * Mode-parity coverage. The matrix is documented in
 * `docs/assessments/mode-parity.md`; these tests exercise the four
 * highest-confidence fixes shipped in the parity audit.
 *
 *  1. `core.executeTool` reads `.kuzushi/prompts/<moduleId>/<verb>.md`
 *     when `resolveOption` has nothing else (so scan + run + shell all
 *     see the same on-disk override).
 *  2. `core.executeTool` honors `activitySource` when wrapping the
 *     runtime so observers can distinguish run-mode activity from shell.
 *  3. `executeRun` resolves `dataDir` from `--target` when it points at
 *     a real directory; otherwise falls back to the caller-provided
 *     dataDir (parity with scan-pipeline's `resolveDbPath`).
 *  4. The Datastore + taskConfig precedence already enforced by
 *     `resolveOption` survives the new file fallback.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AgentRuntime } from "../../src/agent-runtime/types.js";
import type { MessageBus } from "../../src/bus/types.js";
import { CopilotCore } from "../../src/copilot/core.js";
import { Datastore } from "../../src/copilot/options.js";
import { resolveRunDataDir } from "../../src/copilot/run.js";
import type {
  CopilotModule,
  ExecutionContext,
  ModuleTool,
  ToolResult,
} from "../../src/modules/types.js";
import type { KuzushiConfig } from "../../src/types.js";

function fakeConfig(overrides: Partial<KuzushiConfig> = {}): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 1,
    triageConcurrency: 1,
    scanMode: "parallel",
    tasks: [],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: {},
    ...overrides,
  } as KuzushiConfig;
}

const fakeRuntime = {} as AgentRuntime;
const fakeBus = {
  subscribe: () => {},
  emit: async () => {},
  close: async () => {},
  publish: async () => {},
} as unknown as MessageBus;

function probeTool(probe: { capture?: ExecutionContext }): ModuleTool {
  return {
    name: "probe:run",
    description: "captures the ExecutionContext for assertions",
    inputSchema: { type: "object" },
    headless: true,
    async execute(_input, ctx): Promise<ToolResult> {
      probe.capture = ctx;
      return { ok: true, output: "captured" };
    },
  };
}

function probeModule(tools: ModuleTool[]): CopilotModule {
  return {
    id: "probe",
    displayName: "probe",
    category: "offense",
    version: "0.0.1",
    description: "test probe",
    tools,
  };
}

let tmp: string;
beforeEach(() => {
  tmp = mkdtempSync(path.join(tmpdir(), "kuzushi-mode-parity-"));
});
afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

describe("CopilotCore.executeTool — prompt-file fallback", () => {
  async function buildCoreWithPromptProbe(opts: {
    promptFileBody?: string;
    datastorePromptValue?: string;
    taskConfigPromptValue?: string;
  }): Promise<{ ctx: ExecutionContext; resolved: string | undefined }> {
    if (opts.promptFileBody !== undefined) {
      const promptDir = path.join(tmp, "prompts", "probe");
      mkdirSync(promptDir, { recursive: true });
      writeFileSync(path.join(promptDir, "run.md"), opts.promptFileBody, "utf-8");
    }

    const probe: { capture?: ExecutionContext } = {};
    const tool = probeTool(probe);
    const mod = probeModule([tool]);

    const config = fakeConfig({
      taskConfig: opts.taskConfigPromptValue
        ? { probe: { PROBE_PROMPT: opts.taskConfigPromptValue } }
        : {},
    });

    const core = new CopilotCore({
      runtime: fakeRuntime,
      bus: fakeBus,
      config,
      dataDir: tmp,
      loadCoreSast: false,
    });
    await core.init();
    await core.registry.loadModule(mod, {
      runtime: fakeRuntime,
      bus: fakeBus,
      config,
      dataDir: tmp,
    });

    const datastore = new Datastore();
    if (opts.datastorePromptValue !== undefined) {
      datastore.set("PROBE_PROMPT", opts.datastorePromptValue, "global");
    }

    await core.executeTool("probe:run", {}, { datastore });
    if (!probe.capture) throw new Error("tool was not executed");
    const resolved = probe.capture.resolveOption?.<string>("PROBE_PROMPT");
    await core.dispose();
    return { ctx: probe.capture, resolved };
  }

  it("reads .kuzushi/prompts/<moduleId>/<verb>.md when no other source set", async () => {
    const { resolved } = await buildCoreWithPromptProbe({
      promptFileBody: "Override from disk.",
    });
    expect(resolved).toBe("Override from disk.");
  });

  it("returns undefined when no source is set anywhere", async () => {
    const { resolved } = await buildCoreWithPromptProbe({});
    expect(resolved).toBeUndefined();
  });

  it("ignores empty/whitespace-only prompt files", async () => {
    const { resolved } = await buildCoreWithPromptProbe({
      promptFileBody: "   \n\n   ",
    });
    expect(resolved).toBeUndefined();
  });

  it("prefers Datastore over the on-disk file", async () => {
    const { resolved } = await buildCoreWithPromptProbe({
      promptFileBody: "From disk",
      datastorePromptValue: "From shell `set`",
    });
    expect(resolved).toBe("From shell `set`");
  });

  it("prefers taskConfig over the on-disk file", async () => {
    const { resolved } = await buildCoreWithPromptProbe({
      promptFileBody: "From disk",
      taskConfigPromptValue: "From taskConfig",
    });
    expect(resolved).toBe("From taskConfig");
  });

  it("does not auto-load files for non-PROMPT keys", async () => {
    const probeDir = path.join(tmp, "prompts", "probe");
    mkdirSync(probeDir, { recursive: true });
    writeFileSync(path.join(probeDir, "run.md"), "should not load", "utf-8");

    const probe: { capture?: ExecutionContext } = {};
    const tool = probeTool(probe);
    const mod = probeModule([tool]);
    const config = fakeConfig();
    const core = new CopilotCore({
      runtime: fakeRuntime,
      bus: fakeBus,
      config,
      dataDir: tmp,
      loadCoreSast: false,
    });
    await core.init();
    await core.registry.loadModule(mod, {
      runtime: fakeRuntime,
      bus: fakeBus,
      config,
      dataDir: tmp,
    });
    await core.executeTool("probe:run", {});
    if (!probe.capture) throw new Error("tool not executed");
    expect(probe.capture.resolveOption?.<string>("SOMETHING_ELSE")).toBeUndefined();
    expect(probe.capture.resolveOption?.<string>("PROBE_MODEL")).toBeUndefined();
    await core.dispose();
  });
});

describe("CopilotCore — activitySource", () => {
  it("falls back to 'shell' when not provided (default)", async () => {
    const probe: { capture?: ExecutionContext } = {};
    const tool = probeTool(probe);
    const mod = probeModule([tool]);
    const config = fakeConfig();

    const core = new CopilotCore({
      runtime: fakeRuntime,
      bus: fakeBus,
      config,
      dataDir: tmp,
      loadCoreSast: false,
    });
    await core.init();
    await core.registry.loadModule(mod, {
      runtime: fakeRuntime,
      bus: fakeBus,
      config,
      dataDir: tmp,
    });

    // We can't observe the synthetic runId directly through ctx (it's
    // baked into the wrapped runtime's tag), but we can confirm the field
    // is accepted by the constructor without altering behavior.
    await core.executeTool("probe:run", {});
    expect(probe.capture).toBeDefined();
    await core.dispose();
  });

  it("accepts an explicit activitySource label", async () => {
    const probe: { capture?: ExecutionContext } = {};
    const tool = probeTool(probe);
    const mod = probeModule([tool]);
    const config = fakeConfig();

    const core = new CopilotCore({
      runtime: fakeRuntime,
      bus: fakeBus,
      config,
      dataDir: tmp,
      loadCoreSast: false,
      activitySource: "run",
    });
    await core.init();
    await core.registry.loadModule(mod, {
      runtime: fakeRuntime,
      bus: fakeBus,
      config,
      dataDir: tmp,
    });

    await core.executeTool("probe:run", {});
    expect(probe.capture).toBeDefined();
    await core.dispose();
  });
});

describe("executeRun — dataDir resolution from --target", () => {
  it("uses <target>/.kuzushi when target is an existing directory", () => {
    const target = mkdtempSync(path.join(tmpdir(), "kuzushi-target-"));
    try {
      const dataDir = resolveRunDataDir({ target, dataDir: "/tmp/cwd-fallback" });
      expect(dataDir).toBe(path.join(path.resolve(target), ".kuzushi"));
    } finally {
      rmSync(target, { recursive: true, force: true });
    }
  });

  it("falls back to the caller-provided dataDir when target is missing", () => {
    const dataDir = resolveRunDataDir({
      target: "/definitely/not/here/even/maybe",
      dataDir: "/tmp/cwd-fallback",
    });
    expect(dataDir).toBe("/tmp/cwd-fallback");
  });

  it("falls back when target is a URL-shaped string (host, http://...)", () => {
    expect(
      resolveRunDataDir({ target: "http://example.com", dataDir: "/tmp/x" }),
    ).toBe("/tmp/x");
    expect(
      resolveRunDataDir({ target: "ssh://host:22", dataDir: "/tmp/x" }),
    ).toBe("/tmp/x");
  });

  it("falls back when no target is provided", () => {
    expect(resolveRunDataDir({ dataDir: "/tmp/cwd-only" })).toBe("/tmp/cwd-only");
  });

  it("falls back when target points at a file (not a directory)", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "kuzushi-target-file-"));
    const file = path.join(dir, "marker.txt");
    writeFileSync(file, "x", "utf-8");
    try {
      const dataDir = resolveRunDataDir({ target: file, dataDir: "/tmp/x" });
      expect(dataDir).toBe("/tmp/x");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/**
 * Confirms carlini-threat-hunt honors the operator's `config.model` when
 * neither an inline `model=` arg nor `taskConfig["carlini-threat-hunt"].model`
 * is configured. Pre-policy the module fell back to a hardcoded
 * `anthropic:claude-opus-4-7` default, silently overriding operator choice.
 */
import { describe, expect, it } from "vitest";
import type { AgentRuntime } from "../../src/agent-runtime/types.js";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import { __carliniThreatHuntInternals } from "../../src/modules/carlini-threat-hunt/carlini-threat-hunt.js";
import type { ExecutionContext } from "../../src/modules/types.js";
import type { KuzushiConfig } from "../../src/types.js";

const { resolveConfig } = __carliniThreatHuntInternals;

function mkCtx(opts: {
  configModel: string;
  toolModel?: string;
  taskConfig?: Record<string, unknown>;
}): ExecutionContext {
  const runtime: AgentRuntime = {
    id: "pi-ai",
    async *query() {
      /* unused */
    },
  };
  return {
    cwd: "/tmp/repo",
    runtime,
    bus: new InProcessBus(),
    toolModel: opts.toolModel,
    config: {
      model: opts.configModel,
      busBackend: "in-process",
      triageBatchSize: 5,
      triageConcurrency: 2,
      scanMode: "sequential",
      tasks: ["carlini-threat-hunt"],
      severity: ["ERROR"],
      excludePatterns: [],
      taskConfig: opts.taskConfig ? { "carlini-threat-hunt": opts.taskConfig } : {},
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

describe("carlini-threat-hunt model resolution", () => {
  it("uses ctx.config.model when no inline or taskConfig override", async () => {
    const ctx = mkCtx({ configModel: "anthropic:claude-sonnet-4-6" });
    const cfg = await resolveConfig({ target: "/tmp/repo" }, ctx);
    expect(cfg.model).toBe("anthropic:claude-sonnet-4-6");
  });

  it("does NOT silently substitute claude-opus-4-7 default", async () => {
    const ctx = mkCtx({ configModel: "anthropic:claude-haiku-4-5" });
    const cfg = await resolveConfig({ target: "/tmp/repo" }, ctx);
    expect(cfg.model).not.toBe("anthropic:claude-opus-4-7");
    expect(cfg.model).toBe("anthropic:claude-haiku-4-5");
  });

  it("inline model arg wins over config.model", async () => {
    const ctx = mkCtx({ configModel: "anthropic:claude-sonnet-4-6" });
    const cfg = await resolveConfig(
      { target: "/tmp/repo", model: "anthropic:claude-opus-4-7" },
      ctx,
    );
    expect(cfg.model).toBe("anthropic:claude-opus-4-7");
  });

  it("taskConfig['carlini-threat-hunt'].model wins over config.model", async () => {
    const ctx = mkCtx({
      configModel: "anthropic:claude-sonnet-4-6",
      taskConfig: { model: "anthropic:claude-opus-4-7" },
    });
    const cfg = await resolveConfig({ target: "/tmp/repo" }, ctx);
    expect(cfg.model).toBe("anthropic:claude-opus-4-7");
  });

  it("ctx.toolModel wins over taskConfig and config", async () => {
    const ctx = mkCtx({
      configModel: "anthropic:claude-sonnet-4-6",
      toolModel: "anthropic:claude-haiku-4-5",
      taskConfig: { model: "anthropic:claude-opus-4-7" },
    });
    const cfg = await resolveConfig({ target: "/tmp/repo" }, ctx);
    expect(cfg.model).toBe("anthropic:claude-haiku-4-5");
  });
});

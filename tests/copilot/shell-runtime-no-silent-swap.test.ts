/**
 * Confirms the shell does NOT silently swap a custom/incompatible runtime
 * for the Claude SDK runtime when sessions aren't available. The previous
 * behavior (banner + in-process mutation) violated the project's
 * "no silent runtime swap" policy. The new behavior is a hard error so
 * the operator must explicitly choose a compatible backend.
 */
import { describe, expect, it } from "vitest";
import { KuzushiSilentFallbackError } from "../../src/agent-runtime/enforcement.js";
import type { AgentRuntime } from "../../src/agent-runtime/types.js";
import { __shellInternals } from "../../src/copilot/shell.js";
import type { KuzushiConfig } from "../../src/types.js";

const ensureClaudeShellRuntime = __shellInternals.ensureClaudeShellRuntime as unknown as (
  opts: { config: KuzushiConfig; runtime: AgentRuntime },
  store?: unknown,
) => Promise<void>;

function makeConfig(overrides: Partial<KuzushiConfig> = {}): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: {},
    agentRuntimeBackend: "pi-ai",
    ...overrides,
  };
}

/** A bare-bones runtime without `createSession` — mimics a custom plugin runtime. */
class SessionlessRuntime implements AgentRuntime {
  readonly id = "sessionless";
  async *query(): AsyncIterable<never> {
    /* noop */
  }
}

class ClaudeLikeRuntime implements AgentRuntime {
  readonly id = "claude";
  async *query(): AsyncIterable<never> {
    /* noop */
  }
  // Stub createSession so it satisfies the interface — we just need typeof === "function".
  createSession() {
    return {
      query: async function* () {
        /* noop */
      },
      close: async () => {},
    };
  }
}

describe("ensureClaudeShellRuntime — no silent swap", () => {
  it("throws KuzushiSilentFallbackError when runtime lacks createSession", async () => {
    const opts = {
      config: makeConfig({ agentRuntimeBackend: "pi-ai" }),
      runtime: new SessionlessRuntime() as unknown as AgentRuntime,
    };

    await expect(ensureClaudeShellRuntime(opts)).rejects.toBeInstanceOf(KuzushiSilentFallbackError);
  });

  it("does not mutate opts.config.agentRuntimeBackend on rejection", async () => {
    const opts = {
      config: makeConfig({ agentRuntimeBackend: "pi-ai" }),
      runtime: new SessionlessRuntime() as unknown as AgentRuntime,
    };

    await expect(ensureClaudeShellRuntime(opts)).rejects.toThrow();
    expect(opts.config.agentRuntimeBackend).toBe("pi-ai");
  });

  it("does not replace opts.runtime on rejection", async () => {
    const original = new SessionlessRuntime() as unknown as AgentRuntime;
    const opts = {
      config: makeConfig({ agentRuntimeBackend: "pi-ai" }),
      runtime: original,
    };

    await expect(ensureClaudeShellRuntime(opts)).rejects.toThrow();
    expect(opts.runtime).toBe(original);
  });

  it("error message points at /backend remedy", async () => {
    const opts = {
      config: makeConfig({ agentRuntimeBackend: "pi-ai" }),
      runtime: new SessionlessRuntime() as unknown as AgentRuntime,
    };

    try {
      await ensureClaudeShellRuntime(opts);
      throw new Error("expected to throw");
    } catch (err) {
      expect((err as Error).message).toMatch(/\/backend claude/);
      expect((err as Error).message).toMatch(/will not silently switch/);
    }
  });

  it("is a no-op when runtime already supports sessions", async () => {
    const opts = {
      config: makeConfig({ agentRuntimeBackend: "claude" }),
      runtime: new ClaudeLikeRuntime() as unknown as AgentRuntime,
    };

    // Should resolve without throwing or mutating anything.
    const before = opts.runtime;
    await expect(ensureClaudeShellRuntime(opts)).resolves.toBeUndefined();
    expect(opts.runtime).toBe(before);
    expect(opts.config.agentRuntimeBackend).toBe("claude");
  });
});

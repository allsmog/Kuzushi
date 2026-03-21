import { afterEach, describe, expect, it } from "vitest";
import {
  configureAgentRuntime,
  getAgentRuntime,
  setAgentRuntime,
} from "../../src/agent-runtime/index.js";
import type { AgentRuntime } from "../../src/agent-runtime/types.js";
import type { KuzushiConfig } from "../../src/types.js";
import {
  DEFAULT_READ_ONLY_TOOLS,
  resolveDefaultReadOnlyTools,
  SEMANTIC_NAVIGATION_TOOLS,
} from "../../src/agent-runtime/execution.js";

function makeConfig(overrides: Partial<KuzushiConfig> = {}): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    triageMaxTurns: 10,
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    scanners: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    scannerConfig: { semgrep: {} },
    ...overrides,
  };
}

describe("agent runtime", () => {
  afterEach(() => {
    configureAgentRuntime(makeConfig({
      agentRuntimeBackend: "pi-ai",
    }));
  });

  it("configures pi-ai backend (default)", () => {
    const runtime = configureAgentRuntime(makeConfig({
      agentRuntimeBackend: "pi-ai",
    }));
    expect(runtime.id).toBe("pi-ai");
    expect(getAgentRuntime().id).toBe("pi-ai");
  });

  it("throws for acp backend when adapter command is missing", () => {
    expect(() => configureAgentRuntime(makeConfig({
      agentRuntimeBackend: "acp",
    }))).toThrow("agentRuntimeBackend=acp requires acpAdapterCommand");
  });

  it("configures acp backend with adapter command", () => {
    const runtime = configureAgentRuntime(makeConfig({
      agentRuntimeBackend: "acp",
      acpAdapterCommand: "echo test",
    }));
    expect(runtime.id).toBe("acp");
  });

  it("allows tests/extensions to inject a custom runtime", () => {
    const custom: AgentRuntime = {
      id: "custom-test",
      async *query() {
        yield {
          type: "result",
          subtype: "success",
          result: "{\"ok\":true}",
        };
      },
    };

    setAgentRuntime(custom);
    expect(getAgentRuntime().id).toBe("custom-test");
  });

  it("includes semantic navigation tools for pi-ai defaults", () => {
    expect(resolveDefaultReadOnlyTools({ id: "pi-ai" } as AgentRuntime)).toEqual([
      ...DEFAULT_READ_ONLY_TOOLS,
      ...SEMANTIC_NAVIGATION_TOOLS,
    ]);
  });

  it("keeps the legacy default bundle for acp and custom runtimes", () => {
    expect(resolveDefaultReadOnlyTools({ id: "acp" } as AgentRuntime)).toEqual([
      ...DEFAULT_READ_ONLY_TOOLS,
    ]);
    expect(resolveDefaultReadOnlyTools({ id: "custom-test" } as AgentRuntime)).toEqual([
      ...DEFAULT_READ_ONLY_TOOLS,
    ]);
  });
});

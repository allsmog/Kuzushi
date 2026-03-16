import { afterEach, describe, expect, it } from "vitest";
import {
  configureAgentRuntime,
  getAgentRuntime,
  setAgentRuntime,
} from "../../src/agent-runtime/index.js";
import type { AgentRuntime } from "../../src/agent-runtime/types.js";
import type { KuzushiConfig } from "../../src/types.js";

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
});

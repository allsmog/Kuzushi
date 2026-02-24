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
    model: "claude-sonnet-4-20250514",
    triageMaxTurns: 10,
    busBackend: "in-process",
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
      agentRuntimeBackend: "claude-sdk",
    }));
  });

  it("configures claude-sdk backend", () => {
    const runtime = configureAgentRuntime(makeConfig({
      agentRuntimeBackend: "claude-sdk",
    }));
    expect(runtime.id).toBe("claude-sdk");
    expect(getAgentRuntime().id).toBe("claude-sdk");
  });

  it("throws for acp backend until adapter is implemented", () => {
    expect(() => configureAgentRuntime(makeConfig({
      agentRuntimeBackend: "acp",
    }))).toThrow("agentRuntimeBackend=acp is not available yet");
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

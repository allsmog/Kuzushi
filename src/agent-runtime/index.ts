import type { KuzushiConfig } from "../types.js";
import { PiAiAgentRuntime } from "./pi-ai.js";
import { ClaudeAgentRuntime } from "./claude.js";
import { getLogger } from "../logger.js";
import type { AgentRuntime } from "./types.js";

const log = getLogger("agent-runtime");

export function configureAgentRuntime(config: KuzushiConfig): AgentRuntime {
  return createAgentRuntimeInstance(config);
}

export function createAgentRuntimeInstance(config: KuzushiConfig): AgentRuntime {
  const runtimeConfig = config.agentRuntimeConfig;
  const backend = config.agentRuntimeBackend ?? "claude";

  if (backend === "pi-ai") {
    log.info(`Using pi-ai runtime${runtimeConfig?.baseUrl ? ` (baseUrl=${runtimeConfig.baseUrl})` : ""}`);
    return new PiAiAgentRuntime(runtimeConfig);
  }

  log.info(`Using Claude Agent SDK runtime${runtimeConfig?.baseUrl ? ` (baseUrl=${runtimeConfig.baseUrl})` : ""}`);
  return new ClaudeAgentRuntime(runtimeConfig);
}

export * from "./types.js";
export { PiAiAgentRuntime, ClaudeAgentRuntime };

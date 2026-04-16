import { getLogger } from "../logger.js";
import type { KuzushiConfig } from "../types.js";
import { ClaudeAgentRuntime } from "./claude.js";
import { LoggingAgentRuntime } from "./logging-runtime.js";
import { PiAiAgentRuntime } from "./pi-ai.js";
import type { AgentRuntime } from "./types.js";

const log = getLogger("agent-runtime");

export function configureAgentRuntime(config: KuzushiConfig): AgentRuntime {
  return createAgentRuntimeInstance(config);
}

export function createAgentRuntimeInstance(config: KuzushiConfig): AgentRuntime {
  const runtimeConfig = config.agentRuntimeConfig;
  const backend = config.agentRuntimeBackend ?? "claude";

  let runtime: AgentRuntime;
  if (backend === "pi-ai") {
    log.info(
      `Using pi-ai runtime${runtimeConfig?.baseUrl ? ` (baseUrl=${runtimeConfig.baseUrl})` : ""}`,
    );
    runtime = new PiAiAgentRuntime(runtimeConfig);
  } else {
    log.info(
      `Using Claude Agent SDK runtime${runtimeConfig?.baseUrl ? ` (baseUrl=${runtimeConfig.baseUrl})` : ""}`,
    );
    runtime = new ClaudeAgentRuntime(runtimeConfig);
  }

  return new LoggingAgentRuntime(runtime);
}

export * from "./types.js";
export { ClaudeAgentRuntime, PiAiAgentRuntime };

import type { KuzushiConfig } from "../types.js";
import { ClaudeSdkAgentRuntime } from "./claude.js";
import type { AgentRuntime } from "./types.js";

const DEFAULT_BACKEND = "claude-sdk";

let currentRuntime: AgentRuntime = new ClaudeSdkAgentRuntime();

export function getAgentRuntime(): AgentRuntime {
  return currentRuntime;
}

export function setAgentRuntime(runtime: AgentRuntime): void {
  currentRuntime = runtime;
}

export function configureAgentRuntime(config: KuzushiConfig): AgentRuntime {
  const backend = config.agentRuntimeBackend ?? DEFAULT_BACKEND;

  if (backend === "claude-sdk") {
    currentRuntime = new ClaudeSdkAgentRuntime();
    return currentRuntime;
  }

  if (backend === "acp") {
    throw new Error(
      "agentRuntimeBackend=acp is not available yet. "
      + "Use agentRuntimeBackend=claude-sdk until ACP runtime adapter is implemented.",
    );
  }

  throw new Error(
    `Unknown agent runtime backend: ${String(backend)}. `
    + "Expected one of: claude-sdk, acp.",
  );
}

export * from "./types.js";
export { ClaudeSdkAgentRuntime };

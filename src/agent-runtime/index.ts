import type { KuzushiConfig } from "../types.js";
import { PiAiAgentRuntime } from "./pi-ai.js";
import type { AgentRuntime } from "./types.js";

let currentRuntime: AgentRuntime = new PiAiAgentRuntime();

export function getAgentRuntime(): AgentRuntime {
  return currentRuntime;
}

export function setAgentRuntime(runtime: AgentRuntime): void {
  currentRuntime = runtime;
}

export function configureAgentRuntime(config: KuzushiConfig): AgentRuntime {
  const backend = config.agentRuntimeBackend ?? "pi-ai";
  const runtimeConfig = config.agentRuntimeConfig;

  if (backend === "pi-ai") {
    currentRuntime = new PiAiAgentRuntime(runtimeConfig);
    return currentRuntime;
  }

  if (backend === "acp") {
    throw new Error(
      "agentRuntimeBackend=acp is not available yet. "
      + "Use agentRuntimeBackend=pi-ai until ACP runtime adapter is implemented.",
    );
  }

  throw new Error(
    `Unknown agent runtime backend: ${String(backend)}. `
    + "Expected one of: pi-ai, acp.",
  );
}

export * from "./types.js";
export { PiAiAgentRuntime };

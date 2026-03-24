import type { KuzushiConfig } from "../types.js";
import { PiAiAgentRuntime } from "./pi-ai.js";
import { AcpAgentRuntime } from "./acp.js";
import type { AgentRuntime } from "./types.js";

export function configureAgentRuntime(config: KuzushiConfig): AgentRuntime {
  return createAgentRuntimeInstance(config);
}

export function createAgentRuntimeInstance(config: KuzushiConfig): AgentRuntime {
  const backend = config.agentRuntimeBackend ?? "pi-ai";
  const runtimeConfig = config.agentRuntimeConfig;

  if (backend === "pi-ai") {
    return new PiAiAgentRuntime(runtimeConfig);
  }

  if (backend === "acp") {
    const adapterCommand = config.acpAdapterCommand;
    if (!adapterCommand) {
      throw new Error(
        "agentRuntimeBackend=acp requires acpAdapterCommand to be set. "
        + "Set it in config or pass --acp-adapter-command.",
      );
    }
    return new AcpAgentRuntime(adapterCommand, runtimeConfig);
  }

  throw new Error(
    `Unknown agent runtime backend: ${String(backend)}. `
    + "Expected one of: pi-ai, acp.",
  );
}

export * from "./types.js";
export { PiAiAgentRuntime };
export { AcpAgentRuntime };

import { resolveActiveCredentials } from "../config.js";
import { getLogger } from "../logger.js";
import type { KuzushiConfig } from "../types.js";
import { LoggingAgentRuntime } from "./logging-runtime.js";
import { PiAiAgentRuntime } from "./pi-ai.js";
import type { AgentRuntime } from "./types.js";

const log = getLogger("agent-runtime");

export function configureAgentRuntime(config: KuzushiConfig): AgentRuntime {
  return createAgentRuntimeInstance(config);
}

export function createAgentRuntimeInstance(config: KuzushiConfig): AgentRuntime {
  const creds = resolveActiveCredentials(config);
  const hasCreds = Object.keys(creds).length > 0 ? creds : undefined;
  log.info(`Using pi-ai runtime${creds.baseUrl ? ` (baseUrl=${creds.baseUrl})` : ""}`);
  return new LoggingAgentRuntime(new PiAiAgentRuntime(hasCreds));
}

export * from "./types.js";
export { PiAiAgentRuntime };

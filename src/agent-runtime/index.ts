import { resolveActiveCredentials } from "../config.js";
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
  const backend = config.agentRuntimeBackend ?? "pi-ai";
  // Pull only the active backend's slot — the other slot must not leak into
  // this runtime. Before the per-backend split a single shared bag caused
  // pi-ai creds to poison the claude runtime and vice-versa.
  const creds = resolveActiveCredentials(config);
  const hasCreds = Object.keys(creds).length > 0 ? creds : undefined;

  let runtime: AgentRuntime;
  if (backend === "pi-ai") {
    log.info(`Using pi-ai runtime${creds.baseUrl ? ` (baseUrl=${creds.baseUrl})` : ""}`);
    runtime = new PiAiAgentRuntime(hasCreds);
  } else {
    log.info(`Using Claude Agent SDK runtime${creds.baseUrl ? ` (baseUrl=${creds.baseUrl})` : ""}`);
    runtime = new ClaudeAgentRuntime(hasCreds);
  }

  return new LoggingAgentRuntime(runtime);
}

export * from "./types.js";
export { ClaudeAgentRuntime, PiAiAgentRuntime };

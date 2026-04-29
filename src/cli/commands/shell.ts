import { existsSync } from "node:fs";
import { configureAgentRuntime } from "../../agent-runtime/index.js";
import { AGENT_RUNTIME_BACKENDS } from "../../config/defaults.js";
import {
  applyConfigPatch,
  isClaudeCodeHostManagedAuth,
  loadConfig,
  loadLocalCredentials,
  providerBaseUrlEnvVar,
  providerEnvVar,
  resolveActiveCredentials,
  resolveAmbientOauthToken,
} from "../../config.js";
import { getLogger } from "../../logger.js";
import type { AgentRuntimeConfig, KuzushiConfig } from "../../types.js";
import { CliUsageError } from "../errors.js";

export interface ShellCommandOptions {
  workspace?: string;
  load?: string;
  exclude?: string;
  target?: string;
  scope?: string;
  model?: string;
  agentRuntime?: string;
  apiKey?: string;
  inheritClaude?: boolean;
}

export async function runShellCommand(opts: ShellCommandOptions): Promise<void> {
  const { startShell } = await import("../../copilot/shell.js");
  const config = loadConfig();

  applyShellOptionOverrides(config, opts);
  applyLocalCredentials(config, opts.target);
  primeCredentialEnvironment(config, opts.apiKey);
  await primeInheritedAnthropicToken(config);

  await startShell({
    config,
    runtime: configureAgentRuntime(config),
    workspace: opts.workspace,
    modules: commaSeparatedList(opts.load),
    excludeBuiltinModules: commaSeparatedList(opts.exclude),
    target: opts.target,
  });
}

function applyShellOptionOverrides(config: KuzushiConfig, opts: ShellCommandOptions): void {
  if (opts.model) config.model = opts.model;
  if (opts.agentRuntime) setAgentRuntimeBackend(config, opts.agentRuntime);
  validateShellTarget(opts.target);
  if (opts.inheritClaude) applyInheritedClaudeAuth(config);
}

function setAgentRuntimeBackend(config: KuzushiConfig, backend: string): void {
  if (!AGENT_RUNTIME_BACKENDS.has(backend)) {
    throw new CliUsageError(
      `Invalid --agent-runtime "${backend}". Valid values: ${[...AGENT_RUNTIME_BACKENDS].join(", ")}`,
    );
  }
  config.agentRuntimeBackend = backend as typeof config.agentRuntimeBackend;
}

function validateShellTarget(target: string | undefined): void {
  if (!target || isUrlLikeTarget(target) || existsSync(target)) return;
  throw new CliUsageError(
    `--target path not found: ${target}\n` +
      "  Pass an existing repo path, a URL (https://...), or a host:port.",
  );
}

function isUrlLikeTarget(target: string): boolean {
  return /^[a-z][a-z0-9+.-]*:/i.test(target);
}

function applyInheritedClaudeAuth(config: KuzushiConfig): void {
  config.auth = "inherited";
  config.agentRuntimeBackend = "claude";
  tryPersistInheritedClaude();
}

function tryPersistInheritedClaude(): void {
  try {
    applyConfigPatch([
      { path: "agentRuntimeBackend", value: "claude" },
      { path: "auth", value: "inherited" },
    ]);
  } catch {
    return;
  }
}

function applyLocalCredentials(config: KuzushiConfig, target: string | undefined): void {
  const localCredentials = loadLocalCredentials(target ?? process.cwd());
  if (!localCredentials) return;
  config.agentRuntimeConfig = mergeCredentialSlots(config.agentRuntimeConfig, localCredentials);
}

function mergeCredentialSlots(
  existing: AgentRuntimeConfig | undefined,
  localCredentials: AgentRuntimeConfig,
): AgentRuntimeConfig {
  return removeEmptyCredentialSlots({
    claude: { ...(existing?.claude ?? {}), ...(localCredentials.claude ?? {}) },
    piAi: { ...(existing?.piAi ?? {}), ...(localCredentials.piAi ?? {}) },
    codex: { ...(existing?.codex ?? {}), ...(localCredentials.codex ?? {}) },
  });
}

function removeEmptyCredentialSlots(config: AgentRuntimeConfig): AgentRuntimeConfig {
  for (const slot of ["claude", "piAi", "codex"] as const) {
    if (config[slot] && Object.keys(config[slot]).length === 0) delete config[slot];
  }
  return config;
}

function primeCredentialEnvironment(
  config: KuzushiConfig,
  apiKeyOverride: string | undefined,
): void {
  primeActiveCredentialEnvironment(config);
  if (apiKeyOverride) primeApiKeyOverride(config, apiKeyOverride);
}

function primeActiveCredentialEnvironment(config: KuzushiConfig): void {
  const activeCredentials = resolveActiveCredentials(config);
  const activeProvider = config.agentRuntimeBackend === "codex" ? "openai" : "anthropic";
  const apiKeyEnv = providerEnvVar(activeProvider);
  const baseUrlEnv = providerBaseUrlEnvVar(activeProvider);
  if (activeCredentials.apiKey && apiKeyEnv) process.env[apiKeyEnv] = activeCredentials.apiKey;
  if (activeCredentials.baseUrl && baseUrlEnv) {
    process.env[baseUrlEnv] = activeCredentials.baseUrl;
  }
}

function primeApiKeyOverride(config: KuzushiConfig, apiKey: string): void {
  const envName = config.agentRuntimeBackend === "codex" ? "OPENAI_API_KEY" : "ANTHROPIC_API_KEY";
  process.env[envName] = apiKey;
}

async function primeInheritedAnthropicToken(config: KuzushiConfig): Promise<void> {
  if (!shouldLoadInheritedAnthropicToken(config)) return;
  const ambient = resolveAmbientOauthToken(config);
  if (!ambient) return;
  process.env.ANTHROPIC_API_KEY = ambient.token;
  getLogger("kuzushi").info(`Using inherited OAuth token (source: ${ambient.source})`);
}

function shouldLoadInheritedAnthropicToken(config: KuzushiConfig): boolean {
  return (
    config.auth === "inherited" && !process.env.ANTHROPIC_API_KEY && !isClaudeCodeHostManagedAuth()
  );
}

function commaSeparatedList(value: string | undefined): string[] | undefined {
  return value
    ?.split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

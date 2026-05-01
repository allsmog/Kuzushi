import { existsSync } from "node:fs";
import { configureAgentRuntime } from "../../agent-runtime/index.js";
import { parsePiAiModelSpec } from "../../agent-runtime/model-spec.js";
import {
  loadConfig,
  loadLocalCredentials,
  providerBaseUrlEnvVar,
  providerEnvVar,
  resolveActiveCredentials,
} from "../../config.js";
import type { KuzushiConfig } from "../../types.js";
import { CliUsageError } from "../errors.js";

export interface ShellCommandOptions {
  workspace?: string;
  load?: string;
  exclude?: string;
  target?: string;
  scope?: string;
  model?: string;
  effort?: string;
  taskConfig?: string[];
  apiKey?: string;
  authToken?: string;
}

export async function runShellCommand(opts: ShellCommandOptions): Promise<void> {
  const { startShell } = await import("../../copilot/shell.js");
  const config = loadConfig();

  applyShellOptionOverrides(config, opts);
  applyLocalCredentials(config, opts.target);
  primeCredentialEnvironment(config, opts.apiKey, opts.authToken);

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
  applyDefaultEffort(config, opts.effort);
  applyTaskConfigOverrides(config, opts.taskConfig ?? []);
  validateShellTarget(opts.target);
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

function applyDefaultEffort(config: KuzushiConfig, effort: string | undefined): void {
  if (!effort) return;
  if (!["low", "medium", "high", "xhigh"].includes(effort)) {
    throw new CliUsageError(
      `Invalid --effort "${effort}". Valid values: low, medium, high, xhigh.`,
    );
  }
  for (const taskId of Object.keys(config.taskConfig)) {
    config.taskConfig[taskId] = {
      ...config.taskConfig[taskId],
      effort,
    };
  }
}

function applyTaskConfigOverrides(config: KuzushiConfig, assignments: string[]): void {
  for (const assignment of assignments) {
    const parsed = parseTaskConfigAssignment(assignment);
    config.taskConfig[parsed.taskId] = {
      ...(config.taskConfig[parsed.taskId] ?? {}),
      [parsed.key]: parsed.value,
    };
  }
}

function parseTaskConfigAssignment(assignment: string): {
  taskId: string;
  key: string;
  value: unknown;
} {
  const equalsIndex = assignment.indexOf("=");
  if (equalsIndex <= 0 || equalsIndex === assignment.length - 1) {
    throw invalidTaskConfigAssignment(assignment);
  }
  const lhs = assignment.slice(0, equalsIndex).trim();
  const value = parseTaskConfigValue(assignment.slice(equalsIndex + 1).trim());
  const dotIndex = lhs.lastIndexOf(".");
  if (dotIndex <= 0 || dotIndex === lhs.length - 1) {
    throw invalidTaskConfigAssignment(assignment);
  }
  const taskId = lhs.slice(0, dotIndex).trim();
  const key = lhs.slice(dotIndex + 1).trim();
  if (!taskId || !key) throw invalidTaskConfigAssignment(assignment);
  return { taskId, key, value };
}

function parseTaskConfigValue(value: string): unknown {
  if (value === "true") return true;
  if (value === "false") return false;
  if (/^-?\d+(\.\d+)?$/.test(value)) return Number(value);
  return value;
}

function invalidTaskConfigAssignment(assignment: string): CliUsageError {
  return new CliUsageError(
    `--task-config must be in the form <taskId.key=value>; received "${assignment}".`,
  );
}

function applyLocalCredentials(config: KuzushiConfig, target: string | undefined): void {
  const localCredentials = loadLocalCredentials(target ?? process.cwd());
  if (!localCredentials) return;
  config.agentRuntimeConfig = { ...(config.agentRuntimeConfig ?? {}), ...localCredentials };
}

function primeCredentialEnvironment(
  config: KuzushiConfig,
  apiKeyOverride: string | undefined,
  authTokenOverride: string | undefined,
): void {
  primeActiveCredentialEnvironment(config);
  if (apiKeyOverride) primeApiKeyOverride(config, apiKeyOverride);
  if (authTokenOverride) primeAuthTokenOverride(authTokenOverride);
}

function primeActiveCredentialEnvironment(config: KuzushiConfig): void {
  const activeCredentials = resolveActiveCredentials(config);
  const activeProvider = providerFromModel(config.model);
  const apiKeyEnv = activeProvider ? providerEnvVar(activeProvider) : undefined;
  const baseUrlEnv = activeProvider ? providerBaseUrlEnvVar(activeProvider) : undefined;
  if (activeCredentials.apiKey && apiKeyEnv) process.env[apiKeyEnv] = activeCredentials.apiKey;
  if (activeProvider === "anthropic" && activeCredentials.authToken) {
    process.env.ANTHROPIC_AUTH_TOKEN = activeCredentials.authToken;
    process.env.ANTHROPIC_OAUTH_TOKEN = activeCredentials.authToken;
  }
  if (activeCredentials.baseUrl && baseUrlEnv) {
    process.env[baseUrlEnv] = activeCredentials.baseUrl;
  }
}

function primeApiKeyOverride(config: KuzushiConfig, apiKey: string): void {
  const provider = providerFromModel(config.model);
  const envName = provider ? providerEnvVar(provider) : undefined;
  if (envName) process.env[envName] = apiKey;
}

function primeAuthTokenOverride(authToken: string): void {
  process.env.ANTHROPIC_AUTH_TOKEN = authToken;
  process.env.ANTHROPIC_OAUTH_TOKEN = authToken;
}

function providerFromModel(model: string | undefined): string | undefined {
  if (!model) return undefined;
  try {
    return parsePiAiModelSpec(model).provider;
  } catch {
    return undefined;
  }
}

function commaSeparatedList(value: string | undefined): string[] | undefined {
  return value
    ?.split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

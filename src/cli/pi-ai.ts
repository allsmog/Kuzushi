import { parsePiAiModelSpec } from "../agent-runtime/model-spec.js";
import { resolveStageModel } from "../agents/tasks/runtime-overrides.js";
import { resolveTaskConfig, TAINT_ANALYSIS_TASK_IDS } from "../capabilities.js";
import type { KuzushiConfig } from "../types.js";

const DEFAULT_AGENTIC_MODEL = "anthropic:claude-sonnet-4-6";

function requiredEnvVarsForProvider(provider: string): string[] {
  if (provider === "anthropic") {
    return ["ANTHROPIC_API_KEY", "ANTHROPIC_OAUTH_TOKEN"];
  }

  if (provider === "openai") {
    return ["OPENAI_API_KEY"];
  }

  if (provider === "google") {
    return ["GEMINI_API_KEY", "GOOGLE_API_KEY"];
  }

  return [];
}

function maybeWarnPiAiApiKeyForModel(
  model: string | undefined,
  options: { anthropicApiKey?: string } = {},
): void {
  if (!model) {
    return;
  }

  let provider: string;
  try {
    provider = parsePiAiModelSpec(model).provider;
  } catch {
    return;
  }

  const envVars = requiredEnvVarsForProvider(provider);
  if (envVars.length === 0) {
    return;
  }

  const hasAny = envVars.some((name) => Boolean(process.env[name]))
    || (provider === "anthropic" && Boolean(options.anthropicApiKey));
  if (hasAny) {
    return;
  }

  console.warn(
    `Warning: model "${model}" uses provider "${provider}", `
    + `but none of [${envVars.join(", ")}] are set.`,
  );
}

export function warnPiAiBackendApiKeys(
  models: string[],
  options: { anthropicApiKey?: string } = {},
): void {
  for (const model of models) {
    maybeWarnPiAiApiKeyForModel(model, options);
  }
}

export function resolveActivePiAiModels(
  config: KuzushiConfig,
  selectedTasks: string[],
  enabledTaskIds: string[],
): string[] {
  const models = new Set<string>();
  const enabledTaskSet = new Set([...selectedTasks, ...enabledTaskIds]);

  models.add(resolveStageModel(config, "triage"));
  models.add(resolveStageModel(config, "triage-batch", "triage"));
  models.add(resolveStageModel(config, "triage-specialist", "triage"));

  if (config.verify === true) {
    models.add(resolveStageModel(config, "verify"));
    models.add(resolveStageModel(config, "verify-batch", "verify"));
    if (config.verifyGateEnabled !== false) {
      models.add(resolveStageModel(config, "verify-gate", "verify"));
    }
  }

  if (config.pocHarness === true) {
    models.add(resolveStageModel(config, "poc-harness", "verify"));
  }

  if (config.dynamicAnalysisEnabled === true) {
    models.add(resolveStageModel(config, "dynamic-analysis", "poc-harness", "verify"));
  }

  if (config.variantAnalysis === true) {
    models.add(resolveStageModel(config, "variant-analysis"));
  }

  if (config.chainAnalysis === true) {
    models.add(resolveStageModel(config, "chain-analysis"));
  }

  if (config.llmRescoreEnabled === true) {
    models.add(resolveStageModel(config, "llm-rescore"));
  }

  if (config.autoPatchEnabled === true) {
    models.add(resolveStageModel(config, "patch"));
  }

  for (const model of config.ensembleModels ?? []) {
    const trimmed = model.trim();
    if (trimmed) {
      models.add(trimmed);
    }
  }

  for (const taskId of enabledTaskSet) {
    const model = asModel(resolveTaskConfig(config, taskId)["model"]);
    if (model) {
      models.add(model);
    }
  }

  if (enabledTaskSet.has("agentic")) {
    const model = asModel(resolveTaskConfig(config, "agentic")["model"]) ?? DEFAULT_AGENTIC_MODEL;
    models.add(model);
  }

  const usesTaintAnalysis = TAINT_ANALYSIS_TASK_IDS.some((id) => enabledTaskSet.has(id));
  if (usesTaintAnalysis) {
    const taCfg = config.taskConfig["taint-analysis"];
    const labelingModel = asModel(taCfg?.["labelingModel"]) ?? config.model;
    const extractionModel = asModel(taCfg?.["extractionModel"]) ?? labelingModel;
    models.add(labelingModel);
    models.add(extractionModel);
  }

  for (const taskId of [
    "secrets-crypto-detect",
    "crypto-behavioral-test",
    "code-config-detect",
    "race-condition-detect",
  ]) {
    if (enabledTaskSet.has(taskId)) {
      const model = asModel(resolveTaskConfig(config, taskId)["model"]) ?? config.model;
      models.add(model);
    }
  }

  if (enabledTaskSet.has("invariant-extract") || enabledTaskSet.has("invariant-check")) {
    const iaCfg = resolveTaskConfig(config, "invariant-analysis");
    models.add(asModel(iaCfg?.["extractionModel"]) ?? config.model);
    models.add(asModel(iaCfg?.["checkModel"]) ?? config.model);
  }

  if (enabledTaskSet.has("threat-model-randori")) {
    const tmCfg = resolveTaskConfig(config, "threat-model");
    models.add(asModel(tmCfg?.["model"] ?? tmCfg?.["strideModel"]) ?? config.model);
  }

  return [...models];
}

export function validatePiAiProviderCredentials(
  models: string[],
  options: { anthropicApiKey?: string } = {},
): Array<{ provider: string; envVars: string[]; models: string[] }> {
  const missingByProvider = new Map<string, { envVars: string[]; models: Set<string> }>();

  for (const model of models) {
    let provider: string;
    try {
      provider = parsePiAiModelSpec(model).provider;
    } catch {
      continue;
    }

    const envVars = requiredEnvVarsForProvider(provider);
    if (envVars.length === 0) {
      continue;
    }

    const hasAny = envVars.some((name) => Boolean(process.env[name]))
      || (provider === "anthropic" && Boolean(options.anthropicApiKey));
    if (hasAny) {
      continue;
    }

    const entry = missingByProvider.get(provider) ?? { envVars, models: new Set<string>() };
    entry.models.add(model);
    missingByProvider.set(provider, entry);
  }

  return [...missingByProvider.entries()].map(([provider, entry]) => ({
    provider,
    envVars: entry.envVars,
    models: [...entry.models],
  }));
}

function asModel(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed || undefined;
}

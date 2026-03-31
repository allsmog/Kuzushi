import { parsePiAiModelSpec } from "../agent-runtime/model-spec.js";
import { resolveScannerConfig, TAINT_ANALYSIS_CROSS_SERVICE_TASK_IDS, TAINT_ANALYSIS_TASK_IDS } from "../capabilities.js";
import type { KuzushiConfig } from "../types.js";

const DEFAULT_AGENTIC_MODEL = "anthropic:claude-sonnet-4-6";

export function requiredEnvVarsForProvider(provider: string): string[] {
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

export function maybeWarnPiAiApiKeyForModel(
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
  selectedScanners: string[],
  enabledTaskIds: string[],
): string[] {
  const models = new Set<string>();
  const scannerSet = new Set(selectedScanners);
  const enabledTaskSet = new Set(enabledTaskIds);

  const triageModel = config.triageModel ?? config.model;
  models.add(triageModel);

  if (config.verify === true) {
    models.add(config.verifyModel ?? triageModel);
  }

  if (config.pocHarness === true) {
    models.add(
      config.pocHarnessModel
      ?? config.verifyModel
      ?? triageModel,
    );
  }

  for (const model of config.ensembleModels ?? []) {
    const trimmed = model.trim();
    if (trimmed) {
      models.add(trimmed);
    }
  }

  if (scannerSet.has("agentic")) {
    const model = asModel(resolveScannerConfig(config, "agentic")["model"]) ?? DEFAULT_AGENTIC_MODEL;
    models.add(model);
  }

  const usesTaintAnalysis = TAINT_ANALYSIS_TASK_IDS.some((id) => enabledTaskSet.has(id));
  const usesCrossService = TAINT_ANALYSIS_CROSS_SERVICE_TASK_IDS.some((id) => enabledTaskSet.has(id));
  if (usesTaintAnalysis || usesCrossService) {
    const taCfg = config.scannerConfig["taint-analysis"];
    const labelingModel = asModel(taCfg?.["labelingModel"]) ?? config.model;
    const extractionModel = asModel(taCfg?.["extractionModel"]) ?? labelingModel;
    models.add(labelingModel);
    models.add(extractionModel);

    if (usesCrossService) {
      const boundaryModel = asModel(taCfg?.["crossServiceBoundaryModel"]) ?? labelingModel;
      const stitchModel = asModel(taCfg?.["crossServiceStitchModel"]) ?? labelingModel;
      models.add(boundaryModel);
      models.add(stitchModel);
    }
  }

  for (const taskId of [
    "secrets-crypto-detect",
    "crypto-behavioral-test",
    "code-config-detect",
    "race-condition-detect",
  ]) {
    if (enabledTaskSet.has(taskId)) {
      const model = asModel(resolveScannerConfig(config, taskId)["model"]) ?? config.model;
      models.add(model);
    }
  }

  if (enabledTaskSet.has("invariant-extract") || enabledTaskSet.has("invariant-check")) {
    const iaCfg = resolveScannerConfig(config, "invariant-analysis");
    models.add(asModel(iaCfg?.["extractionModel"]) ?? config.model);
    models.add(asModel(iaCfg?.["checkModel"]) ?? config.model);
  }

  if (enabledTaskSet.has("threat-model-stride") || enabledTaskSet.has("threat-model-pasta")) {
    const tmCfg = resolveScannerConfig(config, "threat-model");
    models.add(asModel(tmCfg?.["strideModel"]) ?? config.model);
    models.add(asModel(tmCfg?.["pastaModel"]) ?? config.model);
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

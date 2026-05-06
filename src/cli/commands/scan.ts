import path from "node:path";
import { loadConfig } from "../../config.js";
import { looksLikeMonorepo } from "../../discovery/repo-discovery.js";
import { getGlobalLogLevel } from "../../logger.js";
import type { KuzushiConfig } from "../../types.js";
import { configureTerminalOutput, resetTerminalOutput } from "../../ui/output.js";
import { CliUsageError } from "../errors.js";
import { applyScanCommandConfigOverrides, type ScanCommandOptions } from "../scan-config.js";
import { resolveRepo } from "../shared.js";
import { getScanPlanSummary, prepareScanExecution, runPipeline } from "./scan-pipeline.js";

export {
  applyPipelineCacheOptions,
  createPipelineRuntime,
  getScanPlanSummary,
  prepareScanExecution,
  runPipeline,
} from "./scan-pipeline.js";

export type MonorepoExecutionReason =
  | "manual-modules"
  | "list-modules"
  | "cli-opt-out"
  | "config-modules"
  | "config-monorepo"
  | "auto-detected"
  | "single-root";

export interface MonorepoExecutionDecision {
  useMonorepo: boolean;
  reason: MonorepoExecutionReason;
}

export async function runScanCommand(repoPath: string, opts: ScanCommandOptions): Promise<void> {
  // Initialize the renderer before preflight so one session owns the entire run.
  // `--ci` swaps the Ink app for the machine-readable stream formatter.
  const { createUIRenderer } = await import("../../ui/render.js");
  const renderer = await createUIRenderer({ ci: Boolean(opts.ci) });
  const { store: uiStore, cleanup: cleanupUI } = renderer;
  configureTerminalOutput({
    store: uiStore,
    verbose: getGlobalLogLevel() === "debug",
    quiet: true,
  });

  const scanPath = path.resolve(repoPath);
  const { root: repoRoot, name: repoName, gitRoot } = resolveRepo(repoPath);
  uiStore.update({ repoName });

  // Make the narrowing visible when the operator targets a subdir of a
  // larger git repo — without this, side-effects like config loading
  // and DB paths silently switch to the git root.
  if (gitRoot && !opts.resume) {
    console.log(`Scope: ${repoRoot} (git repo: ${gitRoot})`);
  }

  // Interactive setup flow (skip for --resume)
  if (!opts.resume && process.stdout.isTTY) {
    const { isFirstRun, runSetupWizard, runConfigConfirmation } = await import("../../ui/setup.js");

    if (isFirstRun(repoRoot)) {
      // First-time user: show setup wizard
      const outcome = await runSetupWizard(uiStore, repoName, repoRoot);
      if (outcome.action === "cancel") {
        resetTerminalOutput();
        cleanupUI();
        return;
      }
      // Apply wizard selections as CLI overrides
      if (outcome.preset && !opts.preset) {
        opts.preset = outcome.preset;
      }
      if (outcome.model && !opts.model) {
        opts.model = outcome.model;
      }
    } else if (opts.confirmConfig === true) {
      // Returning user: only show config confirmation when explicitly requested.
      const resolvedConfig = loadConfig(repoRoot, {
        trustProjectConfig: opts.trustRepoConfig === true,
      });
      const outcome = await runConfigConfirmation(
        uiStore,
        {
          model: resolvedConfig.model,
          tasks: resolvedConfig.tasks,
          severity: resolvedConfig.severity,
          concurrency: resolvedConfig.triageConcurrency,
          verify: resolvedConfig.verify,
          pocHarness: resolvedConfig.pocHarness,
          budget: resolvedConfig.costBudgetUsd,
        },
        repoName,
        repoRoot,
      );
      if (outcome.action === "cancel") {
        resetTerminalOutput();
        cleanupUI();
        return;
      }
    }
  }

  // Operator context intake is opt-in so the default TTY scan path gets to value quickly.
  if (
    !opts.resume &&
    process.stdout.isTTY &&
    (opts.reviewContext === true || opts.reviewThreatModel === true)
  ) {
    const { loadOperatorScanContext } = await import("../../operator-context.js");
    const { loadPersistentThreatModel } = await import("../../threat-model-renderer.js");
    const { runContextIntake, runThreatModelEditor } = await import("../../ui/setup.js");

    const existingContext = loadOperatorScanContext(repoRoot);
    if (opts.reviewContext === true && existingContext) {
      const intakeOutcome = await runContextIntake(uiStore, existingContext, repoName, repoRoot);
      if (intakeOutcome.action === "cancel") {
        resetTerminalOutput();
        cleanupUI();
        return;
      }
    }

    const existingThreatModel = loadPersistentThreatModel(repoRoot);
    if (opts.reviewThreatModel === true && existingThreatModel) {
      const tmOutcome = await runThreatModelEditor(
        uiStore,
        existingThreatModel,
        repoName,
        repoRoot,
      );
      if (tmOutcome.action === "cancel") {
        resetTerminalOutput();
        cleanupUI();
        return;
      }
    }
  }

  const modeConfig = applyScanCommandConfigOverrides(
    loadConfig(repoRoot, { trustProjectConfig: opts.trustRepoConfig === true }),
    opts,
  );

  // Inherited auth: walk the OAuth token search path and prime
  const monorepoDecision = await resolveMonorepoExecution({
    repoRoot,
    scanPath,
    config: modeConfig,
    opts,
  });

  if (monorepoDecision.useMonorepo) {
    resetTerminalOutput();
    cleanupUI();
    const { runMonorepoScan } = await import("./monorepo-scan.js");
    await runMonorepoScan(repoPath, opts);
    return;
  }

  if (opts.moduleFilter) {
    resetTerminalOutput();
    cleanupUI();
    throw new CliUsageError(
      "--module-filter can only be used when module discovery or manual modules are active.",
    );
  }

  const { config, scanOpts } = prepareScanExecution(repoRoot, opts);
  ensureCodeExecutionOptIn(config, opts);

  // Interactive credential prompt when no credentials are detected for the
  // default provider. pi-ai resolves creds from env vars, so setting the
  // right env var per provider is sufficient for the scan run.
  if (!opts.resume && process.stdout.isTTY) {
    const { hasAnyProviderCredentials, runCredentialPrompt } = await import("../../ui/setup.js");
    if (!hasAnyProviderCredentials()) {
      const { providerEnvVar, providerBaseUrlEnvVar } = await import("../../config.js");
      const credOutcome = await runCredentialPrompt(uiStore);
      if (credOutcome.action === "cancel") {
        resetTerminalOutput();
        cleanupUI();
        return;
      }

      const choice = credOutcome.choice;

      if (choice.kind === "api-key") {
        config.agentRuntimeConfig = {
          ...(config.agentRuntimeConfig ?? {}),
          apiKey: choice.value,
          ...(choice.baseUrl ? { baseUrl: choice.baseUrl } : {}),
        };
        const envKey = providerEnvVar(choice.providerId);
        if (envKey) process.env[envKey] = choice.value;
        if (choice.baseUrl) {
          const envUrl = providerBaseUrlEnvVar(choice.providerId);
          if (envUrl) process.env[envUrl] = choice.baseUrl;
        }
      } else if (choice.kind === "base-url") {
        // Local/proxy providers (Ollama, OpenRouter, etc.)
        config.agentRuntimeConfig = {
          ...(config.agentRuntimeConfig ?? {}),
          baseUrl: choice.baseUrl,
          ...(choice.apiKey ? { apiKey: choice.apiKey } : {}),
        };
        const envUrl = providerBaseUrlEnvVar(choice.providerId);
        if (envUrl) process.env[envUrl] = choice.baseUrl;
        if (choice.apiKey) {
          const envKey = providerEnvVar(choice.providerId);
          if (envKey) process.env[envKey] = choice.apiKey;
        }
      } else if (choice.kind === "oauth-anthropic") {
        const { loginAnthropicAndPersist } = await import("../../oauth-flow.js");
        const result = await loginAnthropicAndPersist();
        config.agentRuntimeConfig = {
          ...(config.agentRuntimeConfig ?? {}),
          authToken: result.accessToken,
        };
      } else if (choice.kind === "oauth-openai-codex") {
        const { loginOpenAICodexAndPersist } = await import("../../oauth-flow.js");
        await loginOpenAICodexAndPersist();
      }
      // "inherited" — no changes needed, we rely on ambient env vars
    }
  }

  if (opts.dryRun || opts.showPlan) {
    const { taskIds, taskSummary, dynamicSelectionActive } = getScanPlanSummary(config, scanOpts);
    const banner = opts.dryRun
      ? "\nDry run — no scan will be executed."
      : "\nScan plan (will execute after this preview):";
    if (opts.dryRun) {
      resetTerminalOutput();
      cleanupUI();
    }
    console.log(banner);
    console.log(`  Target:    ${scanPath}`);
    console.log(`  Tasks:     ${taskIds.join(", ") || "none"}`);
    console.log(`  Expanded:  ${taskSummary}`);
    console.log(`  Dynamic:   ${dynamicSelectionActive ? "on" : "off"}`);
    console.log(`  Model:     ${config.model}`);
    console.log(`  Severity:  ${scanOpts.severity?.join(", ") || "all"}\n`);
    if (opts.dryRun) return;
    // --show-plan falls through to runPipeline below.
  }

  try {
    await runPipeline({
      repoRoot,
      scanPath,
      repoName,
      gitRoot,
      config,
      scanOpts,
      opts,
      uiStore,
    });
  } finally {
    // Let the UI render one final frame before unmounting
    await new Promise((resolve) => setTimeout(resolve, 100));
    resetTerminalOutput();
    cleanupUI();
  }
}

function ensureCodeExecutionOptIn(config: KuzushiConfig, opts: ScanCommandOptions): void {
  const runsGeneratedCode = config.dynamicAnalysisEnabled === true || config.pocExecute === true;
  if (!runsGeneratedCode) return;

  const explicitYes = opts.yes === true || process.env["KUZUSHI_YES_RUN_GENERATED_CODE"] === "1";
  if (explicitYes) return;

  if (process.stdout.isTTY && process.stdin.isTTY) return;

  const reasons: string[] = [];
  if (config.dynamicAnalysisEnabled === true) reasons.push("dynamicAnalysisEnabled");
  if (config.pocExecute === true) reasons.push("pocExecute");

  throw new CliUsageError(
    [
      "Refusing to run LLM-generated code in a non-interactive context.",
      "",
      "Enabled code-execution features:",
      ...reasons.map((reason) => `  - ${reason}`),
      "",
      `Even with pocSandbox=${String(config.pocSandbox ?? "process")}, running generated code`,
      "against the target is a deliberate security decision. Opt in by:",
      "",
      "  - kuzushi scan <repo> --yes ...",
      "  - KUZUSHI_YES_RUN_GENERATED_CODE=1 kuzushi scan <repo> ...",
      "",
      "To scan without executing generated code, drop --dynamic-analysis and",
      "unset `pocExecute` / `dynamicAnalysisEnabled` in your config.",
    ].join("\n"),
  );
}

export async function resolveMonorepoExecution(params: {
  repoRoot: string;
  scanPath: string;
  config: KuzushiConfig;
  opts: Pick<ScanCommandOptions, "listModules" | "moduleDiscovery" | "modules">;
}): Promise<MonorepoExecutionDecision> {
  const { repoRoot, scanPath, config, opts } = params;

  if (opts.modules) {
    return { useMonorepo: true, reason: "manual-modules" };
  }

  if (opts.listModules) {
    return { useMonorepo: true, reason: "list-modules" };
  }

  if (opts.moduleDiscovery === false) {
    return { useMonorepo: false, reason: "cli-opt-out" };
  }

  const targetIsRepoRoot = path.resolve(scanPath) === path.resolve(repoRoot);
  if ((config.monorepo?.modules?.length ?? 0) > 0) {
    return {
      useMonorepo: targetIsRepoRoot,
      reason: targetIsRepoRoot ? "config-modules" : "single-root",
    };
  }

  if (config.monorepo?.mode === "off") {
    return { useMonorepo: false, reason: "single-root" };
  }

  if (!targetIsRepoRoot) {
    return { useMonorepo: false, reason: "single-root" };
  }

  if (config.monorepo) {
    return { useMonorepo: true, reason: "config-monorepo" };
  }

  return (await looksLikeMonorepo(scanPath))
    ? { useMonorepo: true, reason: "auto-detected" }
    : { useMonorepo: false, reason: "single-root" };
}

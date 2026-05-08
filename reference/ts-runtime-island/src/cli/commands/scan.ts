import path from "node:path";
import { loadConfig } from "../../config.js";
import { looksLikeMonorepo } from "../../discovery/repo-discovery.js";
import { getGlobalLogLevel } from "../../logger.js";
import type { KuzushiConfig } from "../../types.js";
import { attachCiStream } from "../../ui/ci-stream.js";
import { configureTerminalOutput, resetTerminalOutput } from "../../ui/output.js";
import { registerPlainTextRenderer } from "../../ui/plain-renderer.js";
import { createUIStore } from "../../ui/state.js";
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
  // The Rust CLI owns the interactive TUI. The retained TypeScript scan path
  // keeps only a line-oriented UIStore sink for migration/reference commands.
  const uiStore = createUIStore();
  const cleanupUI = opts.ci ? attachCiStream(uiStore) : registerPlainTextRenderer(uiStore);
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

  if (
    !opts.resume &&
    (opts.confirmConfig === true || opts.reviewContext === true || opts.reviewThreatModel === true)
  ) {
    console.warn(
      "TypeScript interactive scan preflight was removed with the Ink TUI. Use the Rust shell for config, context, and threat-model review.",
    );
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

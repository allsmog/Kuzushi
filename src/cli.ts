#!/usr/bin/env node

import { Command } from "commander";
import { mkdirSync, existsSync } from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createInterface } from "node:readline/promises";
import { loadConfig, getConfigValue, setConfigValue, unsetConfigValue, configPath } from "./config.js";
import {
  createRun,
  defaultDbPath,
  getLatestResumableRun,
  getRun,
  initDb,
} from "./store.js";
import { createDefaultRegistry } from "./scanners/index.js";
import { createDefaultTaskRegistry } from "./agents/index.js";
import { configureAgentRuntime } from "./agent-runtime/index.js";
import { parsePiAiModelSpec } from "./agent-runtime/model-spec.js";
import {
  createBus,
  registerAllWorkers,
  createEvent,
  generateRunId,
  type AugurCheckpointEvent,
  type PipelineCompleteEvent,
  type PipelineErrorEvent,
} from "./bus/index.js";
import type { ScanOpts } from "./types.js";

function resolveRepo(repoPath: string): { root: string; name: string } {
  const absPath = path.resolve(repoPath);
  try {
    const root = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd: absPath,
      encoding: "utf-8",
    }).trim();
    return { root, name: path.basename(root) };
  } catch {
    return { root: absPath, name: path.basename(absPath) };
  }
}

function parseScannersArg(raw: string): string[] {
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function maybeWarnPiAiApiKeyForModel(model: string | undefined): void {
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

  const hasAny = envVars.some((name) => Boolean(process.env[name]));
  if (hasAny) {
    return;
  }

  console.warn(
    `Warning: model "${model}" uses provider "${provider}", `
    + `but none of [${envVars.join(", ")}] are set.`,
  );
}

function warnPiAiBackendApiKeys(config: { [key: string]: unknown }): void {
  const modelCandidates = new Set<string>();

  const pushModel = (value: unknown) => {
    if (typeof value !== "string") return;
    const trimmed = value.trim();
    if (!trimmed) return;
    modelCandidates.add(trimmed);
  };

  pushModel(config["model"]);
  pushModel(config["triageModel"]);
  pushModel(config["verifyModel"]);
  pushModel(config["pocHarnessModel"]);

  const scannerConfig = config["scannerConfig"];
  if (scannerConfig && typeof scannerConfig === "object") {
    const scannerConfigRecord = scannerConfig as Record<string, unknown>;
    const agentic = scannerConfigRecord["agentic"];
    if (agentic && typeof agentic === "object") {
      pushModel((agentic as Record<string, unknown>)["model"]);
    }

    const augur = scannerConfigRecord["augur"];
    if (augur && typeof augur === "object") {
      pushModel((augur as Record<string, unknown>)["labelingModel"]);
    }
  }

  for (const model of modelCandidates) {
    maybeWarnPiAiApiKeyForModel(model);
  }
}

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

const program = new Command();

program
  .name("kuzushi")
  .description("Kuzushi — Agentic SAST orchestration")
  .version("0.1.0");

// ── scan (default command) ────────────────────────────────────────────────

program
  .command("scan", { isDefault: true })
  .description("Scan a repository with configured scanners and triage findings with an agent")
  .argument("<repo>", "Path to the repository to scan")
  .option("--scanners <names>", "Scanners to run (comma-separated scanner ids)")
  .option("--severity <levels>", "Severity filter (comma-separated)")
  .option("--max <n>", "Max findings to triage", parseInt)
  .option("--model <model>", "Model to use for scanners")
  .option("--triage-model <model>", "Override model used by triage agent")
  .option("--triage-max-turns <n>", "Override triage agent max turn budget", parseInt)
  .option("--verify", "Enable post-triage exploitability verification", false)
  .option("--verify-model <model>", "Override model used by verification agent")
  .option("--verify-max-turns <n>", "Override verification agent max turn budget", parseInt)
  .option("--verify-concurrency <n>", "Override verification concurrency", parseInt)
  .option("--verify-min-confidence <n>", "Minimum triage confidence required for verification", parseFloat)
  .option("--poc-harness", "Enable post-verification PoC harness generation", false)
  .option("--poc-harness-model <model>", "Override model used by PoC harness generator")
  .option("--poc-harness-max-turns <n>", "Override PoC harness agent max turn budget", parseInt)
  .option("--poc-harness-concurrency <n>", "Override PoC harness generation concurrency", parseInt)
  .option("--max-poc-harness-retries <n>", "Retries for PoC harness generation failures", parseInt)
  .option("--max-triage-retries <n>", "Retries for triage agent failures", parseInt)
  .option("--max-verify-retries <n>", "Retries for verification agent failures", parseInt)
  .option("--retry-backoff-ms <n>", "Initial retry backoff in milliseconds", parseInt)
  .option("--no-context", "Disable pre-scan repository context gathering")
  .option("--audit-log", "Persist per-run audit logs to .kuzushi/runs/<runId>/", false)
  .option("--output <path>", "Write markdown report to this path")
  .option("--sarif <path>", "Write SARIF v2.1.0 report to this path")
  .option("--agent-runtime <backend>", "Agent runtime backend (claude-sdk|pi-ai|acp)")
  .option("--enabled-tasks <ids>", "Additional AgentTask IDs to enable (comma-separated)")
  .option("--approve-checkpoint", "Auto-approve Augur checkpoints for this run", false)
  .option("--fresh", "Clear prior results before scanning", false)
  .option("--resume [runId]", "Resume a previous run (optionally by run id)")
  .option("--db <path>", "SQLite database path (default: <repo>/.kuzushi/findings.sqlite3)")
  .action(async (repoPath: string, opts: {
    scanners?: string;
    severity?: string;
    max?: number;
    model?: string;
    triageModel?: string;
    triageMaxTurns?: number;
    verify: boolean;
    verifyModel?: string;
    verifyMaxTurns?: number;
    verifyConcurrency?: number;
    verifyMinConfidence?: number;
    pocHarness: boolean;
    pocHarnessModel?: string;
    pocHarnessMaxTurns?: number;
    pocHarnessConcurrency?: number;
    maxPocHarnessRetries?: number;
    maxTriageRetries?: number;
    maxVerifyRetries?: number;
    retryBackoffMs?: number;
    context: boolean;
    auditLog: boolean;
    output?: string;
    sarif?: string;
    agentRuntime?: string;
    enabledTasks?: string;
    approveCheckpoint: boolean;
    fresh: boolean;
    resume?: string | boolean;
    db?: string;
  }) => {
    const { root: repoRoot, name: repoName } = resolveRepo(repoPath);

    // Load config with optional project-level overlay, then apply CLI overrides.
    const config = loadConfig(repoRoot);
    if (opts.model) config.model = opts.model;
    if (opts.triageModel) config.triageModel = opts.triageModel;
    if (opts.verify) config.verify = true;
    if (opts.verifyModel) config.verifyModel = opts.verifyModel;
    if (opts.pocHarness) config.pocHarness = true;
    if (opts.pocHarnessModel) config.pocHarnessModel = opts.pocHarnessModel;
    if (opts.verifyMinConfidence !== undefined) {
      if (!Number.isFinite(opts.verifyMinConfidence) || opts.verifyMinConfidence < 0 || opts.verifyMinConfidence > 1) {
        console.error("Error: --verify-min-confidence must be a number between 0 and 1.");
        process.exit(1);
      }
      config.verifyMinConfidence = opts.verifyMinConfidence;
    }
    if (opts.context === false) config.enableContextGathering = false;
    if (opts.auditLog) config.auditLog = true;
    if (opts.output) config.reportOutput = path.resolve(opts.output);
    if (opts.sarif) config.sarifOutput = path.resolve(opts.sarif);
    if (opts.agentRuntime) {
      config.agentRuntimeBackend = opts.agentRuntime as typeof config.agentRuntimeBackend;
    }
    if (opts.enabledTasks) {
      config.enabledTasks = parseScannersArg(opts.enabledTasks);
    }
    if (opts.approveCheckpoint) {
      const augurConfig = config.scannerConfig.augur ?? {};
      config.scannerConfig.augur = {
        ...augurConfig,
        autoApproveCheckpoint: true,
      };
    }
    if (opts.triageMaxTurns !== undefined) {
      if (!Number.isFinite(opts.triageMaxTurns) || opts.triageMaxTurns < 1) {
        console.error("Error: --triage-max-turns must be a positive integer.");
        process.exit(1);
      }
      config.triageMaxTurns = Math.floor(opts.triageMaxTurns);
    }

    if (opts.verifyMaxTurns !== undefined) {
      if (!Number.isFinite(opts.verifyMaxTurns) || opts.verifyMaxTurns < 1) {
        console.error("Error: --verify-max-turns must be a positive integer.");
        process.exit(1);
      }
      config.verifyMaxTurns = Math.floor(opts.verifyMaxTurns);
    }

    if (opts.verifyConcurrency !== undefined) {
      if (!Number.isFinite(opts.verifyConcurrency) || opts.verifyConcurrency < 1) {
        console.error("Error: --verify-concurrency must be a positive integer.");
        process.exit(1);
      }
      config.verifyConcurrency = Math.floor(opts.verifyConcurrency);
    }

    if (opts.pocHarnessMaxTurns !== undefined) {
      if (!Number.isFinite(opts.pocHarnessMaxTurns) || opts.pocHarnessMaxTurns < 1) {
        console.error("Error: --poc-harness-max-turns must be a positive integer.");
        process.exit(1);
      }
      config.pocHarnessMaxTurns = Math.floor(opts.pocHarnessMaxTurns);
    }

    if (opts.pocHarnessConcurrency !== undefined) {
      if (!Number.isFinite(opts.pocHarnessConcurrency) || opts.pocHarnessConcurrency < 1) {
        console.error("Error: --poc-harness-concurrency must be a positive integer.");
        process.exit(1);
      }
      config.pocHarnessConcurrency = Math.floor(opts.pocHarnessConcurrency);
    }

    if (config.pocHarness && config.verify !== true) {
      console.error("Error: --poc-harness requires --verify.");
      process.exit(1);
    }

    if (opts.maxTriageRetries !== undefined) {
      if (!Number.isFinite(opts.maxTriageRetries) || opts.maxTriageRetries < 0) {
        console.error("Error: --max-triage-retries must be a non-negative integer.");
        process.exit(1);
      }
      config.maxTriageRetries = Math.floor(opts.maxTriageRetries);
    }

    if (opts.maxVerifyRetries !== undefined) {
      if (!Number.isFinite(opts.maxVerifyRetries) || opts.maxVerifyRetries < 0) {
        console.error("Error: --max-verify-retries must be a non-negative integer.");
        process.exit(1);
      }
      config.maxVerifyRetries = Math.floor(opts.maxVerifyRetries);
    }

    if (opts.maxPocHarnessRetries !== undefined) {
      if (!Number.isFinite(opts.maxPocHarnessRetries) || opts.maxPocHarnessRetries < 0) {
        console.error("Error: --max-poc-harness-retries must be a non-negative integer.");
        process.exit(1);
      }
      config.maxPocHarnessRetries = Math.floor(opts.maxPocHarnessRetries);
    }

    if (opts.retryBackoffMs !== undefined) {
      if (!Number.isFinite(opts.retryBackoffMs) || opts.retryBackoffMs < 0) {
        console.error("Error: --retry-backoff-ms must be a non-negative integer.");
        process.exit(1);
      }
      config.retryBackoffMs = Math.floor(opts.retryBackoffMs);
    }

    const runtimeBackend = config.agentRuntimeBackend ?? "claude-sdk";
    if (runtimeBackend === "claude-sdk" && !process.env["ANTHROPIC_API_KEY"]) {
      console.error("Error: ANTHROPIC_API_KEY environment variable is required.");
      console.error("Get one at: https://console.anthropic.com/");
      process.exit(1);
    }

    if (runtimeBackend === "pi-ai") {
      warnPiAiBackendApiKeys(config as unknown as Record<string, unknown>);
    }

    try {
      configureAgentRuntime(config);
    } catch (err) {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    }

    const severity = opts.severity
      ? opts.severity.split(",").map((s) => s.trim().toUpperCase())
      : config.severity;

    const scannersOverride = opts.scanners
      ? parseScannersArg(opts.scanners)
      : undefined;

    const scanOpts: ScanOpts = {
      severity,
      maxFindings: opts.max,
      excludePatterns: config.excludePatterns,
      scanners: scannersOverride,
      fresh: opts.fresh,
    };

    const registry = createDefaultRegistry();
    try {
      scanOpts.scanners = registry.resolveEnabled(scanOpts, config);
    } catch (err) {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    }

    // Set up DB.
    const dbPath = opts.db ?? defaultDbPath(repoRoot);
    const dbDir = path.dirname(dbPath);
    if (!existsSync(dbDir)) mkdirSync(dbDir, { recursive: true });

    const db = initDb(dbPath);
    const bus = createBus(config);
    const taskRegistry = createDefaultTaskRegistry(registry);
    registerAllWorkers(bus, { registry, taskRegistry, db, config });

    let resumeRunId: string | undefined;
    if (opts.resume !== undefined) {
      if (opts.resume === true) {
        const latest = getLatestResumableRun(db, repoName);
        if (!latest) {
          console.error(`Error: no resumable runs found for repo "${repoName}".`);
          process.exit(1);
        }
        resumeRunId = latest.runId;
      } else if (typeof opts.resume === "string" && opts.resume.trim().length > 0) {
        resumeRunId = opts.resume.trim();
      }

      if (!resumeRunId) {
        console.error("Error: --resume received an invalid run id.");
        process.exit(1);
      }

      const run = getRun(db, resumeRunId);
      if (!run) {
        console.error(`Error: run "${resumeRunId}" was not found.`);
        process.exit(1);
      }

      if (run.repo !== repoName) {
        console.error(
          `Error: run "${resumeRunId}" belongs to repo "${run.repo}", not "${repoName}".`,
        );
        process.exit(1);
      }

      if (run.status === "complete") {
        console.error(`Error: run "${resumeRunId}" is already complete and cannot be resumed.`);
        process.exit(1);
      }
    }

    const runId = resumeRunId ?? generateRunId();
    if (!resumeRunId) {
      createRun(db, runId, repoName, config, scanOpts);
    }

    const context = {
      runId,
      repoRoot,
      repoName,
      dbPath,
    };

    bus.subscribe<AugurCheckpointEvent>("augur:checkpoint", async (event) => {
      if (event.meta.runId !== runId) {
        return;
      }

      if (opts.approveCheckpoint) {
        await bus.publish(
          createEvent("augur:checkpoint-approved", runId, {
            context: event.payload.context,
            reviewer: "cli-auto-approve",
          }),
        );
        return;
      }

      console.log("");
      console.log("  Augur checkpoint reached.");
      if (event.payload.reviewSummary.trim()) {
        console.log("");
        console.log(event.payload.reviewSummary.trim());
        console.log("");
      }

      let reviewer = "cli-noninteractive";
      if (process.stdin.isTTY && process.stdout.isTTY) {
        const rl = createInterface({ input: process.stdin, output: process.stdout });
        try {
          // Keep the gate explicit: continue only on affirmative approval.
          while (true) {
            const answer = (await rl.question("  Approve Augur labels and continue? [y/n]: "))
              .trim()
              .toLowerCase();
            if (answer === "y" || answer === "yes") {
              reviewer = "cli-user";
              break;
            }

            if (answer === "n" || answer === "no") {
              console.log("  Approval required to continue. Press Ctrl+C to abort or approve to proceed.");
              continue;
            }
          }
        } finally {
          rl.close();
        }
      } else {
        await bus.publish(
          createEvent("pipeline:error", runId, {
            context: event.payload.context,
            error: "Augur checkpoint requires interactive approval. Re-run with --approve-checkpoint in non-interactive mode.",
            fatal: true,
          }),
        );
        return;
      }

      await bus.publish(
        createEvent("augur:checkpoint-approved", runId, {
          context: event.payload.context,
          reviewer,
        }),
      );
    });

    const pipelineComplete = bus
      .waitFor<PipelineCompleteEvent>(
        "pipeline:complete",
        (event) => event.meta.runId === runId,
      )
      .then((event) => ({ kind: "complete" as const, event }));

    const pipelineError = bus
      .waitFor<PipelineErrorEvent>(
        "pipeline:error",
        (event) => event.meta.runId === runId && event.payload.fatal,
      )
      .then((event) => ({ kind: "error" as const, event }));

    try {
      await bus.publish(
        createEvent("pipeline:start", runId, {
          context,
          config,
          scanOpts,
          resumeRunId,
        }),
      );

      const outcome = await Promise.race([pipelineComplete, pipelineError]);
      if (outcome.kind === "error") {
        console.error(`Error: ${outcome.event.payload.error}`);
        process.exitCode = 1;
      }
    } finally {
      await bus.close();
      db.close();
    }
  });

// ── config get/set/unset ──────────────────────────────────────────────────

const configCmd = program
  .command("config")
  .description("Manage Kuzushi configuration");

configCmd
  .command("get")
  .description("Get a config value")
  .argument("[key]", "Config key (omit to show all)")
  .action((key?: string) => {
    if (!key) {
      const config = loadConfig();
      console.log(JSON.stringify(config, null, 2));
      return;
    }
    const value = getConfigValue(key);
    if (value === undefined) {
      console.error(`Unknown config key: ${key}`);
      process.exit(1);
    }
    console.log(typeof value === "string" ? value : JSON.stringify(value));
  });

configCmd
  .command("set")
  .description("Set a config value")
  .argument("<key>", "Config key")
  .argument("<value>", "Value to set")
  .action((key: string, value: string) => {
    try {
      setConfigValue(key, value);
      console.log(`${key} = ${JSON.stringify(getConfigValue(key))}`);
    } catch (err) {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  });

configCmd
  .command("unset")
  .description("Reset a config key to its default")
  .argument("<key>", "Config key")
  .action((key: string) => {
    try {
      unsetConfigValue(key);
      console.log(`${key} reset to default: ${JSON.stringify(getConfigValue(key))}`);
    } catch (err) {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  });

configCmd
  .command("path")
  .description("Print config file path")
  .action(() => {
    console.log(configPath());
  });

program.parse();

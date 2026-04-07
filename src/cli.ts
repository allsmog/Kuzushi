#!/usr/bin/env node

// Suppress EPIPE errors from child process stdio pipes (e.g. Claude SDK subprocesses).
// These occur when a subprocess exits and the parent writes to a closed pipe.
process.on("uncaughtException", (err: NodeJS.ErrnoException) => {
  if (err.code === "EPIPE" || err.code === "ERR_STREAM_DESTROYED") {
    // Non-fatal — the subprocess already exited, the task will be reported as failed.
    return;
  }
  console.error(err);
  process.exitCode = 1;
});

import { Command } from "commander";
import { mkdirSync, existsSync } from "node:fs";
import path from "node:path";
import { cleanup as cleanupHttpAgents } from "./http-agent.js";
import { registerShutdownHook, initiateShutdown } from "./lifecycle.js";
import { loadConfig, getConfigValue, setConfigValue, unsetConfigValue, configPath } from "./config.js";
import {
  formatConfigValidationIssue,
  validateKuzushiConfig,
} from "./config/validation.js";
import {
  defaultDbPath,
  getRun,
  initDb,
} from "./store.js";
import { createDefaultRegistry } from "./scanners/index.js";
import { createDefaultTaskRegistry } from "./agents/index.js";
import { configureAgentRuntime } from "./agent-runtime/index.js";
import { setGlobalLogLevel } from "./logger.js";
import { wrapCliAction, CliUsageError } from "./cli/errors.js";
import { runScanCommand } from "./cli/commands/scan.js";
import { resolveRepo } from "./cli/shared.js";

function maybeWarnPlaintextApiKeyStorage(key: string, value: string): void {
  let storesApiKey = key === "agentRuntimeConfig.apiKey";

  if (!storesApiKey && key === "agentRuntimeConfig") {
    try {
      const parsed = JSON.parse(value);
      storesApiKey = typeof parsed?.["apiKey"] === "string" && parsed["apiKey"].trim().length > 0;
    } catch {
      storesApiKey = false;
    }
  }

  if (!storesApiKey) {
    return;
  }

  console.warn(
    `Warning: ${key} stores API credentials in plaintext at ${configPath()}. `
    + "Prefer --api-key for one-off scans or ANTHROPIC_API_KEY from your shell/secret manager.",
  );
}

const program = new Command();

program
  .name("kuzushi")
  .description("Kuzushi — Agentic SAST orchestration")
  .option("--verbose", "Show debug-level diagnostics", false)
  .version("0.1.0");

program.hook("preAction", (_thisCommand, actionCommand) => {
  if (actionCommand.optsWithGlobals().verbose) {
    setGlobalLogLevel("debug");
  }
});

// ── scan (default command) ────────────────────────────────────────────────

program
  .command("scan", { isDefault: true })
  .description("Scan a repository with configured scanners and triage findings with an agent")
  .argument("<repo>", "Path to the repository to scan")
  .option("--preset <name>", "Scan preset: fast, standard, deep")
  .option("--scanners <names>", "Scanners to run (comma-separated scanner ids)")
  .option("--severity <levels>", "Severity filter (comma-separated)")
  .option("--max <n>", "Max findings to triage", parseInt)
  .option("--model <model>", "Model to use for scanners")
  .option("--ensemble-models <models>", "Run eligible agentic detection tasks across multiple models (comma-separated)")
  .option("--triage-model <model>", "Override model used by triage agent")

  .option("--verify", "Enable post-triage exploitability verification", false)
  .option("--verify-model <model>", "Override model used by verification agent")
  .option("--verify-concurrency <n>", "Override verification concurrency", parseInt)
  .option("--verify-refinement-max-iterations <n>", "Maximum verification refinement attempts", parseInt)
  .option("--verify-reflection-interval <n>", "Inject verification reflection every N failed attempts", parseInt)
  .option("--verify-min-confidence <n>", "Minimum triage confidence required for verification", parseFloat)
  .option("--crypto-behavioral-test", "Enable crypto behavioral runtime confirmation", false)
  .option("--dynamic-analysis", "Enable dynamic analysis using generated PoC harnesses", false)
  .option("--dynamic-max-candidates <n>", "Override maximum number of dynamic analysis candidates", parseInt)
  .option("--dynamic-min-score <n>", "Minimum score for dynamic analysis candidates", parseInt)
  .option("--code-graph", "Enable LLM-powered code graph construction and enrichment", false)
  .option("--multi-strategy", "Enable multi-strategy analysis (adaptive mode)", false)
  .option("--multi-strategy-full", "Enable multi-strategy analysis (all strategies in parallel)", false)
  .option("--multi-strategy-budget <n>", "Budget per finding across all strategies in USD", parseFloat)
  .option("--multi-strategy-auto-rules", "Generate rules from confirmed multi-strategy findings", false)
  .option("--taint-diff-base <ref>", "Only taint-analyze files changed since the provided git ref")
  .option("--taint-diff-mode <mode>", "Diff-aware taint mode: delta|baseline")
  .option("--stream", "Enable SSE streaming server for live pipeline events", false)
  .option("--stream-port <n>", "Port for SSE streaming server (0 = auto)", parseInt)
  .option("--github-pr", "Create GitHub fix PRs from verified patches", false)
  .option("--github-comment", "Post findings summary as PR comment", false)
  .option("--auto-patch", "Enable automatic patch generation in pipeline", false)
  .option("--auto-patch-after <trigger>", "Trigger threshold: verify|poc|triage")
  .option("--patch-verify-depth <depth>", "Re-verification depth: scanner|triage|full")
  .option("--patch-concurrency <n>", "Max concurrent patch synthesis tasks", parseInt)
  .option("--poc-harness", "Enable post-verification PoC harness generation", false)
  .option("--poc-harness-model <model>", "Override model used by PoC harness generator")
  .option("--poc-harness-concurrency <n>", "Override PoC harness generation concurrency", parseInt)
  .option("--poc-refinement-max-iterations <n>", "Maximum PoC refinement attempts when execution feedback is enabled", parseInt)
  .option("--poc-reflection-interval <n>", "Inject PoC reflection every N failed attempts", parseInt)
  .option("--max-poc-harness-retries <n>", "Retries for PoC harness generation failures", parseInt)
  .option("--max-triage-retries <n>", "Retries for triage agent failures", parseInt)
  .option("--max-verify-retries <n>", "Retries for verification agent failures", parseInt)
  .option("--retry-backoff-ms <n>", "Initial retry backoff in milliseconds", parseInt)
  .option("--no-context", "Disable pre-scan repository context gathering")
  .option("--audit-log", "Persist per-run audit logs to .kuzushi/runs/<runId>/", false)
  .option("--output <path>", "Write markdown report to this path")
  .option("--sarif <path>", "Write SARIF v2.1.0 report to this path")
  .option("--json <path>", "Write JSON report to this path")
  .option("--csv <path>", "Write CSV report to this path")
  .option("--jsonl <path>", "Write JSONL report to this path")
  .option("--agent-runtime <backend>", "Agent runtime backend")
  .option("--api-key <key>", "Override ANTHROPIC_API_KEY for this run")
  .option("--base-url <url>", "Override ANTHROPIC_BASE_URL for this run")
  .option("--enabled-tasks <ids>", "Additional AgentTask IDs to enable (comma-separated)")
  .option("--list-modules", "Discover and print modules without scanning", false)
  .option("--modules <spec>", "Manual module list: \"name:path,name:path,...\"")
  .option("--module-filter <pattern>", "Only scan modules whose names match the pattern")
  .option("--no-module-discovery", "Force a single-root scan even when the target looks like a monorepo")
  .option("--enable-external-tasks", "Enable loading of external tasks from config", false)
  .option("--trust-repo-config", "Trust unsafe repo-local config keys such as hooks and external tasks", false)
  .option("--quality-gate", "Enable quality gates (fail CI on threshold violations)", false)
  .option("--fail-on-tp", "Shorthand: fail if any high/critical severity true positive is found", false)
  .option("--fresh", "Clear prior results before scanning", false)
  .option("--no-cache", "Disable inflight request deduplication and LLM result caching")
  .option("--resume [runId]", "Resume a previous run (optionally by run id)")
  .option("--db <path>", "SQLite database path (default: <repo>/.kuzushi/findings.sqlite3)")
  .action(wrapCliAction(runScanCommand));

// ── compare-runs ──────────────────────────────────────────────────────────

function fmt(n: number | undefined): string {
  return n != null ? (n * 100).toFixed(1) + "%" : "n/a";
}

function delta(a: number | undefined, b: number | undefined): string {
  if (a == null || b == null) return "n/a";
  const d = (b - a) * 100;
  return (d >= 0 ? "+" : "") + d.toFixed(1) + "pp";
}

program
  .command("compare-runs <id1> <id2>")
  .description("Compare metrics and assertions between two pipeline runs")
  .option("-r, --repo <path>", "Repository path", ".")
  .action(wrapCliAction(async (id1: string, id2: string, options: { repo: string }) => {
    const { root } = resolveRepo(options.repo);
    const dbPath = defaultDbPath(root);
    const db = initDb(dbPath);
    try {
      const run1 = getRun(db, id1);
      const run2 = getRun(db, id2);
      if (!run1 || !run2) {
        throw new CliUsageError(`Run not found: ${!run1 ? id1 : id2}`);
      }
      // Parse metrics
      const metrics1 = run1.metricsJson ? JSON.parse(run1.metricsJson) : null;
      const metrics2 = run2.metricsJson ? JSON.parse(run2.metricsJson) : null;

      // Print comparison
      console.log("Pipeline Run Comparison");
      console.log("=".repeat(60));
      console.log(`Run 1: ${id1} (${run1.status})`);
      console.log(`Run 2: ${id2} (${run2.status})`);
      console.log(`Prompt hash: ${run1.promptHash ?? "n/a"} vs ${run2.promptHash ?? "n/a"}`);
      if (run1.promptHash && run2.promptHash && run1.promptHash !== run2.promptHash) {
        console.log("  Warning: Prompt templates changed between runs");
      }
      console.log("");

      if (metrics1 && metrics2) {
        console.log("Metrics Comparison:");
        console.log(`  TP Rate: ${fmt(metrics1.tpRate)} -> ${fmt(metrics2.tpRate)} (${delta(metrics1.tpRate, metrics2.tpRate)})`);
        console.log(`  FP Rate: ${fmt(metrics1.fpRate)} -> ${fmt(metrics2.fpRate)} (${delta(metrics1.fpRate, metrics2.fpRate)})`);
        console.log(`  Avg Confidence: ${fmt(metrics1.averageConfidence)} -> ${fmt(metrics2.averageConfidence)} (${delta(metrics1.averageConfidence, metrics2.averageConfidence)})`);
        console.log(`  Total Cost: $${metrics1.costBreakdown?.total?.toFixed(4) ?? "?"} -> $${metrics2.costBreakdown?.total?.toFixed(4) ?? "?"}`);
      }

      // Compare assertions
      const assertions1 = run1.assertionsJson ? JSON.parse(run1.assertionsJson) : null;
      const assertions2 = run2.assertionsJson ? JSON.parse(run2.assertionsJson) : null;
      if (assertions1 || assertions2) {
        console.log("\nAssertion Comparison:");
        if (assertions1?.totalAssertions != null && assertions2?.totalAssertions != null) {
          console.log(`  Pass rate: ${assertions1.passedAssertions}/${assertions1.totalAssertions} -> ${assertions2.passedAssertions}/${assertions2.totalAssertions}`);
          console.log(`  Avg quality: ${fmt(assertions1.averageQualityScore)} -> ${fmt(assertions2.averageQualityScore)}`);
        } else {
          console.log(`  Run 1: ${assertions1 ? JSON.stringify(assertions1) : "n/a"}`);
          console.log(`  Run 2: ${assertions2 ? JSON.stringify(assertions2) : "n/a"}`);
        }
      }

      // Flag regressions
      if (metrics1 && metrics2) {
        const regressions: string[] = [];
        if (metrics2.tpRate < metrics1.tpRate * 0.9) regressions.push("TP rate dropped >10%");
        if (metrics2.fpRate > metrics1.fpRate * 1.1) regressions.push("FP rate increased >10%");
        if (metrics2.averageConfidence < metrics1.averageConfidence * 0.9) regressions.push("Average confidence dropped >10%");
        if (regressions.length > 0) {
          console.log("\nREGRESSIONS DETECTED:");
          for (const r of regressions) console.log(`  - ${r}`);
        } else {
          console.log("\nNo regressions detected");
        }
      }
    } finally {
      db.close();
    }
  }));

// ── config get/set/unset ──────────────────────────────────────────────────

const configCmd = program
  .command("config")
  .description("Manage Kuzushi configuration");

configCmd
  .command("get")
  .description("Get a config value")
  .argument("[key]", "Config key (omit to show all)")
  .action(wrapCliAction((key?: string) => {
    if (!key) {
      const config = loadConfig();
      console.log(JSON.stringify(config, null, 2));
      return;
    }
    const value = getConfigValue(key);
    if (value === undefined) {
      throw new CliUsageError(`Unknown config key: ${key}`);
    }
    console.log(typeof value === "string" ? value : JSON.stringify(value));
  }));

configCmd
  .command("set")
  .description("Set a config value")
  .argument("<key>", "Config key")
  .argument("<value>", "Value to set")
  .action(wrapCliAction((key: string, value: string) => {
    setConfigValue(key, value);
    console.log(`${key} = ${JSON.stringify(getConfigValue(key))}`);
    maybeWarnPlaintextApiKeyStorage(key, value);
  }));

configCmd
  .command("unset")
  .description("Reset a config key to its default")
  .argument("<key>", "Config key")
  .action(wrapCliAction((key: string) => {
    unsetConfigValue(key);
    console.log(`${key} reset to default: ${JSON.stringify(getConfigValue(key))}`);
  }));

configCmd
  .command("path")
  .description("Print config file path")
  .action(() => {
    console.log(configPath());
  });

configCmd
  .command("validate")
  .description("Validate the effective Kuzushi configuration")
  .option("-r, --repo <path>", "Repository path for project-level config overlay", ".")
  .option("--trust-repo-config", "Trust unsafe repo-local config keys during validation", false)
  .action(wrapCliAction((opts: { repo: string; trustRepoConfig?: boolean }) => {
    const { root } = resolveRepo(opts.repo);
    const config = loadConfig(root, { trustProjectConfig: opts.trustRepoConfig === true });
    const issues = validateKuzushiConfig(config);
    const warnings = issues.filter((issue) => issue.severity === "warning");
    const errors = issues.filter((issue) => issue.severity === "error");

    if (warnings.length === 0 && errors.length === 0) {
      console.log(`Configuration is valid for ${root}`);
      return;
    }

    if (warnings.length > 0) {
      console.log("Warnings:");
      for (const issue of warnings) {
        console.log(`  - ${formatConfigValidationIssue(issue)}`);
      }
    }

    if (errors.length > 0) {
      throw new CliUsageError("Errors:", {
        details: errors.map((issue) => `  - ${formatConfigValidationIssue(issue)}`),
      });
    }
  }));

// ── task list/info/validate ────────────────────────────────────────────────

const taskCmd = program
  .command("task")
  .description("Manage and inspect pipeline tasks");

taskCmd
  .command("list")
  .description("List all registered tasks with their metadata")
  .option("-r, --repo <path>", "Repository path", ".")
  .option("--filter <outputKind>", "Filter by output kind (findings|threat-model|verdict|report|custom)")
  .option("--trust-repo-config", "Trust unsafe repo-local config keys while loading tasks", false)
  .action(async (opts: { repo: string; filter?: string; trustRepoConfig?: boolean }) => {
    const { root } = resolveRepo(opts.repo);
    const config = loadConfig(root, { trustProjectConfig: opts.trustRepoConfig === true });
    const registry = createDefaultRegistry();
    const taskRegistry = await createDefaultTaskRegistry(registry, config, root);

    let tasks = taskRegistry.list();
    if (opts.filter) {
      tasks = tasks.filter((t) => t.outputKind === opts.filter);
    }

    if (tasks.length === 0) {
      console.log("No tasks registered.");
      return;
    }

    // Show DAG stages
    const allIds = tasks.map((t) => t.id);
    let stages: string[][] = [];
    try {
      stages = taskRegistry.resolveOrder(allIds);
    } catch {
      // DAG resolution may fail if not all deps are in the list
    }

    console.log(`Registered tasks: ${tasks.length}\n`);

    for (const task of tasks) {
      const deps = task.dependsOn.length > 0 ? task.dependsOn.join(", ") : "none";
      const version = task.manifest?.version ?? "-";
      console.log(`  ${task.id}`);
      console.log(`    Name:       ${task.displayName}`);
      console.log(`    Output:     ${task.outputKind}`);
      console.log(`    Depends on: ${deps}`);
      console.log(`    Version:    ${version}`);
      console.log();
    }

    if (stages.length > 0) {
      console.log("DAG execution stages:");
      for (let i = 0; i < stages.length; i++) {
        console.log(`  Stage ${i}: ${stages[i].join(", ")}`);
      }
    }
  });

taskCmd
  .command("info")
  .description("Show detailed information about a task")
  .argument("<id>", "Task ID")
  .option("-r, --repo <path>", "Repository path", ".")
  .option("--trust-repo-config", "Trust unsafe repo-local config keys while loading tasks", false)
  .action(wrapCliAction(async (id: string, opts: { repo: string; trustRepoConfig?: boolean }) => {
    const { root } = resolveRepo(opts.repo);
    const config = loadConfig(root, { trustProjectConfig: opts.trustRepoConfig === true });
    const registry = createDefaultRegistry();
    const taskRegistry = await createDefaultTaskRegistry(registry, config, root);

    if (!taskRegistry.has(id)) {
      throw new CliUsageError(`Task "${id}" not found.`);
    }

    const task = taskRegistry.get(id);
    const manifest = taskRegistry.getManifest(id);

    console.log(`Task: ${task.id}`);
    console.log(`  Display Name: ${task.displayName}`);
    console.log(`  Output Kind:  ${task.outputKind}`);
    console.log(`  Depends On:   ${task.dependsOn.length > 0 ? task.dependsOn.join(", ") : "none"}`);
    console.log(`  Has Condition: ${task.condition ? "yes" : "no"}`);
    console.log(`  Prompt Mode:  ${task.promptMode ?? "full"}`);

    if (manifest) {
      console.log(`\n  Manifest:`);
      console.log(`    Version:     ${manifest.version}`);
      console.log(`    Description: ${manifest.description}`);
      if (manifest.author) console.log(`    Author:      ${manifest.author}`);
      if (manifest.license) console.log(`    License:     ${manifest.license}`);
      if (manifest.requires) {
        if (manifest.requires.env?.length) {
          console.log(`    Requires env: ${manifest.requires.env.join(", ")}`);
        }
        if (manifest.requires.bins?.length) {
          console.log(`    Requires bins: ${manifest.requires.bins.join(", ")}`);
        }
        if (manifest.requires.nodeVersion) {
          console.log(`    Node version: ${manifest.requires.nodeVersion}`);
        }
      }
      if (manifest.config) {
        console.log(`    Config schema:`);
        for (const [key, entry] of Object.entries(manifest.config)) {
          const defaultVal = entry.default !== undefined ? ` (default: ${JSON.stringify(entry.default)})` : "";
          console.log(`      ${key}: ${entry.type}${defaultVal} — ${entry.description}`);
        }
      }
    }
  }));

taskCmd
  .command("validate")
  .description("Validate an external task file and its manifest")
  .argument("<path>", "Path to task file")
  .action(wrapCliAction(async (filePath: string) => {
    const { parseTaskSpecifier, loadExternalTask } = await import("./agents/task-loader.js");
    const { loadManifestForTaskFile, checkRequirements } = await import("./agents/task-manifest.js");

    const absPath = path.resolve(filePath);

    // Validate manifest if present
    const manifestResult = loadManifestForTaskFile(absPath);
    if (manifestResult) {
      if (!manifestResult.valid) {
        throw new CliUsageError("Manifest validation failed:", {
          details: (manifestResult.errors ?? []).map((err) => `  - ${err}`),
        });
      }
      console.log(`Manifest: valid (${manifestResult.manifest!.id} v${manifestResult.manifest!.version})`);

      // Check requirements
      const reqCheck = checkRequirements(manifestResult.manifest!);
      if (!reqCheck.satisfied) {
        console.warn("Requirements not fully satisfied:");
        if (reqCheck.missing.env.length > 0) {
          console.warn(`  Missing env: ${reqCheck.missing.env.join(", ")}`);
        }
        if (reqCheck.missing.bins.length > 0) {
          console.warn(`  Missing bins: ${reqCheck.missing.bins.join(", ")}`);
        }
        if (reqCheck.missing.nodeVersion) {
          console.warn(`  Node version: ${reqCheck.missing.nodeVersion}`);
        }
      } else {
        console.log("Requirements: all satisfied");
      }
    } else {
      console.log("Manifest: not found (optional)");
    }

    // Validate the task module loads correctly
    try {
      const specifier = `file://${absPath}`;
      const spec = parseTaskSpecifier(specifier);
      await loadExternalTask(spec, path.dirname(absPath));
      console.log("Task module: valid");
    } catch (err) {
      throw new CliUsageError(`Task module validation failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }));

// ── patch ─────────────────────────────────────────────────────────────────

program
  .command("patch")
  .description("Synthesize and validate a security patch for a specific finding")
  .argument("<repo>", "Path to the repository")
  .requiredOption("--fingerprint <fp>", "Finding fingerprint to patch")
  .option("--build-cmd <cmd>", "Override build command for validation")
  .option("--test-cmd <cmd>", "Override test command for validation")
  .option("--max-iterations <n>", "Maximum patch synthesis iterations", parseInt, 3)
  .option("--model <model>", "Model to use for patch synthesis")
  .option("--db <path>", "SQLite database path (default: <repo>/.kuzushi/findings.sqlite3)")
  .option("--trust-repo-config", "Trust unsafe repo-local config keys", false)
  .action(wrapCliAction(async (repoPath: string, opts: {
    fingerprint: string;
    buildCmd?: string;
    testCmd?: string;
    maxIterations: number;
    model?: string;
    db?: string;
    trustRepoConfig?: boolean;
  }) => {
    const { root: repoRoot, name: repoName } = resolveRepo(repoPath);

    // Load config with optional project-level overlay, then apply CLI overrides.
    const config = loadConfig(repoRoot, { trustProjectConfig: opts.trustRepoConfig === true });
    if (opts.model) config.model = opts.model;

    const model = config.model;

    // Set up DB.
    const dbPath = opts.db ?? defaultDbPath(repoRoot);
    const dbDir = path.dirname(dbPath);
    if (!existsSync(dbDir)) mkdirSync(dbDir, { recursive: true });

    const db = initDb(dbPath);
    try {
      const runtime = configureAgentRuntime(config);
      const { runPatchPipeline } = await import("./patch.js");
      const result = await runPatchPipeline(db, {
        fingerprint: opts.fingerprint,
        repoRoot,
        repoName,
        model,
        runtime,
        maxIterations: opts.maxIterations,
        buildCommand: opts.buildCmd ?? null,
        testCommand: opts.testCmd ?? null,

      });

      console.log("");
      console.log(`Patch pipeline complete for finding: ${opts.fingerprint}`);
      console.log(`  Status:     ${result.patchResult.status}`);
      console.log(`  Iterations: ${result.patchResult.iterations}`);
      console.log(`  Cost:       $${result.costUsd.toFixed(4)}`);
      console.log(`  Run ID:     ${result.patchResult.patchRunId}`);

      if (result.patchResult.status === "SOUND") {
        console.log("");
        console.log("Patch is SOUND. Diff:");
        console.log("---");
        console.log(result.patchResult.diff);
        console.log("---");
      } else {
        console.log("");
        console.log(`Patch did not reach SOUND status. Last status: ${result.patchResult.status}`);
        if (result.patchResult.validatorLog) {
          console.log("");
          console.log("Validator log:");
          console.log(result.patchResult.validatorLog);
        }
      }

      process.exit(result.patchResult.status === "SOUND" ? 0 : 1);
    } finally {
      try { db.close(); } catch { /* best-effort */ }
    }
  }));

// ── list-tasks (shorthand) ────────────────────────────────────────────────

program
  .command("list-tasks")
  .description("List all registered tasks (shorthand for 'task list')")
  .option("-r, --repo <path>", "Repository path", ".")
  .option("--filter <outputKind>", "Filter by output kind")
  .action(async (opts: { repo: string; filter?: string }) => {
    // Delegate to the task list command
    await taskCmd.commands.find((c) => c.name() === "list")!.parseAsync(
      [...(opts.filter ? ["--filter", opts.filter] : []), "-r", opts.repo],
      { from: "user" },
    );
  });

// Graceful shutdown via lifecycle coordinator.
// Hooks are registered with priority: bus drain (1), DB close (2), HTTP cleanup (3).
registerShutdownHook("http-cleanup", async () => {
  await Promise.resolve(cleanupHttpAgents());
}, 10);

process.on("SIGINT", () => void initiateShutdown(130));
process.on("SIGTERM", () => void initiateShutdown(143));
process.on("exit", cleanupHttpAgents);

program.parse();

#!/usr/bin/env node

import { Command } from "commander";
import { mkdirSync, existsSync } from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { loadConfig, getConfigValue, setConfigValue, unsetConfigValue, configPath } from "./config.js";
import { initDb, defaultDbPath } from "./store.js";
import { createDefaultRegistry } from "./scanners/index.js";
import { createDefaultTaskRegistry } from "./agents/index.js";
import { configureAgentRuntime } from "./agent-runtime/index.js";
import {
  createBus,
  registerAllWorkers,
  createEvent,
  generateRunId,
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
  .option("--agent-runtime <backend>", "Agent runtime backend (claude-sdk|acp)")
  .option("--fresh", "Clear prior results before scanning", false)
  .option("--db <path>", "SQLite database path (default: <repo>/.kuzushi/findings.sqlite3)")
  .action(async (repoPath: string, opts: {
    scanners?: string;
    severity?: string;
    max?: number;
    model?: string;
    triageModel?: string;
    triageMaxTurns?: number;
    agentRuntime?: string;
    fresh: boolean;
    db?: string;
  }) => {
    if (!process.env["ANTHROPIC_API_KEY"]) {
      console.error("Error: ANTHROPIC_API_KEY environment variable is required.");
      console.error("Get one at: https://console.anthropic.com/");
      process.exit(1);
    }

    const { root: repoRoot, name: repoName } = resolveRepo(repoPath);

    // Load config with optional project-level overlay, then apply CLI overrides.
    const config = loadConfig(repoRoot);
    if (opts.model) config.model = opts.model;
    if (opts.triageModel) config.triageModel = opts.triageModel;
    if (opts.agentRuntime) {
      config.agentRuntimeBackend = opts.agentRuntime as typeof config.agentRuntimeBackend;
    }
    if (opts.triageMaxTurns !== undefined) {
      if (!Number.isFinite(opts.triageMaxTurns) || opts.triageMaxTurns < 1) {
        console.error("Error: --triage-max-turns must be a positive integer.");
        process.exit(1);
      }
      config.triageMaxTurns = Math.floor(opts.triageMaxTurns);
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

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot,
      repoName,
      dbPath,
    };

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

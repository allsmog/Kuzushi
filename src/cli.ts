#!/usr/bin/env node

import { Command } from "commander";
import { mkdirSync, existsSync } from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createDefaultDeps } from "./deps.js";
import { loadConfig, getConfigValue, setConfigValue, unsetConfigValue, configPath } from "./config.js";
import { initDb, defaultDbPath, getTriagedFingerprints, upsertFinding } from "./store.js";
import { printScanStart, printResumeInfo, printTriageProgress, printSummary } from "./report.js";

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

const program = new Command();

program
  .name("kuzushi")
  .description("Agentic SAST scanner — Semgrep + LLM triage")
  .version("0.1.0");

// ── scan (default command) ────────────────────────────────────────────────

program
  .command("scan", { isDefault: true })
  .description("Scan a repository with Semgrep and triage findings with an LLM")
  .argument("<repo>", "Path to the repository to scan")
  .option("--severity <levels>", "Semgrep severity filter (comma-separated)")
  .option("--max <n>", "Max findings to triage", parseInt)
  .option("--model <model>", "LLM model to use for triage")
  .option("--fresh", "Clear prior results before scanning", false)
  .option("--db <path>", "SQLite database path (default: <repo>/.kuzushi/findings.sqlite3)")
  .action(async (repoPath: string, opts: {
    severity?: string;
    max?: number;
    model?: string;
    fresh: boolean;
    db?: string;
  }) => {
    if (!process.env["ANTHROPIC_API_KEY"]) {
      console.error("Error: ANTHROPIC_API_KEY environment variable is required.");
      console.error("Get one at: https://console.anthropic.com/");
      process.exit(1);
    }

    // Load config, then apply CLI overrides
    const config = loadConfig();
    if (opts.model) config.model = opts.model;

    const { root: repoRoot, name: repoName } = resolveRepo(repoPath);

    // Set up DB
    const dbPath = opts.db ?? defaultDbPath(repoRoot);
    const dbDir = path.dirname(dbPath);
    if (!existsSync(dbDir)) mkdirSync(dbDir, { recursive: true });
    const db = initDb(dbPath);

    const deps = await createDefaultDeps(config);
    const severity = opts.severity
      ? opts.severity.split(",").map((s) => s.trim().toUpperCase())
      : config.severity;

    // Run scanner
    console.log(`\n  Scanning ${repoName}...`);
    const allFindings = await deps.runScanner(repoRoot, {
      severity,
      maxFindings: opts.max,
      excludePatterns: config.excludePatterns,
      fresh: opts.fresh,
    });

    if (allFindings.length === 0) {
      console.log("  No findings from scanner. Code looks clean.");
      db.close();
      return;
    }

    // Filter already-triaged (resume support)
    const alreadyTriaged = opts.fresh ? new Set<string>() : getTriagedFingerprints(db);
    const findings = allFindings.filter((f) => !alreadyTriaged.has(f.fingerprint));

    printScanStart(repoName, findings.length, allFindings.length);
    if (findings.length < allFindings.length) {
      printResumeInfo(allFindings.length - findings.length, findings.length);
    }

    if (findings.length === 0) {
      console.log("  All findings already triaged. Nothing to do.");
      printSummary(db, repoName);
      db.close();
      return;
    }

    // Triage each finding sequentially
    console.log(`  Triaging ${findings.length} findings via ${config.model}...\n`);
    let triaged = 0;

    for (const finding of findings) {
      const filePath = path.isAbsolute(finding.filePath)
        ? finding.filePath
        : path.join(repoRoot, finding.filePath);

      const context = await deps.readFileContext(filePath, finding.startLine, 30);

      try {
        const result = await deps.triageFinding(finding, context, repoName);
        upsertFinding(db, finding, result, repoName, "HEAD");
        triaged++;
        printTriageProgress(result, triaged, findings.length);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`  Error triaging ${finding.fingerprint.slice(0, 12)}: ${msg}`);
      }
    }

    printSummary(db, repoName);
    db.close();
  });

// ── config get/set/unset ──────────────────────────────────────────────────

const configCmd = program
  .command("config")
  .description("Manage kuzushi configuration");

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

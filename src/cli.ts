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

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { Command } from "commander";
import { configureAgentRuntime } from "./agent-runtime/index.js";
import { createDefaultTaskRegistry } from "./agents/index.js";
import { runScanCommand } from "./cli/commands/scan.js";
import { CliUsageError, wrapCliAction } from "./cli/errors.js";
import { resolveRepo } from "./cli/shared.js";
import { formatConfigValidationIssue, validateKuzushiConfig } from "./config/validation.js";
import {
  configPath,
  getConfigValue,
  loadConfig,
  setConfigValue,
  unsetConfigValue,
} from "./config.js";
import { cleanup as cleanupHttpAgents } from "./http-agent.js";
import { initiateShutdown, registerShutdownHook } from "./lifecycle.js";
import { setGlobalLogLevel } from "./logger.js";
import { defaultDbPath, getRun, initDb, listRuns } from "./store.js";

function maybeWarnPlaintextApiKeyStorage(key: string, value: string): void {
  // True if the path (after legacy-retarget) stores an apiKey — either a
  // dotted slot write (claude.apiKey / piAi.apiKey) or a whole-object write
  // whose shape contains apiKey at any depth.
  const isSlotApiKeyPath =
    key === "agentRuntimeConfig.claude.apiKey" ||
    key === "agentRuntimeConfig.piAi.apiKey" ||
    key === "agentRuntimeConfig.apiKey"; // legacy form — retargeted, still worth warning
  let storesApiKey = isSlotApiKeyPath;

  if (!storesApiKey && key === "agentRuntimeConfig") {
    try {
      const parsed = JSON.parse(value) as Record<string, unknown> | null;
      const hasApiKey = (obj: unknown): boolean =>
        typeof obj === "object" &&
        obj !== null &&
        typeof (obj as Record<string, unknown>)["apiKey"] === "string" &&
        (obj as Record<string, string>)["apiKey"].trim().length > 0;
      storesApiKey =
        hasApiKey(parsed) || hasApiKey(parsed?.["claude"]) || hasApiKey(parsed?.["piAi"]);
    } catch {
      storesApiKey = false;
    }
  }

  if (!storesApiKey) {
    return;
  }

  console.warn(
    `Warning: ${key} stores API credentials in plaintext at ${configPath()}. ` +
      "Prefer --api-key for one-off scans or ANTHROPIC_API_KEY from your shell/secret manager.",
  );
}

const program = new Command();

function collectRepeatedOption(value: string, previous: string[] = []): string[] {
  previous.push(value);
  return previous;
}

program
  .name("kuzushi")
  .description("Kuzushi — security-native AI operating environment")
  .option("--verbose", "Show debug-level diagnostics", false)
  .option("--debug", "Expand progressive-disclosure sections and show raw stack traces", false)
  .version((createRequire(import.meta.url)("../package.json") as { version: string }).version);

program.hook("preAction", (_thisCommand, actionCommand) => {
  const opts = actionCommand.optsWithGlobals();
  if (opts.verbose) {
    setGlobalLogLevel("debug");
  }
  if (opts.debug) {
    process.env.KUZUSHI_DEBUG = "1";
  }
});

// ── shell (default command) ──────────────────────────────────────────────

program
  .command("shell", { isDefault: true })
  .description("Interactive security copilot shell")
  .option("--workspace <id>", "Resume a workspace")
  .option("--load <modules>", "Additional modules to load (comma-separated)")
  .option("--target <path>", "Set initial target (repo path, host, URL)")
  .option("--scope <path>", "Load rules of engagement from YAML file")
  .option("--model <model>", "Default model for AI operations")
  .option("--api-key <key>", "Override ANTHROPIC_API_KEY")
  .addHelpText(
    "after",
    `
Examples:
  $ kuzushi                                           # start the shell with default modules
  $ kuzushi shell --target ./acme-api                 # pre-set the scan target
  $ kuzushi shell --load randori,vuln-scout,tob      # pre-load extra built-in modules
  $ kuzushi shell --workspace acme-pentest            # resume a named workspace
  $ kuzushi shell --model anthropic:claude-opus-4-7   # override the default model
`,
  )
  .action(
    wrapCliAction(
      async (opts: {
        workspace?: string;
        load?: string;
        target?: string;
        scope?: string;
        model?: string;
        apiKey?: string;
      }) => {
        const { startShell } = await import("./copilot/shell.js");
        const { loadLocalCredentials, resolveActiveCredentials } = await import("./config.js");
        const config = loadConfig();
        if (opts.model) {
          config.model = opts.model;
        }

        // Project-local credentials (`<cwd>/.kuzushi/credentials.json`)
        // override env-only state so per-project keys "just work". Local
        // credentials files now follow the per-backend shape
        // (`{ claude: {...}, piAi: {...} }`), but legacy flat files are
        // migrated by `loadLocalCredentials` into the claude slot.
        const localCreds = loadLocalCredentials(opts.target ?? process.cwd());
        if (localCreds) {
          const existing = config.agentRuntimeConfig ?? {};
          config.agentRuntimeConfig = {
            claude: { ...(existing.claude ?? {}), ...(localCreds.claude ?? {}) },
            piAi: { ...(existing.piAi ?? {}), ...(localCreds.piAi ?? {}) },
          };
          if (
            !config.agentRuntimeConfig.claude ||
            Object.keys(config.agentRuntimeConfig.claude).length === 0
          ) {
            delete config.agentRuntimeConfig.claude;
          }
          if (
            !config.agentRuntimeConfig.piAi ||
            Object.keys(config.agentRuntimeConfig.piAi).length === 0
          ) {
            delete config.agentRuntimeConfig.piAi;
          }
        }

        // Prime env vars from the active backend's slot so child processes
        // (Claude Code subprocess, pi-ai fetch) inherit the right credentials.
        const active = resolveActiveCredentials(config);
        if (active.apiKey) process.env.ANTHROPIC_API_KEY = active.apiKey;
        if (active.baseUrl) process.env.ANTHROPIC_BASE_URL = active.baseUrl;

        if (opts.apiKey) {
          process.env.ANTHROPIC_API_KEY = opts.apiKey;
        }
        const runtime = configureAgentRuntime(config);
        await startShell({
          config,
          runtime,
          workspace: opts.workspace,
          modules: opts.load
            ?.split(",")
            .map((m) => m.trim())
            .filter(Boolean),
          target: opts.target,
        });
      },
    ),
  );

// ── scan ──────────────────────────────────────────────────────────────────

program
  .command("scan")
  .description("Scan a repository with configured tasks and triage findings with an agent")
  .argument("<repo>", "Path to the repository to scan")
  .option("--preset <name>", "Scan preset: fast, standard, deep")
  .option("--tasks <names>", "Tasks to run (comma-separated task ids)")
  .option("--severity <levels>", "Severity filter (comma-separated)")
  .option("--max <n>", "Max findings to triage", parseInt)
  .option("--model <model>", "Default model to use across tasks and AI stages")
  .option(
    "--ensemble-models <models>",
    "Run eligible agentic detection tasks across multiple models (comma-separated)",
  )
  .option(
    "--task-model <taskId=model>",
    "Override the model for a task or AI stage task id (repeatable)",
    collectRepeatedOption,
    [],
  )

  .option("--verify", "Enable post-triage exploitability verification", false)
  .option("--verify-concurrency <n>", "Override verification concurrency", parseInt)
  .option(
    "--verify-refinement-max-iterations <n>",
    "Maximum verification refinement attempts",
    parseInt,
  )
  .option(
    "--verify-reflection-interval <n>",
    "Inject verification reflection every N failed attempts",
    parseInt,
  )
  .option(
    "--verify-min-confidence <n>",
    "Minimum triage confidence required for verification",
    parseFloat,
  )
  .option("--verify-gate", "Enable LLM verification gate (cheap pre-verification triage)", true)
  .option("--no-verify-gate", "Disable LLM verification gate")
  .option("--crypto-behavioral-test", "Enable crypto behavioral runtime confirmation", false)
  .option("--dynamic-analysis", "Enable dynamic analysis using generated PoC harnesses", false)
  .option(
    "--dynamic-max-candidates <n>",
    "Override maximum number of dynamic analysis candidates",
    parseInt,
  )
  .option("--dynamic-min-score <n>", "Minimum score for dynamic analysis candidates", parseInt)
  .option("--code-graph", "Enable LLM-powered code graph construction and enrichment", false)
  .option("--multi-strategy", "Enable multi-strategy analysis (adaptive mode)", false)
  .option(
    "--multi-strategy-full",
    "Enable multi-strategy analysis (all strategies in parallel)",
    false,
  )
  .option(
    "--multi-strategy-budget <n>",
    "Budget per finding across all strategies in USD",
    parseFloat,
  )
  .option(
    "--multi-strategy-auto-rules",
    "Generate rules from confirmed multi-strategy findings",
    false,
  )
  .option("--taint-diff-base <ref>", "Only taint-analyze files changed since the provided git ref")
  .option("--taint-diff-mode <mode>", "Diff-aware taint mode: delta|baseline")
  .option("--stream", "Enable SSE streaming server for live pipeline events", false)
  .option("--stream-port <n>", "Port for SSE streaming server (0 = auto)", parseInt)
  .option("--github-pr", "Create GitHub fix PRs from verified patches", false)
  .option("--github-comment", "Post findings summary as PR comment", false)
  .option("--auto-patch", "Enable automatic patch generation in pipeline", false)
  .option("--auto-patch-after <trigger>", "Trigger threshold: verify|poc|triage")
  .option("--patch-verify-depth <depth>", "Re-verification depth: task|triage|full")
  .option("--patch-concurrency <n>", "Max concurrent patch synthesis tasks", parseInt)
  .option("--poc-harness", "Enable post-verification PoC harness generation", false)
  .option("--poc-harness-concurrency <n>", "Override PoC harness generation concurrency", parseInt)
  .option(
    "--poc-refinement-max-iterations <n>",
    "Maximum PoC refinement attempts when execution feedback is enabled",
    parseInt,
  )
  .option(
    "--poc-reflection-interval <n>",
    "Inject PoC reflection every N failed attempts",
    parseInt,
  )
  .option("--max-poc-harness-retries <n>", "Retries for PoC harness generation failures", parseInt)
  .option("--max-triage-retries <n>", "Retries for triage agent failures", parseInt)
  .option("--max-verify-retries <n>", "Retries for verification agent failures", parseInt)
  .option("--retry-backoff-ms <n>", "Initial retry backoff in milliseconds", parseInt)
  .option("--no-context", "Disable pre-scan repository context gathering")
  .option("--audit-log", "Persist per-run audit logs to .kuzushi/runs/<runId>/", false)
  .option("--output <path>", "Write markdown report to this path")
  .option("--sarif <path>", "Write SARIF v2.1.0 report to this path")
  .option(
    "--ci",
    "CI mode: disable Ink, print one line per stage transition, default --sarif ./kuzushi.sarif",
    false,
  )
  .option("--json <path>", "Write JSON report to this path")
  .option("--csv <path>", "Write CSV report to this path")
  .option("--jsonl <path>", "Write JSONL report to this path")
  .option("--junit <path>", "Write JUnit XML report to this path (CI test-result aggregation)")
  .option("--agent-runtime <backend>", "Agent runtime backend")
  .option("--api-key <key>", "Override ANTHROPIC_API_KEY for this run")
  .option("--base-url <url>", "Override ANTHROPIC_BASE_URL for this run")
  .option("--list-modules", "Discover and print modules without scanning", false)
  .option("--modules <spec>", 'Manual module list: "name:path,name:path,..."')
  .option("--module-filter <pattern>", "Only scan modules whose names match the pattern")
  .option(
    "--no-module-discovery",
    "Force a single-root scan even when the target looks like a monorepo",
  )
  .option(
    "--module-priority <level>",
    "Only scan modules at or above this security priority: critical, high (default), medium, all",
  )
  .option("--max-modules <n>", "Max modules to scan in Phase 2 (top N by priority)", parseInt)
  .option("--dry-run", "Print scan scope (modules, tasks, tasks) without running", false)
  .option("--enable-external-tasks", "Enable loading of external tasks from config", false)
  .option(
    "--trust-repo-config",
    "Trust unsafe repo-local config keys such as hooks and external tasks",
    false,
  )
  .option("--quality-gate", "Enable quality gates (fail CI on threshold violations)", false)
  .option(
    "--fail-on-tp",
    "Shorthand: fail if any high/critical severity true positive is found",
    false,
  )
  .option("--fresh", "Clear prior results before scanning", false)
  .option("--no-cache", "Disable inflight request deduplication and LLM result caching")
  .option("--resume [runId]", "Resume a previous run (optionally by run id)")
  .option("--db <path>", "SQLite database path (default: <repo>/.kuzushi/findings.sqlite3)")
  .addHelpText(
    "after",
    `
Examples:
  $ kuzushi scan ./repo                                                 # default pipeline
  $ kuzushi scan ./repo --preset deep --verify --auto-patch            # full triage + verify + patch
  $ kuzushi scan ./repo --sarif report.sarif --junit report.xml         # CI-friendly reports
  $ kuzushi scan ./repo --quality-gate --fail-on-tp                     # fail build on high/critical TPs
  $ kuzushi scan ./repo --tasks semgrep,codeql --severity ERROR         # only two tasks, errors only
  $ kuzushi scan ./repo --task-model triage=openai:gpt-4o               # override a single stage's model
  $ kuzushi scan ./repo --resume                                        # resume the most recent run

Exit codes:
  0   Clean (no findings above threshold)
  1   Findings present, or scan produced failures
  2   Usage / config / auth error
  3   Unexpected crash (use --debug for a stack trace)
`,
  )
  .action(wrapCliAction(runScanCommand));

// ── compare-runs ──────────────────────────────────────────────────────────

function fmt(n: number | undefined): string {
  return n != null ? `${(n * 100).toFixed(1)}%` : "n/a";
}

function delta(a: number | undefined, b: number | undefined): string {
  if (a == null || b == null) return "n/a";
  const d = (b - a) * 100;
  return `${(d >= 0 ? "+" : "") + d.toFixed(1)}pp`;
}

program
  .command("compare-runs <id1> <id2>")
  .description("Compare metrics and assertions between two pipeline runs")
  .option("-r, --repo <path>", "Repository path", ".")
  .addHelpText(
    "after",
    `
Examples:
  $ kuzushi compare-runs 2026-04-15-abc 2026-04-17-xyz    # diff two runs
  $ kuzushi compare-runs last-main last-pr -r ./repo      # scoped to a specific repo
`,
  )
  .action(
    wrapCliAction(async (id1: string, id2: string, options: { repo: string }) => {
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
          console.log(
            `  TP Rate: ${fmt(metrics1.tpRate)} -> ${fmt(metrics2.tpRate)} (${delta(metrics1.tpRate, metrics2.tpRate)})`,
          );
          console.log(
            `  FP Rate: ${fmt(metrics1.fpRate)} -> ${fmt(metrics2.fpRate)} (${delta(metrics1.fpRate, metrics2.fpRate)})`,
          );
          console.log(
            `  Avg Confidence: ${fmt(metrics1.averageConfidence)} -> ${fmt(metrics2.averageConfidence)} (${delta(metrics1.averageConfidence, metrics2.averageConfidence)})`,
          );
          console.log(
            `  Total Cost: $${metrics1.costBreakdown?.total?.toFixed(4) ?? "?"} -> $${metrics2.costBreakdown?.total?.toFixed(4) ?? "?"}`,
          );
        }

        // Compare assertions
        const assertions1 = run1.assertionsJson ? JSON.parse(run1.assertionsJson) : null;
        const assertions2 = run2.assertionsJson ? JSON.parse(run2.assertionsJson) : null;
        if (assertions1 || assertions2) {
          console.log("\nAssertion Comparison:");
          if (assertions1?.totalAssertions != null && assertions2?.totalAssertions != null) {
            console.log(
              `  Pass rate: ${assertions1.passedAssertions}/${assertions1.totalAssertions} -> ${assertions2.passedAssertions}/${assertions2.totalAssertions}`,
            );
            console.log(
              `  Avg quality: ${fmt(assertions1.averageQualityScore)} -> ${fmt(assertions2.averageQualityScore)}`,
            );
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
          if (metrics2.averageConfidence < metrics1.averageConfidence * 0.9)
            regressions.push("Average confidence dropped >10%");
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
    }),
  );

// ── config get/set/unset ──────────────────────────────────────────────────

const configCmd = program
  .command("config")
  .description("Manage Kuzushi configuration")
  .addHelpText(
    "after",
    `
Examples:
  $ kuzushi config get                                  # show the full effective config
  $ kuzushi config get model                            # get a single key
  $ kuzushi config set model anthropic:claude-opus-4-7  # set a key (warns on plaintext credentials)
  $ kuzushi config unset model                          # reset a key to default
  $ kuzushi config path                                 # print the config file path
  $ kuzushi config validate --repo ./repo               # preflight: schema + env + binaries
  $ kuzushi config explain model                        # describe a key's shape + default
`,
  );

configCmd
  .command("get")
  .description("Get a config value")
  .argument("[key]", "Config key (omit to show all)")
  .action(
    wrapCliAction((key?: string) => {
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
    }),
  );

configCmd
  .command("set")
  .description("Set a config value")
  .argument("<key>", "Config key")
  .argument("<value>", "Value to set")
  .action(
    wrapCliAction((key: string, value: string) => {
      setConfigValue(key, value);
      console.log(`${key} = ${JSON.stringify(getConfigValue(key))}`);
      maybeWarnPlaintextApiKeyStorage(key, value);
    }),
  );

configCmd
  .command("unset")
  .description("Reset a config key to its default")
  .argument("<key>", "Config key")
  .action(
    wrapCliAction((key: string) => {
      unsetConfigValue(key);
      console.log(`${key} reset to default: ${JSON.stringify(getConfigValue(key))}`);
    }),
  );

configCmd
  .command("path")
  .description("Print config file path")
  .action(() => {
    console.log(configPath());
  });

configCmd
  .command("validate")
  .description("Validate schema + preflight (env vars, scanner binaries, data dir)")
  .option("-r, --repo <path>", "Repository path for project-level config overlay", ".")
  .option("--trust-repo-config", "Trust unsafe repo-local config keys during validation", false)
  .option("--no-preflight", "Skip runtime preflight (credentials, binaries, data dir)")
  .action(
    wrapCliAction(
      async (opts: { repo: string; trustRepoConfig?: boolean; preflight?: boolean }) => {
        const { root } = resolveRepo(opts.repo);
        const config = loadConfig(root, { trustProjectConfig: opts.trustRepoConfig === true });

        const schemaIssues = validateKuzushiConfig(config);
        const { runPreflight, formatPreflightCheck } = await import("./cli/preflight.js");
        const preflight = opts.preflight === false ? null : runPreflight(config, root);

        if (preflight) {
          console.log("Preflight:");
          for (const check of preflight.checks) {
            console.log(`  ${formatPreflightCheck(check)}`);
          }
          console.log();
        }

        const allIssues = [...schemaIssues, ...(preflight?.issues ?? [])];
        const warnings = allIssues.filter((issue) => issue.severity === "warning");
        const errors = allIssues.filter((issue) => issue.severity === "error");

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
          throw new CliUsageError("Configuration errors:", {
            details: errors.map((issue) => `  - ${formatConfigValidationIssue(issue)}`),
          });
        }
      },
    ),
  );

configCmd
  .command("explain")
  .description("Describe a config key's shape, default, and purpose")
  .argument("[key]", "Config key (omit to list all known keys)")
  .action(
    wrapCliAction(async (key?: string) => {
      const { CONFIG_KEY_DOCS, explainConfigKey, listConfigKeys } = await import(
        "./config/docs.js"
      );
      if (!key) {
        for (const entry of listConfigKeys()) {
          const defaultPart = entry.default !== undefined ? ` (default: ${entry.default})` : "";
          console.log(`  ${entry.key.padEnd(32)} ${entry.type}${defaultPart}`);
          console.log(`      ${entry.summary}`);
        }
        console.log(`\n${CONFIG_KEY_DOCS.length} keys documented. Use \`config explain <key>\`.`);
        return;
      }
      const doc = explainConfigKey(key);
      if (!doc) {
        throw new CliUsageError(`Unknown config key: ${key}`);
      }
      console.log(`${doc.key}`);
      console.log(`  Type:     ${doc.type}`);
      if (doc.default !== undefined) console.log(`  Default:  ${doc.default}`);
      if (doc.values) console.log(`  Values:   ${doc.values.join(", ")}`);
      if (doc.envVar) console.log(`  Env var:  ${doc.envVar}`);
      console.log(`  Summary:  ${doc.summary}`);
      if (doc.details) {
        console.log("");
        console.log(doc.details);
      }
    }),
  );

// ── init (bootstrap .kuzushi/) ─────────────────────────────────────────────

program
  .command("init")
  .description(
    "Initialise a Kuzushi workspace: create .kuzushi/, write sensible defaults, print next steps",
  )
  .option("-r, --repo <path>", "Repository path (defaults to cwd)", ".")
  .option("--force", "Overwrite an existing .kuzushi/config.json", false)
  .addHelpText(
    "after",
    `
Examples:
  $ kuzushi init                     # scaffold .kuzushi/ in the current directory
  $ kuzushi init -r ./acme-api       # scaffold in a specific repo root
  $ kuzushi init --force             # overwrite an existing config
`,
  )
  .action(
    wrapCliAction((opts: { repo: string; force?: boolean }) => {
      const { root } = resolveRepo(opts.repo);
      const dataDir = path.join(root, ".kuzushi");
      if (!existsSync(dataDir)) {
        mkdirSync(dataDir, { recursive: true });
      }
      const configFile = path.join(dataDir, "config.json");
      if (existsSync(configFile) && !opts.force) {
        throw new CliUsageError(
          `${configFile} already exists. Use --force to overwrite, or edit in place.`,
        );
      }

      const starter = {
        model: "anthropic:claude-sonnet-4-6",
        agentRuntimeBackend: "claude-code",
        busBackend: "in-process",
        triageBatchSize: 5,
        triageConcurrency: 2,
        scanMode: "parallel",
        tasks: ["semgrep", "triage"],
        severity: ["ERROR", "WARNING"],
        excludePatterns: ["test", "tests", "node_modules", "dist", "build", ".next"],
        verify: false,
        qualityGates: { failOnExploitable: false },
      };
      writeFileSync(configFile, `${JSON.stringify(starter, null, 2)}\n`, "utf-8");

      const envExample = path.join(root, ".env.example");
      if (!existsSync(envExample)) {
        writeFileSync(
          envExample,
          [
            "# Kuzushi agent-runtime credentials. At minimum set ANTHROPIC_API_KEY.",
            "ANTHROPIC_API_KEY=",
            "",
            "# Optional overrides:",
            "# OPENAI_API_KEY=",
            "# GOOGLE_API_KEY=",
            "# KUZUSHI_LOG_LEVEL=info         # debug|info|warn|error",
            "# KUZUSHI_LOG_FORMAT=text        # text|json",
            "",
          ].join("\n"),
          "utf-8",
        );
      }

      console.log(`Initialised ${dataDir}.`);
      console.log("");
      console.log("Next steps:");
      console.log(`  1. Set ANTHROPIC_API_KEY (copy ${envExample} to .env and fill it in).`);
      console.log("  2. Run `kuzushi doctor` to check your environment.");
      console.log("  3. Run `kuzushi config validate -r .` to confirm everything is wired.");
      console.log("  4. Run `kuzushi scan .` for your first scan.");
    }),
  );

// ── create-module (scaffold a third-party CopilotModule) ──────────────────

program
  .command("create-module")
  .description("Scaffold a new CopilotModule project (starter tool + manifest + vitest setup)")
  .argument("<id>", "Module ID (lowercase, dash-separated)")
  .option("--template <name>", "Starter template: offense, defense, or intel", "offense")
  .option("-d, --dir <path>", "Parent directory to create the module in (defaults to cwd)", ".")
  .option("--force", "Overwrite an existing target directory", false)
  .option(
    "--rank <rank>",
    "Reliability tier: manual, low, normal, good, great, excellent",
    "normal",
  )
  .option("--schema-url <url>", "Override the $schema URL in module.manifest.json")
  .option("--skip-peer-deps", "Omit peerDependencies.kuzushi in the generated package.json", false)
  .addHelpText(
    "after",
    `
Examples:
  $ kuzushi create-module my-scanner --template offense
  $ kuzushi create-module honey-net --template defense --dir ./modules
  $ kuzushi create-module attck-lookup --template intel --force
  $ kuzushi create-module beacon --template defense --rank great
`,
  )
  .action(
    wrapCliAction(
      async (
        id: string,
        opts: {
          template: string;
          dir: string;
          force?: boolean;
          rank?: string;
          schemaUrl?: string;
          skipPeerDeps?: boolean;
        },
      ) => {
        const { createModule, isValidTemplate, isValidRank } = await import(
          "./cli/create-module.js"
        );
        if (!isValidTemplate(opts.template)) {
          throw new CliUsageError(
            `Unknown --template "${opts.template}". Valid: offense, defense, intel.`,
          );
        }
        if (opts.rank !== undefined && !isValidRank(opts.rank)) {
          throw new CliUsageError(
            `Unknown --rank "${opts.rank}". Valid: manual, low, normal, good, great, excellent.`,
          );
        }
        const result = createModule({
          id,
          template: opts.template,
          targetDir: path.resolve(opts.dir),
          force: opts.force === true,
          rank: opts.rank as Parameters<typeof createModule>[0]["rank"],
          schemaUrl: opts.schemaUrl,
          skipPeerDeps: opts.skipPeerDeps === true,
        });
        console.log(`Scaffolded ${result.moduleDir}:`);
        for (const file of result.files) console.log(`  ${file}`);
        console.log("");
        console.log("Next steps:");
        console.log(`  $ cd ${path.relative(process.cwd(), result.moduleDir) || "."}`);
        console.log("  $ pnpm install && pnpm build && pnpm test");
        console.log(`  $ kuzushi run ${id}:<tool> --load file://$(pwd)`);
      },
    ),
  );

// ── doctor (runtime preflight summary) ────────────────────────────────────

program
  .command("doctor")
  .description(
    "Run runtime preflight: Node, git, credentials, scanner binaries, data-dir permissions",
  )
  .option("-r, --repo <path>", "Repository path", ".")
  .option("--strict", "Exit non-zero on warnings", false)
  .addHelpText(
    "after",
    `
Examples:
  $ kuzushi doctor                        # print preflight status, exit 0 unless errors
  $ kuzushi doctor --strict               # also fail on warnings (useful in CI)
  $ kuzushi doctor -r ./acme-api          # preflight against a specific repo
`,
  )
  .action(
    wrapCliAction(async (opts: { repo: string; strict?: boolean }) => {
      const { root } = resolveRepo(opts.repo);
      const config = loadConfig(root, { trustProjectConfig: false });
      const { runPreflight, formatPreflightCheck, whichSync } = await import("./cli/preflight.js");
      const report = runPreflight(config, root);

      console.log(`Kuzushi doctor  (repo: ${root})\n`);

      // Also surface Node version + git for completeness
      const nodeRaw = process.version;
      const nodeMajor = parseInt(nodeRaw.replace(/^v/, "").split(".")[0] ?? "0", 10);
      const nodeOk = nodeMajor >= 22;
      console.log(
        `  ${nodeOk ? "[ok]     " : "[MISSING]"} node: ${nodeRaw}${nodeOk ? "" : " (need >= 22)"}`,
      );
      const gitPath = whichSync("git");
      console.log(`  ${gitPath ? "[ok]     " : "[MISSING]"} git: ${gitPath ?? "not on PATH"}`);

      for (const check of report.checks) {
        console.log(`  ${formatPreflightCheck(check)}`);
      }

      const errors = report.issues.filter((i) => i.severity === "error");
      const warnings = report.issues.filter((i) => i.severity === "warning");
      console.log(`\n${errors.length} error(s), ${warnings.length} warning(s).`);

      if (!nodeOk || !gitPath || errors.length > 0) {
        throw new CliUsageError("doctor: one or more required checks failed.");
      }
      if (opts.strict && warnings.length > 0) {
        throw new CliUsageError("doctor: warnings present and --strict was set.");
      }
    }),
  );

// ── docs generate (render markdown docs for loaded modules) ──────────────

program
  .command("docs")
  .description("Module docs generator")
  .addHelpText(
    "after",
    `
Examples:
  $ kuzushi docs generate                      # write docs for every built-in module
  $ kuzushi docs generate --module sast        # single module
  $ kuzushi docs generate --out ./docs/modules # custom output directory
`,
  )
  .command("generate")
  .option("--module <id>", "Only render docs for this module id")
  .option("-o, --out <path>", "Output directory (created if missing)", "docs/modules")
  .option("--load <specifier...>", "Additional module specifiers to load before rendering", [])
  .action(
    wrapCliAction(async (opts: { module?: string; out: string; load?: string[] }) => {
      const { existsSync, mkdirSync, writeFileSync } = await import("node:fs");
      const pathMod = await import("node:path");
      const { CopilotCore } = await import("./copilot/core.js");
      const { createBus } = await import("./bus/adapters/index.js");
      const { resolveRepo } = await import("./cli/shared.js");
      const { root } = resolveRepo(".");
      const config = loadConfig(root, { trustProjectConfig: false });
      const bus = createBus(config);
      const runtime = {} as never;
      const core = new CopilotCore({
        runtime,
        bus,
        config,
        dataDir: pathMod.join(root, ".kuzushi"),
        modules: opts.load ?? [],
      });
      await core.init();

      const outDir = pathMod.resolve(opts.out);
      if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });

      const { generateModuleDoc } = await import("./modules/docs.js");
      const modules = core.listModules().filter((m) => m.loaded);
      const subset = opts.module ? modules.filter((m) => m.id === opts.module) : modules;
      if (subset.length === 0) {
        throw new CliUsageError(
          opts.module
            ? `No loaded module with id '${opts.module}'.`
            : "No modules loaded — nothing to render.",
        );
      }
      for (const info of subset) {
        const mod = core.registry.get(info.id);
        const md = generateModuleDoc(mod, {
          footerNote: `Generated by kuzushi docs generate`,
        });
        const file = pathMod.join(outDir, `${mod.id}.md`);
        writeFileSync(file, md, "utf8");
        console.log(`wrote ${file} (${md.length} bytes)`);
      }
      await core.dispose();
      await bus.close();
    }),
  );

// ── task list/info/validate ────────────────────────────────────────────────

const taskCmd = program
  .command("task")
  .description("Manage and inspect pipeline tasks")
  .addHelpText(
    "after",
    `
Examples:
  $ kuzushi task list                                 # all registered tasks + DAG stages
  $ kuzushi task list --filter findings               # only finding-producing tasks
  $ kuzushi task info sast:verify                     # deep info for one task
  $ kuzushi task validate ./my-external-task.ts       # validate a 3rd-party task file
`,
  );

taskCmd
  .command("list")
  .description("List all registered tasks with their metadata")
  .option("-r, --repo <path>", "Repository path", ".")
  .option(
    "--filter <outputKind>",
    "Filter by output kind (findings|threat-model|verdict|report|custom)",
  )
  .option("--trust-repo-config", "Trust unsafe repo-local config keys while loading tasks", false)
  .action(async (opts: { repo: string; filter?: string; trustRepoConfig?: boolean }) => {
    const { root } = resolveRepo(opts.repo);
    const config = loadConfig(root, { trustProjectConfig: opts.trustRepoConfig === true });
    const taskRegistry = await createDefaultTaskRegistry(config, root);

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
      console.log(`  ${task.id}`);
      console.log(`    Name:       ${task.displayName}`);
      console.log(`    Output:     ${task.outputKind}`);
      console.log(`    Depends on: ${deps}`);
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
  .action(
    wrapCliAction(async (id: string, opts: { repo: string; trustRepoConfig?: boolean }) => {
      const { root } = resolveRepo(opts.repo);
      const config = loadConfig(root, { trustProjectConfig: opts.trustRepoConfig === true });
      const taskRegistry = await createDefaultTaskRegistry(config, root);

      if (!taskRegistry.has(id)) {
        throw new CliUsageError(`Task "${id}" not found.`);
      }

      const task = taskRegistry.get(id);

      console.log(`Task: ${task.id}`);
      console.log(`  Display Name: ${task.displayName}`);
      console.log(`  Output Kind:  ${task.outputKind}`);
      console.log(
        `  Depends On:   ${task.dependsOn.length > 0 ? task.dependsOn.join(", ") : "none"}`,
      );
      console.log(`  Has Condition: ${task.condition ? "yes" : "no"}`);
      console.log(`  Prompt Mode:  ${task.promptMode ?? "full"}`);
    }),
  );

// ── patch ─────────────────────────────────────────────────────────────────

program
  .command("patch")
  .description("Synthesize and validate a security patch for a specific finding")
  .argument("<repo>", "Path to the repository")
  .requiredOption("--fingerprint <fp>", "Finding fingerprint to patch")
  .addHelpText(
    "after",
    `
Examples:
  $ kuzushi patch ./repo --fingerprint abc123def                     # default 3 iterations
  $ kuzushi patch ./repo --fingerprint abc123def --max-iterations 5  # more retry budget
  $ kuzushi patch ./repo --fingerprint abc123def --build-cmd "npm run build" --test-cmd "npm test"
`,
  )
  .option("--build-cmd <cmd>", "Override build command for validation")
  .option("--test-cmd <cmd>", "Override test command for validation")
  .option("--max-iterations <n>", "Maximum patch synthesis iterations", parseInt, 3)
  .option("--model <model>", "Model to use for patch synthesis")
  .option("--db <path>", "SQLite database path (default: <repo>/.kuzushi/findings.sqlite3)")
  .option("--trust-repo-config", "Trust unsafe repo-local config keys", false)
  .action(
    wrapCliAction(
      async (
        repoPath: string,
        opts: {
          fingerprint: string;
          buildCmd?: string;
          testCmd?: string;
          maxIterations: number;
          model?: string;
          db?: string;
          trustRepoConfig?: boolean;
        },
      ) => {
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
            console.log(
              `Patch did not reach SOUND status. Last status: ${result.patchResult.status}`,
            );
            if (result.patchResult.validatorLog) {
              console.log("");
              console.log("Validator log:");
              console.log(result.patchResult.validatorLog);
            }
          }

          process.exit(result.patchResult.status === "SOUND" ? 0 : 1);
        } finally {
          try {
            db.close();
          } catch {
            /* best-effort */
          }
        }
      },
    ),
  );

// ── list-tasks (shorthand) ────────────────────────────────────────────────

program
  .command("list-tasks")
  .description("List all registered tasks (shorthand for 'task list')")
  .option("-r, --repo <path>", "Repository path", ".")
  .option("--filter <outputKind>", "Filter by output kind")
  .action(async (opts: { repo: string; filter?: string }) => {
    // Delegate to the task list command
    await taskCmd.commands
      .find((c) => c.name() === "list")!
      .parseAsync([...(opts.filter ? ["--filter", opts.filter] : []), "-r", opts.repo], {
        from: "user",
      });
  });

// ── run (headless module tool invocation) ────────────────────────────────

program
  .command("run")
  .description("Execute a module tool headlessly (e.g. kuzushi run sast:scan ./repo)")
  .argument("<tool>", "Fully-qualified tool name (module:action)")
  .argument("[args...]", "Tool arguments (positional or key=value pairs)")
  .option("--json", "Output as JSON", false)
  .option("--quiet", "Suppress output (exit code only)", false)
  .option("--input <json>", "Tool input as JSON string")
  .option("--target <path>", "Target override (repo path, host, URL)")
  .option("--workspace <id>", "Workspace to write results to")
  .option("--load <modules>", "Additional modules to load (comma-separated)")
  .option("--model <model>", "Model override for AI operations")
  .option("--api-key <key>", "Override ANTHROPIC_API_KEY for this run")
  .addHelpText(
    "after",
    `
Examples:
  $ kuzushi run sast:scan ./repo --json                                    # JSON output
  $ kuzushi run sast:triage fingerprint=abc123 --quiet                     # just the exit code
  $ kuzushi run tob:skills --json                                          # list resolvable ToB skills
  $ kuzushi run randori:pasta --target ./repo --input '{"stages":["s1","s2"]}'
  $ kuzushi run variant:hunt fingerprint=abc123 --load variant-hunter      # load extra module
  $ kuzushi run vuln-scout:audit --target ./repo --load vuln-scout --json  # headless pentest
`,
  )
  .action(
    wrapCliAction(
      async (
        toolName: string,
        args: string[],
        opts: {
          json?: boolean;
          quiet?: boolean;
          input?: string;
          target?: string;
          workspace?: string;
          load?: string;
          model?: string;
          apiKey?: string;
        },
      ) => {
        const { executeRun, formatRunOutput, parseToolArgs } = await import("./copilot/run.js");
        const { createBus } = await import("./bus/index.js");

        // Build tool input from args or --input
        let input: Record<string, unknown>;
        if (opts.input) {
          try {
            input = JSON.parse(opts.input);
          } catch {
            throw new CliUsageError("Invalid JSON in --input");
          }
        } else {
          input = parseToolArgs(args);
        }

        // Target from positional arg or --target
        if (opts.target && !input.target) {
          input.target = opts.target;
        }

        // Resolve config
        const config = loadConfig();
        if (opts.model) {
          config.model = opts.model;
        }

        // Configure runtime
        if (opts.apiKey) {
          process.env.ANTHROPIC_API_KEY = opts.apiKey;
        }
        const runtime = configureAgentRuntime(config);

        const bus = createBus(config);

        // Data directory
        const dataDir = path.resolve(process.cwd(), ".kuzushi");
        if (!existsSync(dataDir)) {
          mkdirSync(dataDir, { recursive: true });
        }

        const format = opts.quiet
          ? ("quiet" as const)
          : opts.json
            ? ("json" as const)
            : ("text" as const);
        const modules = opts.load
          ?.split(",")
          .map((m) => m.trim())
          .filter(Boolean);

        const result = await executeRun({
          toolName,
          input,
          format,
          cwd: process.cwd(),
          target: opts.target ?? (input.target as string | undefined),
          workspaceId: opts.workspace,
          runtime,
          bus,
          config,
          dataDir,
          modules,
        });

        const output = formatRunOutput(result, format);
        if (output) {
          console.log(output);
        }

        await bus.close();

        if (result.exitCode !== 0) {
          process.exit(result.exitCode);
        }
      },
    ),
  );

// ── runs (inspect previous pipeline runs) ─────────────────────────────────

const runsCmd = program
  .command("runs")
  .description("List and inspect previous scan pipeline runs")
  .addHelpText(
    "after",
    `
Examples:
  $ kuzushi runs list -r ./repo                        # 50 most recent runs
  $ kuzushi runs list --status interrupted --limit 10  # only resumable runs
  $ kuzushi runs show 2026-04-15-abc -r ./repo         # details for one run
  $ kuzushi runs show 2026-04-15-abc --costs           # include cost breakdown
`,
  );

runsCmd
  .command("list")
  .description("List persisted pipeline runs, most recent first")
  .option("-r, --repo <path>", "Repository path", ".")
  .option("--status <status>", "Filter by status (complete|interrupted|failed|running)")
  .option("--limit <n>", "Max runs to list", (v) => parseInt(v, 10), 50)
  .action(
    wrapCliAction((opts: { repo: string; status?: string; limit: number }) => {
      const { root } = resolveRepo(opts.repo);
      const dbPath = defaultDbPath(root);
      if (!existsSync(dbPath)) {
        console.log(`No runs database at ${dbPath}. Run \`kuzushi scan ${opts.repo}\` first.`);
        return;
      }
      const db = initDb(dbPath);
      try {
        const runs = listRuns(db, {
          repo: undefined,
          status: opts.status,
          limit: opts.limit,
        });
        if (runs.length === 0) {
          console.log("No runs found.");
          return;
        }
        console.log(`Runs in ${dbPath}:\n`);
        for (const run of runs) {
          const started = run.startedAt ?? "?";
          const cost =
            typeof run.totalCostUsd === "number" ? `$${run.totalCostUsd.toFixed(4)}` : "n/a";
          console.log(
            `  ${run.runId.padEnd(40)} ${(run.status ?? "?").padEnd(12)} ${started.padEnd(24)} cost=${cost}`,
          );
        }
        console.log(`\n${runs.length} run(s).`);
      } finally {
        db.close();
      }
    }),
  );

runsCmd
  .command("show")
  .description("Show details for a specific run")
  .argument("<runId>", "Run ID")
  .option("-r, --repo <path>", "Repository path", ".")
  .option("--costs", "Include cost breakdown from metrics", false)
  .option("--json", "Output as JSON", false)
  .action(
    wrapCliAction((runId: string, opts: { repo: string; costs?: boolean; json?: boolean }) => {
      const { root } = resolveRepo(opts.repo);
      const dbPath = defaultDbPath(root);
      if (!existsSync(dbPath)) {
        throw new CliUsageError(`No runs database at ${dbPath}.`);
      }
      const db = initDb(dbPath);
      try {
        const run = getRun(db, runId);
        if (!run) {
          throw new CliUsageError(`Run not found: ${runId}`);
        }
        if (opts.json) {
          console.log(JSON.stringify(run, null, 2));
          return;
        }
        console.log(`Run: ${run.runId}`);
        console.log(`  Repo:        ${run.repo}`);
        console.log(`  Status:      ${run.status ?? "?"}`);
        console.log(`  Started:     ${run.startedAt ?? "?"}`);
        if (run.completedAt) console.log(`  Completed:   ${run.completedAt}`);
        console.log(
          `  Total cost:  ${typeof run.totalCostUsd === "number" ? `$${run.totalCostUsd.toFixed(4)}` : "n/a"}`,
        );
        if (run.promptHash) console.log(`  Prompt hash: ${run.promptHash}`);
        if (opts.costs && run.metricsJson) {
          const metrics = JSON.parse(run.metricsJson) as {
            costBreakdown?: Record<string, number | undefined>;
          };
          if (metrics.costBreakdown) {
            console.log("\n  Cost breakdown:");
            for (const [stage, value] of Object.entries(metrics.costBreakdown)) {
              if (typeof value === "number")
                console.log(`    ${stage.padEnd(20)} $${value.toFixed(4)}`);
            }
          }
        }
      } finally {
        db.close();
      }
    }),
  );

// ── intel (security intelligence management) ──────────────────────────────

const intelCmd = program
  .command("intel")
  .description("Manage the security intelligence store (CVEs, ATT&CK, CAPEC, custom docs)")
  .addHelpText(
    "after",
    `
Examples:
  $ kuzushi intel search "SSRF metadata"             # semantic search across the store
  $ kuzushi intel search "RCE" --source nvd --limit 5
  $ kuzushi intel add ./notes/cve-2025-12345.md --source custom
  $ kuzushi intel stats                              # counts by source
`,
  );

intelCmd
  .command("search")
  .description("Search the intel store")
  .argument("<query>", "Search query")
  .option(
    "--source <source>",
    "Filter by source (nvd, attack, capec, cwe, compliance, findings, custom)",
  )
  .option("--limit <n>", "Max results", "10")
  .action(
    wrapCliAction(async (query: string, searchOpts: { source?: string; limit: string }) => {
      const dataDir = path.resolve(process.cwd(), ".kuzushi");
      const dbPath = path.join(dataDir, "intel.sqlite3");
      if (!existsSync(dbPath)) {
        console.log("No intel store found. Run `kuzushi intel add <file>` to ingest documents.");
        return;
      }
      const Database = (await import("better-sqlite3")).default;
      const { createIntelTables, SqliteIntelStore } = await import("./intel/store.js");
      const db = new Database(dbPath);
      createIntelTables(db);
      const store = new SqliteIntelStore(db);

      const results = store.search(query, {
        limit: parseInt(searchOpts.limit, 10),
        sources: searchOpts.source
          ? [searchOpts.source as import("./intel/types.js").IntelSource]
          : undefined,
      });

      if (results.length === 0) {
        console.log("No results found.");
        return;
      }

      for (const r of results) {
        console.log(`\n  ${r.document.title} [${r.document.source}]`);
        if (r.snippet) console.log(`  ${r.snippet}`);
      }
      console.log(`\n  ${results.length} result(s)`);
    }),
  );

intelCmd
  .command("add")
  .description("Ingest a document into the intel store")
  .argument("<file>", "Path to a text file to ingest")
  .option("--source <source>", "Source type", "custom")
  .option("--title <title>", "Document title (defaults to filename)")
  .action(
    wrapCliAction(async (file: string, addOpts: { source: string; title?: string }) => {
      const { readFileSync } = await import("node:fs");
      const dataDir = path.resolve(process.cwd(), ".kuzushi");
      if (!existsSync(dataDir)) mkdirSync(dataDir, { recursive: true });
      const dbPath = path.join(dataDir, "intel.sqlite3");

      const Database = (await import("better-sqlite3")).default;
      const { createIntelTables, SqliteIntelStore } = await import("./intel/store.js");
      const db = new Database(dbPath);
      db.pragma("journal_mode = WAL");
      createIntelTables(db);
      const store = new SqliteIntelStore(db);

      const content = readFileSync(path.resolve(file), "utf-8");
      const title = addOpts.title ?? path.basename(file);
      const id = store.ingest({
        source: addOpts.source as import("./intel/types.js").IntelSource,
        title,
        content,
        metadata: { originalPath: file },
      });

      console.log(`Ingested: ${title} (${id.slice(0, 8)}) — ${content.length} chars`);
    }),
  );

intelCmd
  .command("stats")
  .description("Show intel store statistics")
  .action(
    wrapCliAction(async () => {
      const dataDir = path.resolve(process.cwd(), ".kuzushi");
      const dbPath = path.join(dataDir, "intel.sqlite3");
      if (!existsSync(dbPath)) {
        console.log("No intel store found.");
        return;
      }
      const Database = (await import("better-sqlite3")).default;
      const { createIntelTables, SqliteIntelStore } = await import("./intel/store.js");
      const db = new Database(dbPath);
      createIntelTables(db);
      const store = new SqliteIntelStore(db);

      const sources = [
        "nvd",
        "attack",
        "capec",
        "cwe",
        "compliance",
        "findings",
        "custom",
      ] as const;
      const total = store.count();
      console.log(`\n  Intel Store: ${total} documents`);
      for (const source of sources) {
        const count = store.count(source);
        if (count > 0) console.log(`    ${source.padEnd(12)} ${count}`);
      }
      console.log();
    }),
  );

// Graceful shutdown via lifecycle coordinator.
// Hooks are registered with priority: bus drain (1), DB close (2), HTTP cleanup (3).
registerShutdownHook(
  "http-cleanup",
  async () => {
    await Promise.resolve(cleanupHttpAgents());
  },
  10,
);

process.on("SIGINT", () => void initiateShutdown(130));
process.on("SIGTERM", () => void initiateShutdown(143));
process.on("exit", cleanupHttpAgents);

program.parse();

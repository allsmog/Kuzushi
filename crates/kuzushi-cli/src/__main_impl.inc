use std::env;
use std::fs;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use kuzushi_core::config::write_default_config;
use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::{
    append_run_trace_step, build_pr_comment, build_whitebox_suppression_for_finding,
    list_run_summaries, load_config_for_target, load_run_summary, load_whitebox_suppressions,
    new_run_id, resolve_finding_alias, stable_finding_alias, upsert_whitebox_suppression,
    whitebox_suppression_store_path, write_run_artifact_json, write_run_summary, AgentRuntime,
    FindingDetailReport, FindingListFilter, FindingStore, ModuleRegistry, PrCommentInput,
    RunSummary, RunTraceStep, WhiteboxSuppressionRecord, WorkspaceTarget,
};
use kuzushi_openai::PiAgentCoreRuntime;
use kuzushi_tui::run_shell_with_plain;

#[derive(Debug, Parser)]
#[command(name = "kuzushi")]
#[command(about = "Kuzushi security-native code agent", version)]
struct Cli {
    #[arg(long, global = true)]
    target: Option<PathBuf>,
    /// Force line-oriented output with no ANSI, animation, or box drawing.
    #[arg(long, global = true)]
    plain: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the interactive shell.
    Shell {
        #[arg(long)]
        target: Option<PathBuf>,
    },
    /// Run configured scanners and persist findings.
    Scan {
        target: PathBuf,
        #[arg(long, value_enum, default_value_t = ScanModeArg::Standard)]
        mode: ScanModeArg,
        #[arg(long, value_delimiter = ',')]
        tasks: Vec<String>,
        #[arg(long)]
        triage: bool,
        #[arg(long)]
        json: bool,
        /// Emit one line per pipeline event in a deterministic, grep-friendly format.
        #[arg(long, conflicts_with = "json")]
        ci: bool,
        /// Per-operation USD budget caps, e.g. `triage=50,deep-audit=200,full-mode-multi=300`.
        /// Caps are persisted to the spend ledger and enforced before each LLM call
        /// once the runtime is wired through (Phase 4+). Set without value to clear all caps.
        #[arg(long)]
        budget: Option<String>,
        /// Diff-scope the scan to files changed since `<ref>`. Engines that
        /// support it (full-mode-multi today) narrow their walk; others are
        /// unaffected. Pass `--include-worktree` to include uncommitted edits.
        #[arg(long)]
        since: Option<String>,
        /// When `--since` is set, also include uncommitted (working-tree) changes.
        #[arg(long, requires = "since")]
        include_worktree: bool,
    },
    /// List persisted findings.
    Findings {
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long, value_delimiter = ',')]
        severity: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        verdict: Vec<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long = "file-path")]
        file_path: Option<String>,
        /// Filter by discovery channel: sarif, ainalysis, ainalysis-multi,
        /// diff-analyzer, infer, fuzzing. Comma- or repeat-separated.
        #[arg(long = "vuln-source", value_delimiter = ',')]
        vuln_source: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Inspect one persisted finding by alias, fingerprint, or fingerprint prefix.
    Finding {
        reference: String,
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Inspect replayable run artifacts under `.kuzushi/runs`.
    Runs {
        #[command(subcommand)]
        command: RunsCommand,
    },
    /// Add an expiring, evidence-backed suppression for a finding.
    Suppress {
        reference: String,
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        reason: String,
        #[arg(long, default_value = "operator")]
        author: String,
        #[arg(long, default_value_t = 90)]
        days: u64,
        #[arg(long)]
        json: bool,
    },
    /// List whitebox/static suppressions and their audit store.
    Suppressions {
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Show the current CLI/shell permission and sandbox policy summary.
    Permissions {
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Inspect or initialize config.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Diagnostic credential subcommands. For interactive OAuth login,
    /// use `kuzushi shell` then `auth login openai-codex` or
    /// `auth login anthropic`.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// List native modules.
    Modules {
        #[arg(long)]
        json: bool,
    },
    /// List native tools.
    Tools {
        #[arg(long)]
        json: bool,
    },
    /// Run Rust CLI preflight diagnostics.
    Doctor {
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Execute a native tool descriptor-backed command. Use an explicit
    /// `module:tool`; shell-only `run .` needs focused module state.
    Run {
        tool: String,
        #[arg(long, default_value = "{}")]
        input: String,
    },
    /// Run a local MCP server (joern, clang, or gtags) over stdio.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Render a markdown PR comment summarising persisted findings.
    PrComment {
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long)]
        run_url: Option<String>,
        #[arg(long, default_value_t = 10)]
        top_n: usize,
        #[arg(long, value_delimiter = ',')]
        changed_files: Vec<String>,
        #[arg(long)]
        run_id: Option<String>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        git_sha: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ScanModeArg {
    Standard,
    WhiteboxStatic,
}

impl ScanModeArg {
    fn as_input_value(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::WhiteboxStatic => "whitebox-static",
        }
    }
}

#[derive(Debug, Subcommand)]
enum McpCommand {
    /// Run an MCP server over stdio. Speaks JSON-RPC 2.0 newline-delimited.
    Serve {
        /// Which backend to serve.
        #[arg(value_enum)]
        backend: McpBackend,
    },
    /// Print a JSON health summary for the chosen backend (no MCP loop).
    Health {
        #[arg(value_enum)]
        backend: McpBackend,
    },
}

#[derive(Debug, Subcommand)]
enum RunsCommand {
    /// List run summaries.
    List {
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Show one run summary.
    Show {
        run_id: String,
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Print a run's trace JSONL.
    Trace {
        run_id: String,
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum McpBackend {
    Gtags,
    Clang,
    Joern,
}

impl McpBackend {
    fn binary(self) -> &'static str {
        match self {
            Self::Gtags => "kuzushi-mcp-gtags",
            Self::Clang => "kuzushi-mcp-clang",
            Self::Joern => "kuzushi-mcp-joern",
        }
    }
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Print the effective config.
    Show,
    /// Write the global config if it does not already exist.
    Init {
        #[arg(long)]
        force: bool,
    },
    /// Print the global config path.
    Path,
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    /// Round-trip a 1-token request to verify credentials, network, and bridge.
    Ping {
        /// Provider to ping. Default: anthropic.
        #[arg(default_value = "anthropic")]
        provider: String,
        /// Model spec to use for the ping. Default: ctx.config.model or anthropic:claude-haiku-4-5.
        #[arg(long)]
        model: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let plain = plain_output_requested(cli.plain);
    let command = cli.command.unwrap_or(Command::Shell { target: None });

    match command {
        Command::Shell { target } => {
            let target = target.or(cli.target);
            // Resolve the workspace before printing boot progress. Otherwise
            // a bad --target path prints "first finding: scan ..." (which
            // can never run) and only then bails out — confusing the
            // operator into thinking the scan was almost ready.
            let workspace = target
                .as_deref()
                .map(WorkspaceTarget::new)
                .transpose()
                .context("Could not resolve shell target")?;
            if should_emit_shell_startup_progress(plain) {
                for line in shell_startup_progress_messages(target.as_deref()) {
                    eprintln!("{line}");
                }
            }
            let config = load_config_for_target(workspace.as_ref().map(WorkspaceTarget::root))?;
            run_shell_with_plain(config, workspace.as_ref(), plain)
        }
        Command::Scan {
            target,
            mode,
            tasks,
            triage,
            json,
            ci,
            budget,
            since,
            include_worktree,
        } => {
            scan_command(
                target,
                mode,
                tasks,
                triage,
                json,
                ci,
                budget,
                since,
                include_worktree,
            )
            .await
        }
        Command::Findings {
            target,
            limit,
            severity,
            verdict,
            name,
            file_path,
            vuln_source,
            json,
        } => findings_command(
            target.or(cli.target),
            FindingListFilter::from_parts_full(
                severity,
                verdict,
                name,
                file_path,
                vuln_source,
                limit,
            )?,
            json,
        ),
        Command::Finding {
            reference,
            target,
            json,
        } => finding_command(target.or(cli.target), reference, json),
        Command::Runs { command } => runs_command(command, cli.target),
        Command::Suppress {
            reference,
            target,
            reason,
            author,
            days,
            json,
        } => suppress_command(target.or(cli.target), reference, reason, author, days, json),
        Command::Suppressions { target, json } => suppressions_command(target.or(cli.target), json),
        Command::Permissions { target, json } => permissions_command(target.or(cli.target), json),
        Command::Config { command } => config_command(command, cli.target),
        Command::Auth { command } => auth_command(command, cli.target),
        Command::Modules { json } => modules_command(json),
        Command::Tools { json } => tools_command(json),
        Command::Doctor { target, json } => doctor_command(target.or(cli.target), json),
        Command::Run { tool, input } => run_tool_command(tool, input, cli.target),
        Command::Mcp { command } => mcp_command(command).await,
        Command::PrComment {
            target,
            repo,
            run_url,
            top_n,
            changed_files,
            run_id,
            model,
            git_sha,
        } => pr_comment_command(
            target.or(cli.target),
            repo,
            run_url,
            top_n,
            changed_files,
            run_id,
            model,
            git_sha,
        ),
    }
}

fn plain_output_requested(flag: bool) -> bool {
    flag || std::env::var_os("KUZUSHI_PLAIN").is_some()
        || std::env::var_os("KUZUSHI_SCREEN_READER").is_some()
        || std::env::var_os("KUZUSHI_LOW_BANDWIDTH").is_some()
}

fn should_emit_shell_startup_progress(plain: bool) -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal() && io::stderr().is_terminal() && !plain
}

fn shell_startup_progress_messages(target: Option<&Path>) -> Vec<String> {
    let target_label = target
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "none".to_string());
    let scan_command = if target.is_some() { "scan" } else { "scan ." };
    vec![
        "kuzushi: loading config and native registry...".to_string(),
        format!("kuzushi: target {target_label}; first finding: {scan_command}, then findings"),
    ]
}

async fn mcp_command(command: McpCommand) -> Result<()> {
    match command {
        McpCommand::Serve { backend } => serve_mcp_backend(backend),
        McpCommand::Health { backend } => health_mcp_backend(backend),
    }
}

fn serve_mcp_backend(backend: McpBackend) -> Result<()> {
    let binary = backend.binary();
    let status = std::process::Command::new(binary)
        .args::<[&str; 0], _>([])
        .status()
        .with_context(|| mcp_spawn_error(binary))?;
    std::process::exit(status.code().unwrap_or(0));
}

fn health_mcp_backend(backend: McpBackend) -> Result<()> {
    let binary = backend.binary();
    let output = std::process::Command::new(binary)
        .arg("--health")
        .output()
        .with_context(|| mcp_health_spawn_error(binary))?;
    write_mcp_output(&output.stdout, &output.stderr);
    std::process::exit(output.status.code().unwrap_or(0));
}

fn mcp_spawn_error(binary: &str) -> String {
    format!(
        "could not spawn `{binary}`. Build the workspace and add the target dir to PATH (e.g. `cargo build && export PATH=$PWD/target/debug:$PATH`)"
    )
}

fn mcp_health_spawn_error(binary: &str) -> String {
    format!(
        "could not spawn `{binary} --health`. Build the workspace and add the target dir to PATH."
    )
}

fn write_mcp_output(stdout: &[u8], stderr: &[u8]) {
    std::io::Write::write_all(&mut std::io::stdout(), stdout).ok();
    std::io::Write::write_all(&mut std::io::stderr(), stderr).ok();
}

fn pr_comment_command(
    target: Option<PathBuf>,
    repo: Option<String>,
    run_url: Option<String>,
    top_n: usize,
    changed_files: Vec<String>,
    run_id: Option<String>,
    model: Option<String>,
    git_sha: Option<String>,
) -> Result<()> {
    let target = target.unwrap_or_else(|| PathBuf::from("."));
    let workspace = WorkspaceTarget::new(target)?;
    let input = load_pr_comment_input(
        &workspace,
        repo,
        run_url,
        top_n,
        changed_files,
        run_id,
        model,
        git_sha,
    )?;
    println!("{}", build_pr_comment(&input));
    Ok(())
}

fn load_pr_comment_input(
    workspace: &WorkspaceTarget,
    repo: Option<String>,
    run_url: Option<String>,
    top_n: usize,
    changed_files: Vec<String>,
    run_id: Option<String>,
    model: Option<String>,
    git_sha: Option<String>,
) -> Result<PrCommentInput> {
    let store = FindingStore::open(workspace.findings_db_path())?;
    let report = store.list_findings_filtered(&FindingListFilter::default())?;
    Ok(PrCommentInput {
        repo_name: repo.or_else(|| {
            workspace
                .root()
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string)
        }),
        findings: report.findings,
        cost_usd: 0.0,
        elapsed: None,
        run_url,
        top_n: Some(top_n),
        kuzushi_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        model,
        git_sha,
        run_id,
        changed_files,
    })
}

async fn scan_command(
    target: PathBuf,
    mode: ScanModeArg,
    tasks: Vec<String>,
    triage: bool,
    json: bool,
    ci: bool,
    budget: Option<String>,
    since: Option<String>,
    include_worktree: bool,
) -> Result<()> {
    let workspace = WorkspaceTarget::new(&target)?;
    let config = load_config_for_target(Some(workspace.root()))?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let registry = ModuleRegistry::with_v2_builtins();

    apply_scan_since_scope(&workspace, since.as_deref(), include_worktree, json, ci)?;
    apply_scan_budget_caps(&workspace, budget.as_deref(), json, ci)?;
    let input = scan_tool_input(mode, &tasks, triage);
    let runtime = scan_runtime(&config, &input)?;
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
    };

    let started = std::time::Instant::now();
    emit_scan_ci_start(ci, started, &target, &config, &tasks);

    let result = registry.execute_tool_with_runtime(
        "sast:scan",
        input,
        &ctx,
        runtime.as_ref().map(|runtime| runtime as &dyn AgentRuntime),
    );
    let elapsed = started.elapsed();
    let result = scan_result_or_report_ci_error(result, ci, started, elapsed)?;
    emit_scan_output(&workspace, &result, json, ci, started, elapsed)
}

fn apply_scan_since_scope(
    workspace: &WorkspaceTarget,
    since: Option<&str>,
    include_worktree: bool,
    json: bool,
    ci: bool,
) -> Result<()> {
    let Some(since_ref) = since else {
        return Ok(());
    };
    let scope = kuzushi_core::git_diff_files(workspace.root(), since_ref, include_worktree)
        .with_context(|| format!("--since {since_ref:?} failed"))?;
    let scope_file = workspace.findings_db_path().with_file_name("since.txt");
    std::fs::write(&scope_file, scan_scope_body(&scope.files))
        .with_context(|| format!("could not write {}", scope_file.display()))?;
    emit_scan_scope_line(&scope.files, since_ref, include_worktree, json, ci);
    Ok(())
}

fn scan_scope_body(files: &[PathBuf]) -> String {
    files.iter().map(|p| format!("{}\n", p.display())).collect()
}

fn emit_scan_scope_line(
    files: &[PathBuf],
    since_ref: &str,
    include_worktree: bool,
    json: bool,
    ci: bool,
) {
    if !json && !ci {
        eprintln!(
            "scope: {} files since {} {}",
            files.len(),
            since_ref,
            scan_worktree_suffix(include_worktree)
        );
    }
}

fn scan_worktree_suffix(include_worktree: bool) -> &'static str {
    if include_worktree {
        "(+worktree)"
    } else {
        ""
    }
}

fn apply_scan_budget_caps(
    workspace: &WorkspaceTarget,
    budget: Option<&str>,
    json: bool,
    ci: bool,
) -> Result<()> {
    let Some(spec) = budget else {
        return Ok(());
    };
    let pairs = kuzushi_core::parse_budget_flag(spec)
        .with_context(|| format!("invalid --budget spec {spec:?}"))?;
    let limiter = kuzushi_core::SpendLimiter::open(workspace.findings_db_path())
        .context("could not open spend ledger")?;
    for (op, cap) in &pairs {
        limiter
            .set_cap(*op, *cap)
            .with_context(|| format!("could not set cap for {}", op.as_db_str()))?;
    }
    emit_scan_budget_lines(&pairs, json, ci);
    Ok(())
}

fn emit_scan_budget_lines(pairs: &[(kuzushi_core::SpendOperation, f64)], json: bool, ci: bool) {
    if should_emit_scan_budget_lines(json, ci) {
        write_scan_budget_lines(pairs);
    }
}

fn should_emit_scan_budget_lines(json: bool, ci: bool) -> bool {
    !json && !ci
}

fn write_scan_budget_lines(pairs: &[(kuzushi_core::SpendOperation, f64)]) {
    for (op, cap) in pairs {
        eprintln!("budget: {} = ${:.2}", op.as_db_str(), cap);
    }
}

fn scan_tool_input(mode: ScanModeArg, tasks: &[String], triage: bool) -> serde_json::Value {
    serde_json::json!({
        "mode": mode.as_input_value(),
        "taskMode": scan_task_mode(tasks),
        "tasks": tasks,
        "triage": triage,
    })
}

fn scan_task_mode(tasks: &[String]) -> &'static str {
    if tasks.is_empty() {
        "auto"
    } else {
        "manual"
    }
}

fn scan_runtime(
    config: &kuzushi_core::V2Config,
    input: &serde_json::Value,
) -> Result<Option<PiAgentCoreRuntime>> {
    if wants_sast_runtime(input) {
        Ok(Some(PiAgentCoreRuntime::from_config(
            config,
            std::env::current_dir()?,
        )?))
    } else {
        Ok(None)
    }
}

fn emit_scan_ci_start(
    ci: bool,
    started: std::time::Instant,
    target: &Path,
    config: &kuzushi_core::V2Config,
    tasks: &[String],
) {
    if ci {
        println!(
            "{}",
            ci_line(started, "scan", &scan_started_body(target, config, tasks))
        );
        println!("{}", ci_line(started, "phase", "(init) → scanning"));
    }
}

fn scan_started_body(target: &Path, config: &kuzushi_core::V2Config, tasks: &[String]) -> String {
    format!(
        "{} started [model={} tasks={}]",
        target.display(),
        config.model.as_deref().unwrap_or("unconfigured"),
        scan_tasks_label(tasks),
    )
}

fn scan_tasks_label(tasks: &[String]) -> String {
    if tasks.is_empty() {
        "auto".to_string()
    } else {
        tasks.join(",")
    }
}

fn scan_result_or_report_ci_error(
    result: Result<serde_json::Value>,
    ci: bool,
    started: std::time::Instant,
    elapsed: std::time::Duration,
) -> Result<serde_json::Value> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            emit_scan_ci_error(ci, started, elapsed, &error);
            Err(error)
        }
    }
}

fn emit_scan_ci_error(
    ci: bool,
    started: std::time::Instant,
    elapsed: std::time::Duration,
    error: &anyhow::Error,
) {
    if ci {
        println!(
            "{}",
            ci_line(
                started,
                "phase",
                &format!("scanning → failed ({})", format_duration(elapsed))
            )
        );
        println!("{}", ci_line(started, "error", &error.to_string()));
        println!("{}", ci_line(started, "exit", "1"));
    }
}

fn emit_scan_output(
    workspace: &WorkspaceTarget,
    result: &serde_json::Value,
    json: bool,
    ci: bool,
    started: std::time::Instant,
    elapsed: std::time::Duration,
) -> Result<()> {
    let data = scan_result_data(result);
    if ci {
        emit_scan_ci_success(result, &data, started, elapsed);
        return Ok(());
    }
    if json {
        println!("{}", scan_json_output(workspace, &data));
    } else if let Some(output) = result.get("output").and_then(serde_json::Value::as_str) {
        println!("{output}");
    }
    Ok(())
}

fn scan_result_data(result: &serde_json::Value) -> serde_json::Value {
    result
        .get("data")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}))
}

fn emit_scan_ci_success(
    result: &serde_json::Value,
    data: &serde_json::Value,
    started: std::time::Instant,
    elapsed: std::time::Duration,
) {
    println!(
        "{}",
        ci_line(
            started,
            "phase",
            &format!("scanning → done ({})", format_duration(elapsed))
        )
    );
    println!(
        "{}",
        ci_line(
            started,
            "summary",
            &format!(
                "{} finding(s) · ${:.4} · {}",
                scan_findings_count(data),
                scan_cost_usd(result),
                format_duration(elapsed)
            )
        )
    );
    println!("{}", ci_line(started, "exit", "0"));
}

fn scan_findings_count(data: &serde_json::Value) -> u64 {
    data.get("findingsCount")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

fn scan_cost_usd(result: &serde_json::Value) -> f64 {
    result
        .get("costUsd")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0)
}

fn scan_json_output(workspace: &WorkspaceTarget, data: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "runId": data.get("runId").cloned(),
        "target": data.get("target").cloned(),
        "findingsCount": data.get("findingsCount").cloned(),
        "db": workspace.findings_db_path(),
        "mode": data.get("mode").cloned(),
        "whiteboxStatic": data.get("whiteboxStatic").cloned(),
        "triage": data.get("triage").cloned(),
    })
}

fn ci_line(started: std::time::Instant, prefix: &str, body: &str) -> String {
    let elapsed = started.elapsed();
    format!("[+{:.1}s] {prefix}: {body}", elapsed.as_secs_f64())
}

fn format_duration(elapsed: std::time::Duration) -> String {
    let secs = elapsed.as_secs();
    if secs >= 60 {
        let minutes = secs / 60;
        let rem = secs % 60;
        format!("{minutes}m {rem}s")
    } else {
        format!("{:.1}s", elapsed.as_secs_f64())
    }
}

fn findings_command(target: Option<PathBuf>, filter: FindingListFilter, json: bool) -> Result<()> {
    let target = target.unwrap_or_else(|| PathBuf::from("."));
    let workspace = WorkspaceTarget::new(target)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let report = store.list_findings_filtered(&filter)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if report.findings.is_empty() {
        println!(
            "no findings found at {}\nNext: kuzushi scan {}",
            workspace.findings_db_path().display(),
            workspace.root().display()
        );
    } else {
        println!("{}", report.output());
    }
    Ok(())
}

fn finding_command(target: Option<PathBuf>, reference: String, json: bool) -> Result<()> {
    let target = target.unwrap_or_else(|| PathBuf::from("."));
    let workspace = WorkspaceTarget::new(target)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let all_findings = store
        .list_findings_filtered(&FindingListFilter::with_limit(FindingListFilter::MAX_LIMIT))?
        .findings;

    let finding = if let Some(alias_finding) = resolve_finding_alias(&all_findings, &reference) {
        store
            .get_finding_by_fingerprint(&alias_finding.fingerprint)?
            .unwrap_or(alias_finding)
    } else {
        store
            .get_finding_by_reference(&reference)?
            .with_context(|| {
                format!(
                    "no finding found for {reference:?} at {}\nNext: kuzushi findings --target {}",
                    workspace.findings_db_path().display(),
                    workspace.root().display()
                )
            })?
    };
    let alias = stable_finding_alias(&all_findings, &finding.fingerprint);
    let patch_results = store.get_patch_results_for_finding(&finding.fingerprint)?;
    let report = FindingDetailReport::new(alias, finding, patch_results);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", report.output());
    }
    Ok(())
}

fn runs_command(command: RunsCommand, global_target: Option<PathBuf>) -> Result<()> {
    match command {
        RunsCommand::List { target, json } => runs_list_command(target.or(global_target), json),
        RunsCommand::Show {
            run_id,
            target,
            json,
        } => runs_show_command(target.or(global_target), &run_id, json),
        RunsCommand::Trace {
            run_id,
            target,
            json,
        } => runs_trace_command(target.or(global_target), &run_id, json),
    }
}

fn runs_list_command(target: Option<PathBuf>, json: bool) -> Result<()> {
    let workspace = WorkspaceTarget::new(target.unwrap_or_else(|| PathBuf::from(".")))?;
    let runs = list_run_summaries(workspace.root())?;
    print!("{}", runs_list_output(&workspace, &runs, json)?);
    Ok(())
}

fn runs_list_output(
    workspace: &WorkspaceTarget,
    runs: &[RunSummary],
    json: bool,
) -> Result<String> {
    if json {
        return Ok(format!("{}\n", serde_json::to_string_pretty(runs)?));
    }
    Ok(runs_list_plain(workspace, runs))
}

fn runs_list_plain(workspace: &WorkspaceTarget, runs: &[RunSummary]) -> String {
    if runs.is_empty() {
        return format!(
            "no run artifacts found at {}\nNext: kuzushi scan {}\n",
            workspace.root().join(".kuzushi/runs").display(),
            workspace.root().display()
        );
    }

    let mut lines = vec![
        "Run artifacts".to_string(),
        format!("Target: {}", workspace.root().display()),
    ];
    lines.extend(runs.iter().map(run_list_row));
    lines.push(format!(
        "Next: kuzushi runs show <runId> --target {}",
        workspace.root().display()
    ));
    format!("{}\n", lines.join("\n"))
}

fn run_list_row(run: &RunSummary) -> String {
    let tool = run.tool.as_deref().unwrap_or(run.kind.as_str());
    let findings = run
        .findings
        .map(|count| count.to_string())
        .unwrap_or_else(|| "-".to_string());
    format!(
        "{}  {:<9} {:<24} findings={} target={}",
        run.run_id, run.status, tool, findings, run.target
    )
}

fn runs_show_command(target: Option<PathBuf>, run_id: &str, json: bool) -> Result<()> {
    let workspace = WorkspaceTarget::new(target.unwrap_or_else(|| PathBuf::from(".")))?;
    let summary = load_run_summary(workspace.root(), run_id).with_context(|| {
        format!(
            "no run summary found for {run_id:?} under {}",
            workspace.root().join(".kuzushi/runs").display()
        )
    })?;
    print!("{}", runs_show_output(&summary, json)?);
    Ok(())
}

fn runs_show_output(summary: &RunSummary, json: bool) -> Result<String> {
    if json {
        return Ok(format!("{}\n", serde_json::to_string_pretty(summary)?));
    }
    Ok(run_summary_plain(summary))
}

fn runs_trace_command(target: Option<PathBuf>, run_id: &str, json: bool) -> Result<()> {
    let workspace = WorkspaceTarget::new(target.unwrap_or_else(|| PathBuf::from(".")))?;
    let trace_path = run_trace_path(&workspace, run_id);
    let body = fs::read_to_string(&trace_path)
        .with_context(|| format!("Could not read {}", trace_path.display()))?;
    print!("{}", runs_trace_output(&trace_path, &body, json)?);
    Ok(())
}

fn run_trace_path(workspace: &WorkspaceTarget, run_id: &str) -> PathBuf {
    workspace
        .root()
        .join(".kuzushi")
        .join("runs")
        .join(run_id)
        .join("trace.jsonl")
}

fn runs_trace_output(trace_path: &Path, body: &str, json: bool) -> Result<String> {
    if json {
        let steps = parse_trace_json_lines(trace_path, body)?;
        return Ok(format!("{}\n", serde_json::to_string_pretty(&steps)?));
    }
    Ok(body.to_string())
}

fn parse_trace_json_lines(trace_path: &Path, body: &str) -> Result<Vec<serde_json::Value>> {
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("Could not parse {}", trace_path.display()))
}

fn run_summary_plain(summary: &RunSummary) -> String {
    let mut lines = vec![
        format!("Run {}", summary.run_id),
        format!("Status: {}", summary.status),
        format!("Kind: {}", summary.kind),
    ];
    if let Some(tool) = &summary.tool {
        lines.push(format!("Tool: {tool}"));
    }
    lines.push(format!("Target: {}", summary.target));
    if let Some(findings) = summary.findings {
        lines.push(format!("Findings: {findings}"));
    }
    if let Some(cost) = summary.cost_usd {
        lines.push(format!("Cost USD: {cost:.4}"));
    }
    if let Some(error) = &summary.error {
        lines.push(format!("Error: {error}"));
    }
    if !summary.artifacts.is_empty() {
        lines.push("Artifacts:".to_string());
        for artifact in &summary.artifacts {
            lines.push(format!("  {}: {}", artifact.label, artifact.path));
        }
    }
    lines.push(format!("Next: kuzushi runs trace {}", summary.run_id));
    format!("{}\n", lines.join("\n"))
}

fn suppress_command(
    target: Option<PathBuf>,
    reference: String,
    reason: String,
    author: String,
    days: u64,
    json: bool,
) -> Result<()> {
    let target = target.unwrap_or_else(|| PathBuf::from("."));
    let workspace = WorkspaceTarget::new(target)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let finding = resolve_persisted_finding(&store, &reference, &workspace)?;
    let expires_at_unix = now_unix().saturating_add(days.saturating_mul(86_400));
    let record = build_whitebox_suppression_for_finding(
        workspace.root(),
        &finding,
        reason,
        author,
        expires_at_unix,
    )?;
    let record = upsert_whitebox_suppression(&workspace, record)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        println!("suppression recorded: {}", record.id);
        println!(
            "Store: {}",
            whitebox_suppression_store_path(&workspace).display()
        );
        println!(
            "Scope: {}:{}",
            record.scope.file_path, record.scope.start_line
        );
        println!("Expires: {}", record.expires_at_unix);
        println!("Policy: findings remain visible in audit/report output.");
    }
    Ok(())
}

fn suppressions_command(target: Option<PathBuf>, json: bool) -> Result<()> {
    let workspace = WorkspaceTarget::new(target.unwrap_or_else(|| PathBuf::from(".")))?;
    let suppressions = load_whitebox_suppressions(&workspace)?;
    print!(
        "{}",
        suppressions_command_output(&workspace, &suppressions, json)?
    );
    Ok(())
}

fn suppressions_command_output(
    workspace: &WorkspaceTarget,
    suppressions: &[WhiteboxSuppressionRecord],
    json: bool,
) -> Result<String> {
    if json {
        return Ok(format!("{}\n", serde_json::to_string_pretty(suppressions)?));
    }
    Ok(format!(
        "{}\n",
        suppressions_plain_lines(workspace, suppressions).join("\n")
    ))
}

fn suppressions_plain_lines(
    workspace: &WorkspaceTarget,
    suppressions: &[WhiteboxSuppressionRecord],
) -> Vec<String> {
    let mut lines = vec![
        "Suppressions".to_string(),
        format!(
            "Store: {}",
            whitebox_suppression_store_path(workspace).display()
        ),
    ];

    if suppressions.is_empty() {
        lines.push("none recorded".to_string());
        lines.push(format!(
            "Next: kuzushi suppress F-0001 --reason <reason> --target {}",
            workspace.root().display()
        ));
    } else {
        lines.extend(suppressions.iter().map(suppression_row));
    }

    lines
}

fn suppression_row(record: &WhiteboxSuppressionRecord) -> String {
    format!(
        "{}  {}:{}  expires={}  reason={}",
        record.id,
        record.scope.file_path,
        record.scope.start_line,
        record.expires_at_unix,
        record.reason
    )
}

fn permissions_command(target: Option<PathBuf>, json: bool) -> Result<()> {
    let workspace = target.as_deref().map(WorkspaceTarget::new).transpose()?;
    let target_label = workspace
        .as_ref()
        .map(|workspace| workspace.root().display().to_string())
        .unwrap_or_else(|| "none".to_string());
    let report = serde_json::json!({
        "target": target_label,
        "policy": {
            "modelFallback": "forbidden without explicit operator consent",
            "shellNetworkEgress": "approval required before dispatch",
            "shellFilesystemWrites": "approval required for writes outside .kuzushi or staged patch flows",
            "destructiveActions": "approval required; denial leaves state unchanged",
            "headlessRun": "explicit tool name required; no focused-module shorthand",
            "sandbox": "tools must state backend and risk; validation evidence records backend when available"
        },
        "next": [
            "kuzushi doctor --target .",
            "kuzushi runs list --target ."
        ]
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Kuzushi permissions");
        println!("Target: {}", report["target"].as_str().unwrap_or("none"));
        println!("Model fallback: forbidden without explicit operator consent");
        println!("Shell network egress: approval required before dispatch");
        println!("Shell filesystem writes: approval required outside .kuzushi/staged patch flows");
        println!("Destructive actions: approval required; denial leaves state unchanged");
        println!("Headless run: explicit tool name required; no `run .` shorthand");
        println!("Sandbox: validation evidence records backend when available");
        println!("Next: kuzushi doctor --target .");
    }
    Ok(())
}

fn resolve_persisted_finding(
    store: &FindingStore,
    reference: &str,
    workspace: &WorkspaceTarget,
) -> Result<kuzushi_core::Finding> {
    let all_findings = store
        .list_findings_filtered(&FindingListFilter::with_limit(FindingListFilter::MAX_LIMIT))?
        .findings;
    if let Some(alias_finding) = resolve_finding_alias(&all_findings, reference) {
        return Ok(store
            .get_finding_by_fingerprint(&alias_finding.fingerprint)?
            .unwrap_or(alias_finding));
    }
    store.get_finding_by_reference(reference)?.with_context(|| {
        format!(
            "no finding found for {reference:?} at {}\nNext: kuzushi findings --target {}",
            workspace.findings_db_path().display(),
            workspace.root().display()
        )
    })
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn config_command(command: ConfigCommand, target: Option<PathBuf>) -> Result<()> {
    match command {
        ConfigCommand::Show => config_show_command(target),
        ConfigCommand::Init { force } => config_init_command(force),
        ConfigCommand::Path => config_path_command(),
    }
}

fn config_show_command(target: Option<PathBuf>) -> Result<()> {
    let workspace = target.as_deref().map(WorkspaceTarget::new).transpose()?;
    let config = load_config_for_target(workspace.as_ref().map(WorkspaceTarget::root))?;
    println!("{}", serde_json::to_string_pretty(&config)?);
    Ok(())
}

fn config_init_command(force: bool) -> Result<()> {
    let path = writable_config_init_path(force)?;
    write_default_config(&path)?;
    println!("{}", path.display());
    Ok(())
}

fn writable_config_init_path(force: bool) -> Result<PathBuf> {
    let paths = kuzushi_core::ConfigPaths::from_target(None)?;
    let path = paths.global_config_path();
    ensure_config_init_allowed(&path, force)?;
    Ok(path)
}

fn ensure_config_init_allowed(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite",
            path.display()
        );
    }
    Ok(())
}

fn config_path_command() -> Result<()> {
    let paths = kuzushi_core::ConfigPaths::from_target(None)?;
    println!("{}", paths.global_config_path().display());
    Ok(())
}

fn auth_command(command: AuthCommand, target: Option<PathBuf>) -> Result<()> {
    match command {
        AuthCommand::Ping { provider, model } => auth_ping(&provider, model, target),
    }
}

fn auth_ping(
    provider: &str,
    model_override: Option<String>,
    target: Option<PathBuf>,
) -> Result<()> {
    let workspace = auth_ping_workspace(target)?;
    let config = auth_ping_config(workspace.as_ref())?;
    let mut log = AuthPingLog::default();
    run_auth_ping_checks(provider, model_override, &config, &mut log)
}

fn auth_ping_workspace(target: Option<PathBuf>) -> Result<Option<WorkspaceTarget>> {
    target.as_deref().map(WorkspaceTarget::new).transpose()
}

fn auth_ping_config(workspace: Option<&WorkspaceTarget>) -> Result<kuzushi_core::V2Config> {
    load_config_for_target(workspace.map(WorkspaceTarget::root))
}

fn run_auth_ping_checks(
    provider: &str,
    model_override: Option<String>,
    config: &kuzushi_core::V2Config,
    log: &mut AuthPingLog,
) -> Result<()> {
    eprintln!("[auth ping] provider = {provider}");
    probe_auth_credentials(provider, config, log)?;

    let model = auth_ping_model(model_override, config);
    log.record(true, format!("ping model = {model}"));

    let bridge_command = required_auth_ping_bridge_command(config, log);
    let envelope = auth_ping_envelope(config, model);
    let parsed = run_auth_ping_bridge(&bridge_command, &envelope, log)?;
    record_auth_ping_result(&parsed, log);
    log.exit_if_failed();
    eprintln!("\x1b[32mauth ping: OK\x1b[0m");
    Ok(())
}

fn required_auth_ping_bridge_command(
    config: &kuzushi_core::V2Config,
    log: &mut AuthPingLog,
) -> Vec<String> {
    let command = auth_ping_bridge_command(config);
    if command.is_empty() {
        log.record(false, "bridge command is empty");
        std::process::exit(1);
    }
    command
}

fn record_auth_ping_result(parsed: &serde_json::Value, log: &mut AuthPingLog) {
    if let Some(error) = bridge_ping_error(parsed) {
        log.record(false, format!("bridge ping failed: {error}"));
        std::process::exit(1);
    }
    log.record(true, bridge_ping_summary(parsed));
}

struct AuthPingLog {
    all_ok: bool,
}

impl Default for AuthPingLog {
    fn default() -> Self {
        Self { all_ok: true }
    }
}

impl AuthPingLog {
    fn record(&mut self, ok: bool, msg: impl Into<String>) {
        let msg = msg.into();
        if ok {
            eprintln!("  \x1b[32m✓\x1b[0m {msg}");
        } else {
            eprintln!("  \x1b[31m✗\x1b[0m {msg}");
            self.all_ok = false;
        }
    }

    fn exit_if_failed(&self) {
        if !self.all_ok {
            std::process::exit(1);
        }
    }
}

fn probe_auth_credentials(
    provider: &str,
    config: &kuzushi_core::V2Config,
    log: &mut AuthPingLog,
) -> Result<()> {
    if provider == "anthropic" {
        probe_anthropic_credentials(config, log)?;
    }
    Ok(())
}

fn probe_anthropic_credentials(
    config: &kuzushi_core::V2Config,
    log: &mut AuthPingLog,
) -> Result<()> {
    if let Some(oauth_cfg) = &config.runtime.anthropic_oauth {
        let readiness = kuzushi_openai::probe_anthropic_oauth(oauth_cfg)?;
        record_anthropic_oauth_readiness(readiness, log);
    } else {
        log.record(true, "oauth not configured; will check env / api key");
    }
    record_anthropic_env_presence(log);
    Ok(())
}

fn record_anthropic_oauth_readiness(
    readiness: kuzushi_openai::OauthReadiness,
    log: &mut AuthPingLog,
) {
    let (ok, message) = anthropic_oauth_readiness_message(readiness);
    log.record(ok, message);
}

fn anthropic_oauth_readiness_message(readiness: kuzushi_openai::OauthReadiness) -> (bool, String) {
    match readiness {
        kuzushi_openai::OauthReadiness::Ready { expires_at_ms } => (
            true,
            format!(
                "oauth credentials ready (expires {})",
                format_unix_ms(expires_at_ms)
            ),
        ),
        kuzushi_openai::OauthReadiness::Expired { expires_at_ms } => (
            true,
            format!(
                "oauth credentials present but expired ({}); will refresh on next call",
                format_unix_ms(expires_at_ms)
            ),
        ),
        kuzushi_openai::OauthReadiness::Missing { searched } => (
            false,
            format!("oauth credentials missing at {}", searched.display()),
        ),
        kuzushi_openai::OauthReadiness::Invalid { searched, reason } => (
            false,
            format!(
                "oauth credentials invalid at {}: {reason}",
                searched.display()
            ),
        ),
    }
}

fn record_anthropic_env_presence(log: &mut AuthPingLog) {
    record_env_presence(
        log,
        &["ANTHROPIC_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN"],
        "ANTHROPIC_OAUTH_TOKEN/AUTH_TOKEN env present",
    );
    record_env_presence(log, &["ANTHROPIC_API_KEY"], "ANTHROPIC_API_KEY env present");
}

fn record_env_presence(log: &mut AuthPingLog, names: &[&str], label: &str) {
    if names.iter().any(|name| std::env::var(name).is_ok()) {
        log.record(true, label);
    }
}

fn auth_ping_model(model_override: Option<String>, config: &kuzushi_core::V2Config) -> String {
    model_override
        .or_else(|| config.model.clone())
        .unwrap_or_else(|| "anthropic:claude-haiku-4-5".to_string())
}

fn auth_ping_bridge_command(config: &kuzushi_core::V2Config) -> Vec<String> {
    config
        .runtime
        .agent_bridge_command
        .clone()
        .unwrap_or_else(|| {
            vec![
                "node".to_string(),
                "scripts/pi-agent-core-bridge.mjs".to_string(),
            ]
        })
}

fn auth_ping_envelope(config: &kuzushi_core::V2Config, model: String) -> serde_json::Value {
    serde_json::json!({
        "type": "ping",
        "model": model,
        "apiKeyEnv": config.runtime.api_key_env,
        "apiKey": std::env::var(&config.runtime.api_key_env).ok(),
    })
}

fn run_auth_ping_bridge(
    bridge_command: &[String],
    envelope: &serde_json::Value,
    log: &mut AuthPingLog,
) -> Result<serde_json::Value> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(&bridge_command[0])
        .args(&bridge_command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("could not start bridge {}", bridge_command[0]))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .context("could not open bridge stdin")?;
        stdin.write_all(serde_json::to_vec(&envelope)?.as_slice())?;
    }
    let output = child
        .wait_with_output()
        .context("could not read bridge output")?;
    match parse_bridge_stdout(&output.stdout) {
        Ok(value) => Ok(value),
        Err(e) => {
            log.record(false, format!("bridge returned non-JSON output: {e}"));
            eprintln!("    stdout: {}", String::from_utf8_lossy(&output.stdout));
            eprintln!("    stderr: {}", String::from_utf8_lossy(&output.stderr));
            std::process::exit(1);
        }
    }
}

fn parse_bridge_stdout(stdout: &[u8]) -> std::result::Result<serde_json::Value, serde_json::Error> {
    serde_json::from_slice(stdout)
}

fn bridge_ping_error(parsed: &serde_json::Value) -> Option<String> {
    if parsed.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
        return None;
    }
    Some(
        parsed
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("(no error message)")
            .to_string(),
    )
}

fn bridge_ping_summary(parsed: &serde_json::Value) -> String {
    let auth_mode = parsed
        .get("auth_mode")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?");
    let latency_ms = parsed
        .get("latency_ms")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let in_tok = parsed
        .get("input_tokens")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let out_tok = parsed
        .get("output_tokens")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let cost = parsed
        .get("cost_usd")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0);
    format!(
        "round-trip ok via {auth_mode} ({latency_ms}ms, {in_tok}/{out_tok} tokens, ~${cost:.5})"
    )
}

fn format_unix_ms(ms: u64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let when = UNIX_EPOCH + Duration::from_millis(ms);
    let now = SystemTime::now();
    let delta = match when.duration_since(now) {
        Ok(d) => format!("in {}s", d.as_secs()),
        Err(e) => format!("{}s ago", e.duration().as_secs()),
    };
    format!("{ms}ms unix; {delta}")
}

fn modules_command(json: bool) -> Result<()> {
    let registry = ModuleRegistry::with_v2_builtins();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &registry
                    .modules()
                    .map(|module| module.metadata())
                    .collect::<Vec<_>>()
            )?
        );
    } else {
        for module in registry.modules() {
            println!(
                "{} - {}",
                module.metadata().id,
                module.metadata().description
            );
        }
    }
    Ok(())
}

fn tools_command(json: bool) -> Result<()> {
    let registry = ModuleRegistry::with_v2_builtins();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&registry.tools().collect::<Vec<_>>())?
        );
    } else {
        for tool in registry.tools() {
            println!("{} - {}", tool.name, tool.description);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DoctorStatus {
    Ok,
    Warn,
    Fail,
}

impl DoctorStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone)]
struct DoctorCheck {
    name: &'static str,
    status: DoctorStatus,
    detail: String,
    next: Option<String>,
}

impl DoctorCheck {
    fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: DoctorStatus::Ok,
            detail: detail.into(),
            next: None,
        }
    }

    fn warn(name: &'static str, detail: impl Into<String>, next: impl Into<String>) -> Self {
        Self {
            name,
            status: DoctorStatus::Warn,
            detail: detail.into(),
            next: Some(next.into()),
        }
    }

    fn fail(name: &'static str, detail: impl Into<String>, next: impl Into<String>) -> Self {
        Self {
            name,
            status: DoctorStatus::Fail,
            detail: detail.into(),
            next: Some(next.into()),
        }
    }
}

#[derive(Debug, Clone)]
struct DoctorReport {
    target: PathBuf,
    checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    fn count(&self, status: DoctorStatus) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == status)
            .count()
    }

    fn failures(&self) -> usize {
        self.count(DoctorStatus::Fail)
    }

    fn has_failures(&self) -> bool {
        self.failures() > 0
    }
}

fn doctor_command(target: Option<PathBuf>, json: bool) -> Result<()> {
    let report = build_doctor_report(target.unwrap_or_else(|| PathBuf::from(".")));
    if json {
        print_doctor_json(&report)?;
    } else {
        print_doctor_plain(&report);
    }

    if report.has_failures() {
        anyhow::bail!(
            "doctor found {} failing check(s). Fix the listed next steps and rerun `kuzushi doctor`.",
            report.failures()
        );
    }
    Ok(())
}

fn build_doctor_report(target: PathBuf) -> DoctorReport {
    let mut checks = Vec::new();
    let workspace = match WorkspaceTarget::new(&target) {
        Ok(workspace) => {
            checks.push(DoctorCheck::ok(
                "target",
                format!("workspace resolved to {}", workspace.root().display()),
            ));
            Some(workspace)
        }
        Err(error) => {
            checks.push(DoctorCheck::fail(
                "target",
                error.to_string(),
                "Pass --target <repo> or run `kuzushi doctor` from an existing repository directory.",
            ));
            None
        }
    };

    let config = match load_config_for_target(workspace.as_ref().map(WorkspaceTarget::root)) {
        Ok(config) => {
            checks.push(DoctorCheck::ok(
                "config",
                "effective config loaded from global/project/env sources",
            ));
            Some(config)
        }
        Err(error) => {
            checks.push(DoctorCheck::fail(
                "config",
                error.to_string(),
                "Run `kuzushi config init`, then fix the reported config field.",
            ));
            None
        }
    };

    if let Some(workspace) = &workspace {
        checks.push(check_state_dir(workspace));
        checks.push(check_findings_db(workspace));
    } else {
        checks.push(DoctorCheck::fail(
            "state",
            "workspace target was not resolved; state directory was not checked",
            "Pass --target <repo> or run from the repository root.",
        ));
        checks.push(DoctorCheck::fail(
            "findings-db",
            "workspace target was not resolved; findings DB was not checked",
            "Pass --target <repo> or run from the repository root.",
        ));
    }

    checks.push(check_scanner_binary("semgrep"));
    checks.push(check_scanner_binary("codeql"));

    if let Some(config) = &config {
        checks.push(check_model_config(config));
        checks.push(check_auth_env(config));
        checks.push(check_bridge_command(config));
    } else {
        checks.push(DoctorCheck::fail(
            "model",
            "config did not load; model/provider compatibility was not checked",
            "Fix `kuzushi config show` errors, then rerun `kuzushi doctor`.",
        ));
        checks.push(DoctorCheck::fail(
            "auth-env",
            "config did not load; credential environment variable name was not checked",
            "Fix `kuzushi config show` errors, then rerun `kuzushi doctor`.",
        ));
        checks.push(DoctorCheck::fail(
            "pi-agent-core bridge",
            "config did not load; bridge command was not checked",
            "Fix `kuzushi config show` errors, then rerun `kuzushi doctor`.",
        ));
    }

    DoctorReport { target, checks }
}

fn check_state_dir(workspace: &WorkspaceTarget) -> DoctorCheck {
    match workspace.ensure_state_dir() {
        Ok(state_dir) => {
            let probe = state_dir.join(format!(".doctor-write-test-{}", std::process::id()));
            match fs::write(&probe, b"kuzushi doctor\n").and_then(|_| fs::remove_file(&probe)) {
                Ok(_) => DoctorCheck::ok("state", format!("{} is writable", state_dir.display())),
                Err(error) => DoctorCheck::fail(
                    "state",
                    format!("{} is not writable: {error}", state_dir.display()),
                    "Fix directory ownership/permissions or choose a writable --target.",
                ),
            }
        }
        Err(error) => DoctorCheck::fail(
            "state",
            error.to_string(),
            "Fix directory ownership/permissions or choose a writable --target.",
        ),
    }
}

fn check_findings_db(workspace: &WorkspaceTarget) -> DoctorCheck {
    let db_path = workspace.findings_db_path();
    let existed = db_path.exists();
    let check_path = if existed {
        db_path.clone()
    } else {
        workspace.state_dir().join(format!(
            ".doctor-findings-check-{}.sqlite3",
            std::process::id()
        ))
    };

    let check = match FindingStore::open(&check_path) {
        Ok(_) if existed => DoctorCheck::ok(
            "findings-db",
            format!("{} opened successfully", db_path.display()),
        ),
        Ok(_) => DoctorCheck::ok(
            "findings-db",
            format!(
                "{} is creatable; next `kuzushi scan <repo>` will initialize it",
                db_path.display()
            ),
        ),
        Err(error) => DoctorCheck::fail(
            "findings-db",
            format!("{} could not be opened: {error}", db_path.display()),
            "Fix .kuzushi/v2 permissions or move the workspace to a writable path.",
        ),
    };
    if !existed {
        remove_sqlite_file_set(&check_path);
    }
    check
}

fn remove_sqlite_file_set(path: &Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
    let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
}

fn check_scanner_binary(binary: &'static str) -> DoctorCheck {
    match resolve_executable(
        binary,
        env::var_os("PATH").as_deref(),
        &current_dir_for_doctor(),
    ) {
        Some(path) => DoctorCheck::ok(binary, format!("found {}", path.display())),
        None => {
            let next = match binary {
                "semgrep" => "Install Semgrep (`pipx install semgrep` or `brew install semgrep`) or pass a scanner binary in tool input.",
                "codeql" => "Install the CodeQL CLI or pass {\"binary\":\"/path/to/codeql\"} to codeql:scan.",
                _ => "Install the missing scanner binary or configure the tool input with an explicit path.",
            };
            DoctorCheck::warn(binary, format!("{binary} was not found on PATH"), next)
        }
    }
}

fn check_model_config(config: &kuzushi_core::V2Config) -> DoctorCheck {
    match config.model.as_deref().map(str::trim).filter(|model| !model.is_empty()) {
        None => DoctorCheck::warn(
            "model",
            "no explicit model configured; static scanners still work",
            "Set `KUZUSHI_MODEL=provider:model` or add `model = \"provider:model\"` before using agentic tools.",
        ),
        Some(model) => match model.split_once(':') {
            Some((provider, name)) if !provider.trim().is_empty() && !name.trim().is_empty() => {
                DoctorCheck::ok(
                    "model",
                    format!(
                        "explicit model configured for provider {}",
                        provider.trim()
                    ),
                )
            }
            _ => DoctorCheck::fail(
                "model",
                format!("model must use non-empty provider:model syntax, got {model:?}"),
                "Set `KUZUSHI_MODEL=provider:model` or fix config.toml.",
            ),
        },
    }
}

fn check_auth_env(config: &kuzushi_core::V2Config) -> DoctorCheck {
    let name = config.runtime.api_key_env.trim();
    if name.is_empty() {
        return DoctorCheck::fail(
            "auth-env",
            "runtime.api_key_env is empty",
            "Set runtime.api_key_env to the name of an environment variable, not a secret value.",
        );
    }

    if env::var_os(name).is_some() {
        DoctorCheck::ok("auth-env", format!("{name} is set; value is hidden"))
    } else {
        DoctorCheck::warn(
            "auth-env",
            format!("{name} is not set"),
            format!("Export {name}=<token> before running model-backed tools."),
        )
    }
}

fn check_bridge_command(config: &kuzushi_core::V2Config) -> DoctorCheck {
    match PiAgentCoreRuntime::from_config(config, current_dir_for_doctor()) {
        Ok(runtime) => {
            let command = runtime.command();
            if command.is_empty() {
                return DoctorCheck::fail(
                    "pi-agent-core bridge",
                    "bridge command is empty",
                    "Set runtime.agent_bridge_command to an executable command.",
                );
            }
            let cwd = current_dir_for_doctor();
            let executable = resolve_executable(&command[0], env::var_os("PATH").as_deref(), &cwd);
            let Some(executable) = executable else {
                return DoctorCheck::fail(
                    "pi-agent-core bridge",
                    format!("bridge executable {:?} was not found", command[0]),
                    "Install Node.js or set runtime.agent_bridge_command to an executable bridge.",
                );
            };

            if let Some(script) = command
                .get(1)
                .filter(|arg| arg.ends_with("pi-agent-core-bridge.mjs"))
            {
                let script_path = resolve_command_path(script, &cwd);
                if !script_path.exists() {
                    return DoctorCheck::fail(
                        "pi-agent-core bridge",
                        format!("bridge script {} was not found", script_path.display()),
                        "Run from a source checkout, build the npm package, or set runtime.agent_bridge_command.",
                    );
                }
            }

            DoctorCheck::ok(
                "pi-agent-core bridge",
                format!("{} via {}", command.join(" "), executable.display()),
            )
        }
        Err(error) => DoctorCheck::fail(
            "pi-agent-core bridge",
            error.to_string(),
            "Set runtime.agent_bridge_command to an executable command.",
        ),
    }
}

fn current_dir_for_doctor() -> PathBuf {
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn resolve_executable(binary: &str, path: Option<&std::ffi::OsStr>, cwd: &Path) -> Option<PathBuf> {
    let candidate = Path::new(binary);
    if candidate.components().count() > 1 {
        let resolved = resolve_command_path(binary, cwd);
        return is_executable_file(&resolved).then_some(resolved);
    }

    path.into_iter()
        .flat_map(env::split_paths)
        .map(|dir| dir.join(binary))
        .find(|candidate| is_executable_file(candidate))
}

fn resolve_command_path(value: &str, cwd: &Path) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}

fn is_executable_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }

    #[cfg(not(unix))]
    {
        true
    }
}

fn print_doctor_plain(report: &DoctorReport) {
    println!("Kuzushi doctor");
    println!("Target: {}", report.target.display());
    for check in &report.checks {
        println!(
            "[{}] {:<20} {}",
            check.status.label(),
            check.name,
            check.detail
        );
        if let Some(next) = &check.next {
            println!("      Next: {next}");
        }
    }
    println!(
        "Summary: {} ok, {} warn, {} fail",
        report.count(DoctorStatus::Ok),
        report.count(DoctorStatus::Warn),
        report.count(DoctorStatus::Fail)
    );
}

fn print_doctor_json(report: &DoctorReport) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "target": report.target,
            "checks": report.checks.iter().map(|check| serde_json::json!({
                "name": check.name,
                "status": check.status.as_str(),
                "detail": check.detail,
                "next": check.next,
            })).collect::<Vec<_>>(),
            "summary": {
                "ok": report.count(DoctorStatus::Ok),
                "warn": report.count(DoctorStatus::Warn),
                "fail": report.count(DoctorStatus::Fail),
            },
        }))?
    );
    Ok(())
}

fn run_tool_command(tool: String, input: String, target: Option<PathBuf>) -> Result<()> {
    reject_shell_only_run_dot(&tool)?;
    let workspace = run_tool_workspace(&tool, target.as_deref())?;
    let config = load_config_for_target(workspace.as_ref().map(WorkspaceTarget::root))?;
    let store = workspace
        .as_ref()
        .filter(|_| tool_needs_finding_store(&tool))
        .map(|workspace| FindingStore::open(workspace.findings_db_path()))
        .transpose()?;
    let input = serde_json::from_str(&input).context("--input must be JSON")?;
    let registry = ModuleRegistry::with_v2_builtins();
    let run_id = workspace
        .as_ref()
        .map(|workspace| start_cli_tool_run(workspace.root(), &tool, &input));
    let runtime = if tool_needs_runtime(&tool, &input) {
        Some(PiAgentCoreRuntime::from_config(
            &config,
            std::env::current_dir()?,
        )?)
    } else {
        None
    };
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: workspace.as_ref(),
        findings_store: store.as_ref(),
    };
    let result = registry.execute_tool_with_runtime(
        &tool,
        input,
        &ctx,
        runtime.as_ref().map(|runtime| runtime as &dyn AgentRuntime),
    );
    let output = match result {
        Ok(output) => {
            if let (Some(workspace), Some(run_id)) = (workspace.as_ref(), run_id.as_deref()) {
                finish_cli_tool_run(workspace.root(), run_id, &tool, &output);
            }
            output
        }
        Err(error) => {
            if let (Some(workspace), Some(run_id)) = (workspace.as_ref(), run_id.as_deref()) {
                fail_cli_tool_run(workspace.root(), run_id, &tool, &error.to_string());
            }
            return Err(error);
        }
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn start_cli_tool_run(target: &Path, tool: &str, input: &serde_json::Value) -> String {
    let run_id = new_run_id("run");
    let input_artifact =
        write_run_artifact_json(target, &run_id, "input.json", "input", input).ok();
    let mut summary = RunSummary::running(
        run_id.clone(),
        "run",
        Some(tool.to_string()),
        target.display().to_string(),
    );
    if let Some(artifact) = input_artifact {
        summary = summary.with_artifact(artifact);
    }
    let _ = append_run_trace_step(
        target,
        &run_id,
        &RunTraceStep::new(1, "tool", format!("{tool} started")),
    );
    let _ = write_run_summary(target, &summary);
    run_id
}

fn finish_cli_tool_run(target: &Path, run_id: &str, tool: &str, output: &serde_json::Value) {
    let result_artifact =
        write_run_artifact_json(target, run_id, "result.json", "result", output).ok();
    let mut summary = RunSummary::running(
        run_id.to_string(),
        "run",
        Some(tool.to_string()),
        target.display().to_string(),
    )
    .complete()
    .with_findings(run_output_findings_count(output))
    .with_cost(run_output_cost_usd(output));
    if let Some(artifact) = result_artifact {
        summary = summary.with_artifact(artifact);
    }
    let _ = append_run_trace_step(
        target,
        run_id,
        &RunTraceStep::new(2, "tool", format!("{tool} complete"))
            .with_cost_usd(run_output_cost_usd(output)),
    );
    let _ = write_run_summary(target, &summary);
}

fn fail_cli_tool_run(target: &Path, run_id: &str, tool: &str, error: &str) {
    let summary = RunSummary::running(
        run_id.to_string(),
        "run",
        Some(tool.to_string()),
        target.display().to_string(),
    )
    .failed(error.to_string());
    let _ = append_run_trace_step(
        target,
        run_id,
        &RunTraceStep::new(2, "tool", format!("{tool} failed")),
    );
    let _ = write_run_summary(target, &summary);
}

fn run_output_findings_count(output: &serde_json::Value) -> Option<u64> {
    output
        .pointer("/data/findingsCount")
        .or_else(|| output.get("findingsCount"))
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            output
                .pointer("/data/findings")
                .and_then(serde_json::Value::as_array)
                .map(|findings| findings.len() as u64)
        })
}

fn run_output_cost_usd(output: &serde_json::Value) -> Option<f64> {
    output
        .get("costUsd")
        .and_then(serde_json::Value::as_f64)
        .or_else(|| {
            output
                .pointer("/data/costUsd")
                .and_then(serde_json::Value::as_f64)
        })
        .filter(|cost| cost.is_finite() && *cost >= 0.0)
}

fn reject_shell_only_run_dot(tool: &str) -> Result<()> {
    if tool == "." {
        anyhow::bail!(
            "`kuzushi run .` is shell-only because the terminal command has no focused module. Use `kuzushi shell`, then `use <module>` and `run .`; from a terminal run an explicit tool such as `kuzushi --target . run context:build --input '{{}}'`."
        );
    }
    Ok(())
}

fn run_tool_workspace(tool: &str, target: Option<&Path>) -> Result<Option<WorkspaceTarget>> {
    match target {
        Some(target) => Ok(Some(WorkspaceTarget::new(target)?)),
        None if tool_defaults_to_workspace(tool) => Ok(Some(WorkspaceTarget::new(".")?)),
        None => Ok(None),
    }
}

const WORKSPACE_TOOL_PREFIXES: &[&str] = &[
    "findings:",
    "context:",
    "recon:",
    "vendor-assessment:",
    "chrome-rce:",
    "vuln-scout:",
    "tob:",
    "shinsa:",
    "prompt-armor:",
    "x-ray:",
    "threat-model:",
    "randori:",
    "variant:",
    "ndiff:",
    "systems-hunt:",
];

const WORKSPACE_TOOL_NAMES: &[&str] = &[
    "carlini-threat-hunt:run",
    "agentic-sast:scan",
    "taint-iris:hunt",
    "taint-iris-next:hunt",
    "triage:run",
    "verify:finding",
    "verify:exploit",
    "patch:finding",
    "context-lite:index",
    "full-mode:hunt",
    "classifier-gate:score",
    "deep-audit:run",
    "sast:scan",
    "semgrep:scan",
    "codeql:scan",
    "iac-scan:scan",
];

const FINDING_STORE_TOOL_PREFIXES: &[&str] =
    &["findings:", "chrome-rce:", "variant:", "systems-hunt:"];

const FINDING_STORE_TOOL_NAMES: &[&str] = &[
    "triage:run",
    "verify:finding",
    "verify:exploit",
    "patch:finding",
    "agentic-sast:scan",
    "carlini-threat-hunt:run",
    "vuln-scout:audit",
    "tob:audit",
    "shinsa:scan",
    "shinsa:quick-check",
    "shinsa:nist-scan",
    "shinsa:nist-quick-check",
    "prompt-armor:scan",
    "prompt-armor:analyze",
    "prompt-armor:attack",
    "ndiff:hunt-variants",
    "taint-iris:hunt",
    "taint-iris-next:hunt",
    "sast:scan",
    "semgrep:scan",
    "codeql:scan",
    "iac-scan:scan",
];

const RUNTIME_TOOL_NAMES: &[&str] = &[
    "triage:run",
    "verify:finding",
    "patch:finding",
    "agentic-sast:scan",
    "carlini-threat-hunt:run",
    "vendor-assessment:assess",
    "vuln-scout:audit",
    "tob:audit",
    "shinsa:scan",
    "shinsa:quick-check",
    "shinsa:nist-scan",
    "shinsa:nist-quick-check",
    "prompt-armor:scan",
    "prompt-armor:analyze",
    "prompt-armor:attack",
    "variant:lift-pattern",
    "variant:hunt",
    "ndiff:extract-fix-pattern",
    "ndiff:hunt-variants",
    "systems-hunt:systems-invariant-extract",
    "systems-hunt:systems-trigger-synth",
    "systems-hunt:systems-hunt",
    "systems-hunt:deep-semantic-cwe-select",
    "systems-hunt:deep-semantic-hunt",
    "taint-iris:hunt",
    "taint-iris-next:hunt",
    "full-mode:hunt",
    "classifier-gate:score",
    "deep-audit:run",
    "smoke:next-step",
    "threat-model:build",
    "randori:pasta",
    "x-ray:run",
    "x-ray:x-ray",
];

fn tool_defaults_to_workspace(tool: &str) -> bool {
    has_known_prefix(tool, WORKSPACE_TOOL_PREFIXES) || has_known_name(tool, WORKSPACE_TOOL_NAMES)
}

fn tool_needs_finding_store(tool: &str) -> bool {
    has_known_prefix(tool, FINDING_STORE_TOOL_PREFIXES)
        || has_known_name(tool, FINDING_STORE_TOOL_NAMES)
}

fn tool_needs_runtime(tool: &str, input: &serde_json::Value) -> bool {
    has_known_name(tool, RUNTIME_TOOL_NAMES) || tool == "sast:scan" && wants_sast_runtime(input)
}

fn has_known_prefix(tool: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| tool.starts_with(prefix))
}

fn has_known_name(tool: &str, names: &[&str]) -> bool {
    names.contains(&tool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_line_uses_relative_timestamp_and_prefix() {
        let started = std::time::Instant::now();
        let line = ci_line(started, "scan", "demo started");
        assert!(line.starts_with("[+"), "got: {line}");
        assert!(line.ends_with("scan: demo started"));
    }

    #[test]
    fn format_duration_below_one_minute_is_decimal_seconds() {
        assert_eq!(
            format_duration(std::time::Duration::from_millis(500)),
            "0.5s"
        );
        assert_eq!(format_duration(std::time::Duration::from_secs(12)), "12.0s");
    }

    #[test]
    fn format_duration_above_one_minute_is_compound() {
        assert_eq!(
            format_duration(std::time::Duration::from_secs(78)),
            "1m 18s"
        );
        assert_eq!(
            format_duration(std::time::Duration::from_secs(3600)),
            "60m 0s"
        );
    }

    #[test]
    fn shell_startup_progress_names_real_first_finding_commands() {
        let bare = shell_startup_progress_messages(None).join("\n");
        assert!(bare.contains("loading config"));
        assert!(bare.contains("native registry"));
        assert!(bare.contains("first finding: scan ., then findings"));

        let targeted = shell_startup_progress_messages(Some(Path::new("."))).join("\n");
        assert!(targeted.contains("target ."));
        assert!(targeted.contains("first finding: scan, then findings"));
        assert!(!targeted.contains("scan ."));
    }

    #[test]
    fn run_summary_plain_includes_optional_fields_and_artifacts() {
        let summary =
            RunSummary::running("run-123", "scan", Some("sast:scan".to_string()), "/repo")
                .failed("boom")
                .with_findings(Some(2))
                .with_cost(Some(0.125))
                .with_artifact(kuzushi_core::RunArtifact {
                    label: "summary".to_string(),
                    path: "/repo/.kuzushi/runs/run-123/summary.json".to_string(),
                    kind: "json".to_string(),
                });

        let rendered = run_summary_plain(&summary);

        assert!(rendered.contains("Run run-123"));
        assert!(rendered.contains("Status: failed"));
        assert!(rendered.contains("Tool: sast:scan"));
        assert!(rendered.contains("Findings: 2"));
        assert!(rendered.contains("Cost USD: 0.1250"));
        assert!(rendered.contains("Error: boom"));
        assert!(rendered.contains("summary: /repo/.kuzushi/runs/run-123/summary.json"));
        assert!(rendered.ends_with("Next: kuzushi runs trace run-123\n"));
    }

    #[test]
    fn runs_list_output_covers_empty_plain_rows_and_json() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let empty = runs_list_output(&workspace, &[], false).unwrap();
        assert!(empty.contains("no run artifacts found"));
        assert!(empty.contains("Next: kuzushi scan"));

        let runs = vec![
            RunSummary::running("run-1", "scan", None, "target").with_findings(Some(3)),
            RunSummary::running("run-2", "tool", Some("ctx:build".to_string()), "target"),
        ];
        let plain = runs_list_output(&workspace, &runs, false).unwrap();
        assert!(plain.contains("Run artifacts"));
        assert!(plain.contains("run-1  running   scan"));
        assert!(plain.contains("findings=3"));
        assert!(plain.contains("run-2  running   ctx:build"));
        assert!(plain.ends_with('\n'));

        let json = runs_list_output(&workspace, &runs, true).unwrap();
        assert!(json.contains("\"runId\": \"run-1\""));
        assert!(json.ends_with('\n'));
    }

    #[test]
    fn runs_show_output_covers_plain_and_json() {
        let summary = RunSummary::running("run-123", "scan", None, "/repo").complete();

        assert!(runs_show_output(&summary, false)
            .unwrap()
            .contains("Run run-123"));
        assert!(runs_show_output(&summary, true)
            .unwrap()
            .contains("\"runId\": \"run-123\""));
    }

    #[test]
    fn trace_json_parser_skips_blank_lines_and_reports_values() {
        let steps = parse_trace_json_lines(
            Path::new("/tmp/trace.jsonl"),
            "\n{\"n\":1,\"kind\":\"plan\"}\n\n{\"n\":2,\"kind\":\"llm\"}\n",
        )
        .unwrap();

        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0]["kind"], "plan");
        assert_eq!(steps[1]["n"], 2);
    }

    #[test]
    fn runs_trace_output_covers_plain_and_json() {
        let body = "{\"n\":1,\"kind\":\"plan\"}\n";

        assert_eq!(
            runs_trace_output(Path::new("/tmp/trace.jsonl"), body, false).unwrap(),
            body
        );
        let json = runs_trace_output(Path::new("/tmp/trace.jsonl"), body, true).unwrap();
        assert!(json.contains("\"kind\": \"plan\""));
        assert!(json.ends_with('\n'));
    }

    #[test]
    fn suppressions_plain_lines_cover_empty_and_recorded_states() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let empty = suppressions_plain_lines(&workspace, &[]);
        assert!(empty.iter().any(|line| line == "none recorded"));
        assert!(empty
            .iter()
            .any(|line| line.contains("kuzushi suppress F-0001")));

        let record = kuzushi_core::WhiteboxSuppressionRecord {
            id: "sup-1".to_string(),
            scope: kuzushi_core::WhiteboxSuppressionScope {
                finding_fingerprint: Some("fp".to_string()),
                rule_id: "rule".to_string(),
                file_path: "src/lib.rs".to_string(),
                start_line: 7,
                end_line: 8,
                snippet_hash: "hash".to_string(),
            },
            evidence: Vec::new(),
            reason: "accepted risk".to_string(),
            author: "tester".to_string(),
            created_at_unix: 1,
            expires_at_unix: 2,
            metadata: serde_json::json!({}),
        };
        let rendered = suppressions_plain_lines(&workspace, &[record]).join("\n");

        assert!(rendered.contains("sup-1  src/lib.rs:7  expires=2  reason=accepted risk"));
        assert!(!rendered.contains("none recorded"));
    }

    #[test]
    fn suppressions_command_output_covers_plain_and_json() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let record = kuzushi_core::WhiteboxSuppressionRecord {
            id: "sup-1".to_string(),
            scope: kuzushi_core::WhiteboxSuppressionScope {
                finding_fingerprint: None,
                rule_id: "rule".to_string(),
                file_path: "src/lib.rs".to_string(),
                start_line: 7,
                end_line: 8,
                snippet_hash: "hash".to_string(),
            },
            evidence: Vec::new(),
            reason: "accepted risk".to_string(),
            author: "tester".to_string(),
            created_at_unix: 1,
            expires_at_unix: 2,
            metadata: serde_json::json!({}),
        };

        let plain = suppressions_command_output(&workspace, &[record.clone()], false).unwrap();
        assert!(plain.contains("sup-1  src/lib.rs:7"));
        assert!(plain.ends_with('\n'));

        let json = suppressions_command_output(&workspace, &[record], true).unwrap();
        assert!(json.contains("\"id\": \"sup-1\""));
        assert!(json.ends_with('\n'));
    }

    #[test]
    fn plain_flag_suppresses_tty_startup_progress() {
        assert!(plain_output_requested(true));
        assert!(!should_emit_shell_startup_progress(true));
    }

    #[test]
    fn auth_ping_model_preserves_operator_override_then_config_then_default() {
        let mut config = kuzushi_core::V2Config::default();
        config.model = Some("openai:gpt-5.4".to_string());

        assert_eq!(
            auth_ping_model(Some("anthropic:claude-sonnet-4-5".to_string()), &config),
            "anthropic:claude-sonnet-4-5"
        );
        assert_eq!(auth_ping_model(None, &config), "openai:gpt-5.4");

        config.model = None;
        assert_eq!(auth_ping_model(None, &config), "anthropic:claude-haiku-4-5");
    }

    #[test]
    fn auth_ping_readiness_messages_cover_oauth_states() {
        let (ok, ready) =
            anthropic_oauth_readiness_message(kuzushi_openai::OauthReadiness::Ready {
                expires_at_ms: 0,
            });
        assert!(ok);
        assert!(ready.contains("oauth credentials ready"));

        let (ok, expired) =
            anthropic_oauth_readiness_message(kuzushi_openai::OauthReadiness::Expired {
                expires_at_ms: 0,
            });
        assert!(ok);
        assert!(expired.contains("will refresh on next call"));

        let missing_path = PathBuf::from("/tmp/kuzushi-oauth.json");
        let (ok, missing) =
            anthropic_oauth_readiness_message(kuzushi_openai::OauthReadiness::Missing {
                searched: missing_path.clone(),
            });
        assert!(!ok);
        assert!(missing.contains(&missing_path.display().to_string()));

        let (ok, invalid) =
            anthropic_oauth_readiness_message(kuzushi_openai::OauthReadiness::Invalid {
                searched: missing_path,
                reason: "malformed json".to_string(),
            });
        assert!(!ok);
        assert!(invalid.contains("malformed json"));
    }

    #[test]
    fn bridge_ping_error_and_summary_parse_bridge_json() {
        let parsed = parse_bridge_stdout(
            br#"{"ok":true,"auth_mode":"oauth","latency_ms":7,"input_tokens":2,"output_tokens":3,"cost_usd":0.0042}"#,
        )
        .unwrap();

        assert_eq!(bridge_ping_error(&parsed), None);
        assert_eq!(
            bridge_ping_summary(&parsed),
            "round-trip ok via oauth (7ms, 2/3 tokens, ~$0.00420)"
        );

        let failed = serde_json::json!({"ok": false, "error": "bad credentials"});
        assert_eq!(
            bridge_ping_error(&failed),
            Some("bad credentials".to_string())
        );
    }

    #[test]
    fn run_auth_ping_bridge_round_trips_json_over_stdio() {
        let mut log = AuthPingLog::default();
        let envelope = serde_json::json!({
            "ok": true,
            "auth_mode": "echo",
            "latency_ms": 1,
            "input_tokens": 0,
            "output_tokens": 0,
            "cost_usd": 0.0
        });

        let parsed = run_auth_ping_bridge(&["cat".to_string()], &envelope, &mut log).unwrap();

        assert_eq!(parsed, envelope);
    }

    #[test]
    fn config_show_and_path_commands_return_success() {
        let temp = tempfile::tempdir().unwrap();

        config_command(ConfigCommand::Show, Some(temp.path().to_path_buf())).unwrap();
        config_command(ConfigCommand::Path, None).unwrap();
    }

    #[test]
    fn config_init_guard_rejects_existing_path_unless_forced() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        std::fs::write(&path, "existing").unwrap();

        assert!(ensure_config_init_allowed(&path, false)
            .unwrap_err()
            .to_string()
            .contains("--force"));
        ensure_config_init_allowed(&path, true).unwrap();
    }

    #[test]
    fn run_tool_policy_predicates_cover_workspace_store_and_runtime() {
        assert!(tool_defaults_to_workspace(
            "systems-hunt:deep-semantic-hunt"
        ));
        assert!(tool_defaults_to_workspace("findings:list"));
        assert!(!tool_defaults_to_workspace("clang.health"));

        assert!(tool_needs_finding_store("variant:hunt"));
        assert!(tool_needs_finding_store("prompt-armor:scan"));
        assert!(!tool_needs_finding_store("context-lite:index"));

        assert!(tool_needs_runtime("deep-audit:run", &serde_json::json!({})));
        assert!(tool_needs_runtime(
            "sast:scan",
            &serde_json::json!({"triage": true})
        ));
        assert!(!tool_needs_runtime(
            "sast:scan",
            &serde_json::json!({"whiteboxStatic": true})
        ));
    }

    #[test]
    fn scan_helpers_format_scope_tasks_and_json_summary() {
        let scope = scan_scope_body(&[PathBuf::from("src/lib.rs"), PathBuf::from("Cargo.toml")]);
        assert_eq!(scope, "src/lib.rs\nCargo.toml\n");
        assert_eq!(scan_task_mode(&[]), "auto");
        assert_eq!(scan_task_mode(&["sast".to_string()]), "manual");
        assert_eq!(scan_worktree_suffix(true), "(+worktree)");
        assert_eq!(scan_worktree_suffix(false), "");

        let mut config = kuzushi_core::V2Config::default();
        config.model = Some("anthropic:claude-sonnet-4-5".to_string());
        assert!(scan_started_body(
            Path::new("."),
            &config,
            &["sast".to_string(), "triage".to_string()]
        )
        .contains("tasks=sast,triage"));

        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let data = serde_json::json!({
            "runId": "run-1",
            "target": ".",
            "findingsCount": 2,
            "mode": "standard",
            "whiteboxStatic": true,
            "triage": false,
        });
        let summary = scan_json_output(&workspace, &data);
        assert_eq!(summary["findingsCount"], serde_json::json!(2));
        assert!(summary["db"].as_str().unwrap().contains(".kuzushi"));
    }

    #[test]
    fn mcp_backend_binary_names_are_stable() {
        assert_eq!(McpBackend::Gtags.binary(), "kuzushi-mcp-gtags");
        assert_eq!(McpBackend::Clang.binary(), "kuzushi-mcp-clang");
        assert_eq!(McpBackend::Joern.binary(), "kuzushi-mcp-joern");
        assert!(mcp_spawn_error("kuzushi-mcp-gtags").contains("cargo build"));
        assert!(mcp_health_spawn_error("kuzushi-mcp-gtags").contains("--health"));
    }
}

fn wants_sast_runtime(input: &serde_json::Value) -> bool {
    let whitebox_static = kuzushi_core::whitebox_static_enabled(input).unwrap_or(false);
    let triage_runtime = input
        .get("triage")
        .or_else(|| input.get("aiTriage"))
        .or_else(|| input.get("ai_triage"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let execution_runtime = !whitebox_static
        && input
            .get("verify")
            .or_else(|| input.get("autoPatch"))
            .or_else(|| input.get("auto_patch"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

    triage_runtime
        || execution_runtime
        || input
            .get("tasks")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|tasks| {
                tasks
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .any(|task| {
                        matches!(
                            task.trim(),
                            "agentic"
                                | "agentic-sast"
                                | "agentic-sast:scan"
                                | "carlini"
                                | "threat-hunt"
                                | "carlini-threat-hunt"
                                | "carlini-threat-hunt:run"
                                | "taint"
                                | "iris"
                                | "taint-iris"
                                | "taint-iris:hunt"
                                | "taint-iris-next"
                                | "iris-next"
                                | "taint-next"
                                | "taint-iris-next:hunt"
                                | "systems"
                                | "systems-hunt"
                                | "systems-hunt:systems-hunt"
                                | "deep-semantic"
                                | "deep-semantic-hunt"
                                | "systems-hunt:deep-semantic-hunt"
                        )
                    })
            })
}

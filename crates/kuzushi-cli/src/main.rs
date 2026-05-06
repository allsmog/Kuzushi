use std::env;
use std::fs;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use kuzushi_core::config::write_default_config;
use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::{
    build_pr_comment, gateway_shortcut_active, load_config_for_target, AgentRuntime,
    FindingListFilter, FindingStore, ModuleRegistry, PrCommentInput, WorkspaceTarget,
    VERCEL_AI_GATEWAY_BASE_URL,
};
use kuzushi_openai::PiAgentCoreRuntime;
use kuzushi_tui::run_shell_with_plain;

#[derive(Debug, Parser)]
#[command(name = "kuzushi")]
#[command(about = "Kuzushi security copilot", version)]
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
        /// Run scanners through an executor backend. `local` (default) spawns
        /// scanners as subprocesses. `docker:<image>` routes each scanner
        /// invocation through `docker run --rm -v <target>:/workspace -w
        /// /workspace <image>`. `noop` errors on any execution.
        #[arg(long)]
        executor: Option<String>,
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
        #[arg(long)]
        json: bool,
    },
    /// Inspect or initialize config.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
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
    /// Snapshot the latest pipeline run for the active target.
    Status {
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Run the tool-augmented deep auditor on a single finding. Persists
    /// EvidenceCitations to the findings_evidence table and appends an
    /// `agent_type=deep_audit` AnalysisEntry to the finding's history.
    Audit {
        /// Finding fingerprint (full or unambiguous prefix) or alias (F-NNNN).
        fingerprint: String,
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long, default_value_t = 8)]
        max_steps: u32,
        #[arg(long, default_value_t = 0.50)]
        deposit_usd: f64,
        #[arg(long)]
        json: bool,
    },
    /// Cross-run aggregations: counts by severity, TP/FP ratio, total runs.
    Metrics {
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long, default_value_t = 20)]
        recent: usize,
        #[arg(long)]
        json: bool,
    },
    /// Scaffold .kuzushi/ for a project: writes a CONTEXT.md template, prints
    /// an agent prompt operators can paste into Claude/Codex to fill it in,
    /// and runs doctor. Idempotent.
    Init {
        target: Option<PathBuf>,
        /// Overwrite an existing .kuzushi/CONTEXT.md.
        #[arg(long)]
        force: bool,
        /// Skip the doctor preflight at the end.
        #[arg(long)]
        skip_doctor: bool,
    },
    /// Execute a native tool descriptor-backed command.
    Run {
        tool: String,
        #[arg(long, default_value = "{}")]
        input: String,
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let plain = plain_output_requested(cli.plain);
    let command = cli.command.unwrap_or(Command::Shell { target: None });

    match command {
        Command::Shell { target } => {
            let target = target.or(cli.target);
            if should_emit_shell_startup_progress(plain) {
                for line in shell_startup_progress_messages(target.as_deref()) {
                    eprintln!("{line}");
                }
            }
            let workspace = target
                .as_deref()
                .map(WorkspaceTarget::new)
                .transpose()
                .context("Could not resolve shell target")?;
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
            executor,
        } => scan_command(target, mode, tasks, triage, json, ci, executor).await,
        Command::Findings {
            target,
            limit,
            severity,
            verdict,
            name,
            file_path,
            json,
        } => findings_command(
            target.or(cli.target),
            FindingListFilter::from_parts(severity, verdict, name, file_path, limit)?,
            json,
        ),
        Command::Config { command } => config_command(command, cli.target),
        Command::Modules { json } => modules_command(json),
        Command::Tools { json } => tools_command(json),
        Command::Doctor { target, json } => doctor_command(target.or(cli.target), json),
        Command::Status { target, json } => status_command(target.or(cli.target), json),
        Command::Audit {
            fingerprint,
            target,
            max_steps,
            deposit_usd,
            json,
        } => audit_command(
            fingerprint,
            target.or(cli.target),
            max_steps,
            deposit_usd,
            json,
        ),
        Command::Metrics {
            target,
            recent,
            json,
        } => metrics_command(target.or(cli.target), recent, json),
        Command::Init {
            target,
            force,
            skip_doctor,
        } => init_command(target.or(cli.target), force, skip_doctor),
        Command::Run { tool, input } => run_tool_command(tool, input, cli.target),
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
    let mut messages = vec![
        "kuzushi: loading config and native registry...".to_string(),
        format!("kuzushi: target {target_label}; first finding: {scan_command}, then findings"),
    ];
    if gateway_shortcut_active() {
        messages.push(format!(
            "kuzushi: AI_GATEWAY_API_KEY detected; routing through {VERCEL_AI_GATEWAY_BASE_URL}"
        ));
    }
    messages
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
    let store = FindingStore::open(workspace.findings_db_path())?;
    let report = store.list_findings_filtered(&FindingListFilter::default())?;
    let input = PrCommentInput {
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
    };
    println!("{}", build_pr_comment(&input));
    Ok(())
}

async fn scan_command(
    target: PathBuf,
    mode: ScanModeArg,
    tasks: Vec<String>,
    triage: bool,
    json: bool,
    ci: bool,
    executor_spec: Option<String>,
) -> Result<()> {
    let workspace = WorkspaceTarget::new(&target)?;
    let config = load_config_for_target(Some(workspace.root()))?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let registry = ModuleRegistry::with_v2_builtins();
    let input = serde_json::json!({
        "mode": mode.as_input_value(),
        "taskMode": if tasks.is_empty() { "auto" } else { "manual" },
        "tasks": tasks,
        "triage": triage,
    });
    let runtime = if wants_sast_runtime(&input) {
        Some(PiAgentCoreRuntime::from_config(
            &config,
            std::env::current_dir()?,
        )?)
    } else {
        None
    };
    let executor: Option<Box<dyn kuzushi_core::Executor>> = match executor_spec.as_deref() {
        None | Some("local") => None,
        Some("noop") => Some(Box::new(kuzushi_core::NoopExecutor)),
        Some(other) if other.starts_with("docker:") => {
            let image = other.trim_start_matches("docker:").trim();
            anyhow::ensure!(!image.is_empty(), "executor=docker requires an image, e.g. docker:alpine:3.19");
            Some(Box::new(kuzushi_core::DockerExecutor::new(image)))
        }
        Some(other) if other.starts_with("sandbox:") => {
            let endpoint = other.trim_start_matches("sandbox:").trim();
            anyhow::ensure!(
                !endpoint.is_empty(),
                "executor=sandbox requires an endpoint, e.g. sandbox:https://api.example.com/v1"
            );
            let mut sandbox = kuzushi_core::SandboxExecutor::new(endpoint);
            if let Ok(key) = std::env::var("KUZUSHI_SANDBOX_API_KEY") {
                if !key.trim().is_empty() {
                    sandbox = sandbox.with_api_key(key);
                }
            }
            Some(Box::new(sandbox))
        }
        Some(other) => {
            anyhow::bail!(
                "unknown executor {other:?}. Try `local`, `docker:<image>`, `sandbox:<url>`, or `noop`."
            );
        }
    };
    let executor_ref: Option<&dyn kuzushi_core::Executor> = executor.as_deref();
    let ctx = if let Some(exec) = executor_ref {
        ToolExecutionContext::new(&config)
            .with_workspace(&workspace)
            .with_findings_store(&store)
            .with_executor(exec)
    } else {
        ToolExecutionContext::new(&config)
            .with_workspace(&workspace)
            .with_findings_store(&store)
    };

    let started = std::time::Instant::now();
    if ci {
        println!(
            "{}",
            ci_line(
                started,
                "scan",
                &format!(
                    "{} started [model={} tasks={}]",
                    target.display(),
                    config.model.as_deref().unwrap_or("unconfigured"),
                    if tasks.is_empty() {
                        "auto".to_string()
                    } else {
                        tasks.join(",")
                    },
                ),
            )
        );
        println!("{}", ci_line(started, "phase", "(init) → scanning"));
    }

    let result = registry.execute_tool_with_runtime(
        "sast:scan",
        input,
        &ctx,
        runtime.as_ref().map(|runtime| runtime as &dyn AgentRuntime),
    );
    let elapsed = started.elapsed();

    let result = match result {
        Ok(value) => value,
        Err(error) => {
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
            return Err(error);
        }
    };
    let data = result
        .get("data")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let count = data
        .get("findingsCount")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let cost = result
        .get("costUsd")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0);

    let run_id = data
        .get("runId")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);

    let report_path = match write_scan_report(
        &workspace,
        run_id.as_deref(),
        count,
        cost,
        elapsed,
        &config,
    ) {
        Ok(path) => Some(path),
        Err(error) => {
            eprintln!("warn: could not write run report: {error}");
            None
        }
    };

    if ci {
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
                    "{count} finding(s) · ${cost:.4} · {}",
                    format_duration(elapsed)
                )
            )
        );
        if let Some(report_path) = &report_path {
            println!(
                "{}",
                ci_line(started, "report", &report_path.display().to_string())
            );
        }
        println!("{}", ci_line(started, "exit", "0"));
        return Ok(());
    }

    if json {
        println!(
            "{}",
            serde_json::json!({
                "runId": data.get("runId").cloned(),
                "target": data.get("target").cloned(),
                "findingsCount": data.get("findingsCount").cloned(),
                "db": workspace.findings_db_path(),
                "mode": data.get("mode").cloned(),
                "whiteboxStatic": data.get("whiteboxStatic").cloned(),
                "triage": data.get("triage").cloned(),
                "report": report_path.as_ref().map(|path| path.display().to_string()),
            })
        );
    } else {
        if let Some(output) = result.get("output").and_then(serde_json::Value::as_str) {
            println!("{output}");
        }
        let counts = severity_counts_from_store(&workspace);
        println!();
        println!(
            "Scan complete: {count} finding(s){}{} · ${cost:.4} · {}",
            counts
                .as_ref()
                .map(|c| format!(" ({} crit, {} high, {} med, {} low)", c.0, c.1, c.2, c.3))
                .unwrap_or_default(),
            if counts.is_none() { " (severity breakdown unavailable)" } else { "" },
            format_duration(elapsed)
        );
        if let Some(report_path) = &report_path {
            println!("Report:  {}", report_path.display());
        }
        println!("Browse:  kuzushi findings --target {}", target.display());
        println!("Or open the shell with: kuzushi --target {}", target.display());
    }

    Ok(())
}

fn severity_counts_from_store(workspace: &WorkspaceTarget) -> Option<(usize, usize, usize, usize)> {
    use kuzushi_core::Severity;
    let store = FindingStore::open(workspace.findings_db_path()).ok()?;
    let report = store
        .list_findings_filtered(&FindingListFilter::default())
        .ok()?;
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    for finding in &report.findings {
        match finding.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low | Severity::Info => low += 1,
            Severity::Unknown => {}
        }
    }
    Some((critical, high, medium, low))
}

fn write_scan_report(
    workspace: &WorkspaceTarget,
    run_id: Option<&str>,
    count: u64,
    cost: f64,
    elapsed: std::time::Duration,
    config: &kuzushi_core::config::V2Config,
) -> Result<PathBuf> {
    let run_id = run_id.unwrap_or("latest");
    let dir = workspace
        .root()
        .join(".kuzushi")
        .join("runs")
        .join(run_id);
    fs::create_dir_all(&dir)
        .with_context(|| format!("Could not create {}", dir.display()))?;
    let path = dir.join("report.md");
    let store = FindingStore::open(workspace.findings_db_path())?;
    let report = store.list_findings_filtered(&FindingListFilter::default())?;
    let input = PrCommentInput {
        repo_name: workspace
            .root()
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string),
        findings: report.findings,
        cost_usd: cost,
        elapsed: Some(elapsed),
        run_url: None,
        top_n: Some(20),
        kuzushi_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        model: config.model.clone(),
        git_sha: None,
        run_id: Some(run_id.to_string()),
        changed_files: Vec::new(),
    };
    let body = format!(
        "# Kuzushi scan report\n\nrun: `{run_id}` · findings: {count} · cost: ${cost:.4} · elapsed: {}\n\n{}\n",
        format_duration(elapsed),
        build_pr_comment(&input)
    );
    fs::write(&path, body)
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
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

fn config_command(command: ConfigCommand, target: Option<PathBuf>) -> Result<()> {
    match command {
        ConfigCommand::Show => {
            let workspace = target.as_deref().map(WorkspaceTarget::new).transpose()?;
            let config = load_config_for_target(workspace.as_ref().map(WorkspaceTarget::root))?;
            println!("{}", serde_json::to_string_pretty(&config)?);
        }
        ConfigCommand::Init { force } => {
            let paths = kuzushi_core::ConfigPaths::from_target(None)?;
            let path = paths.global_config_path();
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite",
                    path.display()
                );
            }
            write_default_config(&path)?;
            println!("{}", path.display());
        }
        ConfigCommand::Path => {
            let paths = kuzushi_core::ConfigPaths::from_target(None)?;
            println!("{}", paths.global_config_path().display());
        }
    }
    Ok(())
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

const CONTEXT_TEMPLATE: &str = r#"# Project context for kuzushi

This file is read by every agentic tool kuzushi runs (triage, verify,
threat modelling). 50–100 lines focused on *this* repository pays for
itself many times over: it cuts false-positive rate, sharpens triage,
and tells the model what to ignore.

Replace each section below with project-specific facts. Delete sections
that don't apply.

## What this code does

One paragraph. The product, the surface, the audience.

## Trust boundaries

Where untrusted input enters. Where privileged operations happen. What
runs as which user / in which container.

## Authentication & authorization

How identity is established. Where authorization is checked. Known
gaps you've already accepted.

## Known false-positive sources

Patterns the scanner will flag that are intentional in this codebase
(e.g. "sandboxed eval in worker isolates is fine — see X.ts").

## Dangerous sinks worth re-reading

If we touch these files, slow down: payments, key derivation, raw
SQL, deserialization, child-process spawn.

## Out-of-scope

Vendored code, generated artifacts, abandoned modules.

## Conventions

How errors are handled. How config is loaded. Where the audit log
lives. What "secure-by-default" looks like in this repo.
"#;

const INIT_AGENT_PROMPT: &str = r#"You are filling in `.kuzushi/CONTEXT.md` for this repository.

Your job: read the codebase enough to replace each section of the
template with concrete, project-specific facts a security auditor
would want before triaging findings here. Aim for 50–100 lines total.

Concretely:
1. Read the repo's README, package.json/Cargo.toml/pyproject.toml, and the
   top of `src/`/`app/`/`lib/` to understand what this code does.
2. Search for HTTP route declarations, middleware, auth checks, raw SQL,
   child-process spawns, deserialization, eval/exec, key derivation.
3. Identify trust boundaries: where untrusted input enters, where privileged
   operations happen, what runs in what context.
4. Capture known false-positive sources (intentional patterns the scanner
   will flag) and dangerous sinks worth a second look.
5. Write the result to `.kuzushi/CONTEXT.md`, replacing the template
   sections in place. Keep it terse — fact density beats prose.
6. Commit the file when you're done.

When CONTEXT.md is good, run `kuzushi scan .` and `kuzushi findings` to
see kuzushi flow through it.
"#;

fn init_command(target: Option<PathBuf>, force: bool, skip_doctor: bool) -> Result<()> {
    let target = target.unwrap_or_else(|| PathBuf::from("."));
    let target = target
        .canonicalize()
        .with_context(|| format!("Could not resolve {}", target.display()))?;
    let kuzushi_dir = target.join(".kuzushi");
    fs::create_dir_all(&kuzushi_dir)
        .with_context(|| format!("Could not create {}", kuzushi_dir.display()))?;
    let context_path = kuzushi_dir.join("CONTEXT.md");
    let context_status = if context_path.exists() && !force {
        "kept (exists)"
    } else {
        fs::write(&context_path, CONTEXT_TEMPLATE)
            .with_context(|| format!("Could not write {}", context_path.display()))?;
        if force {
            "overwritten (--force)"
        } else {
            "wrote template"
        }
    };

    // Roll the previously-separate `kuzushi config init` into the same
    // verb: if the global config file is missing, write defaults so the
    // operator doesn't have to learn a second subcommand. Existing files
    // are kept (the `config init --force` path is still available
    // separately if a wholesale reset is wanted).
    let global_paths = kuzushi_core::ConfigPaths::from_target(None)?;
    let global_path = global_paths.global_config_path();
    let global_status = if global_path.exists() {
        "kept (exists)"
    } else {
        write_default_config(&global_path)?;
        "wrote defaults"
    };

    println!("Kuzushi init");
    println!("Target:        {}", target.display());
    println!("State dir:     {}", kuzushi_dir.display());
    println!("CONTEXT.md:    {context_status}");
    println!("Global config: {} ({})", global_path.display(), global_status);
    println!();
    println!("Paste this into Claude Code or Codex to fill in CONTEXT.md:");
    println!();
    for line in INIT_AGENT_PROMPT.lines() {
        println!("  {line}");
    }
    println!();

    if !skip_doctor {
        let report = build_doctor_report(target.clone());
        print_doctor_plain(&report);
        if report.has_failures() {
            anyhow::bail!(
                "init wrote CONTEXT.md, but doctor found {} failing check(s). Fix the listed next steps and rerun `kuzushi doctor`.",
                report.failures()
            );
        }
    }

    println!();
    println!("Ready. Next: `kuzushi scan {}` (or run `kuzushi` to enter the shell).", target.display());
    Ok(())
}

fn audit_command(
    fingerprint: String,
    target: Option<PathBuf>,
    max_steps: u32,
    deposit_usd: f64,
    json: bool,
) -> Result<()> {
    use kuzushi_core::{
        agent_router::{AgentRouter, RoutedRuntime},
        deep_auditor::{run_deep_auditor, save_evidence, DeepAuditConfig},
        spend::SpendLimiter,
    };
    use std::sync::Arc;

    let target = target.unwrap_or_else(|| PathBuf::from("."));
    let workspace = WorkspaceTarget::new(&target)?;
    let config = load_config_for_target(Some(workspace.root()))?;
    let store = FindingStore::open(workspace.findings_db_path())?;

    let finding = store
        .get_finding_by_reference(fingerprint.trim())?
        .with_context(|| format!("no finding matches {fingerprint:?}"))?;
    let finding_id = finding
        .id
        .context("audit: loaded finding has no SQLite id")?;
    let finding_fingerprint = finding.fingerprint.clone();

    let bridge = kuzushi_openai::PiAgentCoreRuntime::from_config(&config, std::env::current_dir()?)
        .context("audit: pi-agent-core runtime")?;
    let router = AgentRouter::default();
    let routed = RoutedRuntime::new(
        Arc::new(bridge),
        Arc::new(router),
        config.model.clone(),
    );

    let spend_path = workspace
        .root()
        .join(".kuzushi")
        .join("v2")
        .join("spend.sqlite3");
    let limiter = SpendLimiter::open(&spend_path).ok();

    let cfg = DeepAuditConfig {
        workspace_root: workspace.root().to_path_buf(),
        max_steps,
        deposit_usd,
        system_prompt: None,
    };

    let outcome = run_deep_auditor(&routed, limiter.as_ref(), &cfg, &finding)
        .context("deep auditor failed")?;

    if let Err(error) = save_evidence(
        &workspace.findings_db_path(),
        finding_id,
        &outcome.evidence,
    ) {
        eprintln!("[warn] could not persist evidence rows: {error}");
    }

    let model = config.model.clone().unwrap_or_else(|| "(unknown)".to_string());
    if let Err(error) = store.record_analysis(
        &finding_fingerprint,
        finding.scan_id.as_deref().unwrap_or("audit"),
        "deep_audit",
        &model,
        outcome.cost_usd,
        &kuzushi_core::RefusalReport::default(),
    ) {
        eprintln!("[warn] could not record audit history: {error}");
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "fingerprint": finding_fingerprint,
                "verdict": outcome.triage.verdict.as_str(),
                "confidence": outcome.triage.confidence,
                "rationale": outcome.triage.rationale,
                "evidence": outcome.evidence,
                "costUsd": outcome.cost_usd,
                "stepsUsed": outcome.steps_used,
                "truncated": outcome.truncated,
            }))?
        );
        return Ok(());
    }

    println!("Kuzushi audit");
    println!("Finding:       {finding_fingerprint}");
    println!(
        "Verdict:       {} ({:.2})",
        outcome.triage.verdict.as_str(),
        outcome.triage.confidence
    );
    println!("Cost:          ${:.4}", outcome.cost_usd);
    println!(
        "Steps:         {}{}",
        outcome.steps_used,
        if outcome.truncated { " (truncated)" } else { "" }
    );
    if !outcome.evidence.is_empty() {
        println!();
        println!("Evidence ({}):", outcome.evidence.len());
        for citation in &outcome.evidence {
            let kind = if citation.kind.is_empty() {
                "".to_string()
            } else {
                format!(" [{}]", citation.kind)
            };
            println!(
                "  {}:{}-{}{}{}",
                citation.file,
                citation.start_line,
                citation.end_line,
                kind,
                if citation.note.is_empty() {
                    String::new()
                } else {
                    format!(" — {}", citation.note)
                }
            );
        }
    }
    if !outcome.triage.rationale.is_empty() {
        println!();
        println!("Rationale:");
        for line in outcome.triage.rationale.lines() {
            println!("  {line}");
        }
    }

    Ok(())
}

fn status_command(target: Option<PathBuf>, json: bool) -> Result<()> {
    let target = target.unwrap_or_else(|| PathBuf::from("."));
    let workspace = WorkspaceTarget::new(&target)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let latest = store.latest_scan_run()?;
    let by_severity = store.aggregate_severity_counts()?;
    let by_verdict = store.aggregate_verdict_counts()?;
    let total_findings: usize = by_severity.iter().map(|(_, count)| count).sum();
    let report_path = latest.as_ref().and_then(|run| {
        let path = workspace
            .root()
            .join(".kuzushi")
            .join("runs")
            .join(&run.id)
            .join("report.md");
        path.exists().then_some(path)
    });

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "target": workspace.root(),
                "latestRun": latest,
                "totalFindings": total_findings,
                "bySeverity": by_severity
                    .iter()
                    .map(|(severity, count)| (severity.as_str().to_string(), *count))
                    .collect::<std::collections::BTreeMap<String, usize>>(),
                "byVerdict": by_verdict
                    .iter()
                    .cloned()
                    .collect::<std::collections::BTreeMap<String, usize>>(),
                "report": report_path,
            }))?
        );
        return Ok(());
    }

    println!("Kuzushi status");
    println!("Target:        {}", workspace.root().display());
    match latest {
        None => {
            println!("Latest run:    (none)");
            println!();
            println!("No scans on disk yet. Next: kuzushi scan {}", target.display());
        }
        Some(run) => {
            println!(
                "Latest run:    {} · {} · started {}{}",
                run.id,
                run.status,
                run.started_at,
                run.completed_at
                    .as_deref()
                    .map(|completed| format!(" · completed {completed}"))
                    .unwrap_or_default()
            );
            println!("Run findings:  {}", run.findings_count);
            println!("Total findings (all runs): {total_findings}");
            if !by_severity.is_empty() {
                let line = by_severity
                    .iter()
                    .map(|(severity, count)| format!("{} {count}", severity.as_str()))
                    .collect::<Vec<_>>()
                    .join(" · ");
                println!("By severity:   {line}");
            }
            if !by_verdict.is_empty() {
                let line = by_verdict
                    .iter()
                    .map(|(verdict, count)| format!("{verdict} {count}"))
                    .collect::<Vec<_>>()
                    .join(" · ");
                println!("By verdict:    {line}");
            }
            if let Some(path) = report_path {
                println!("Report:        {}", path.display());
            }
        }
    }
    Ok(())
}

fn metrics_command(target: Option<PathBuf>, recent: usize, json: bool) -> Result<()> {
    let target = target.unwrap_or_else(|| PathBuf::from("."));
    let workspace = WorkspaceTarget::new(&target)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let runs = store.list_scan_runs(recent.max(1))?;
    let by_severity = store.aggregate_severity_counts()?;
    let by_verdict = store.aggregate_verdict_counts()?;
    let total_findings: usize = by_severity.iter().map(|(_, count)| count).sum();
    let total_runs = runs.len();

    let analysis_summary = aggregate_analysis_history(&store)?;

    let tp = verdict_count(&by_verdict, "true_positive");
    let fp = verdict_count(&by_verdict, "false_positive");
    let triaged = tp + fp;
    let tp_rate = if triaged > 0 {
        Some((tp as f64) / (triaged as f64))
    } else {
        None
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "target": workspace.root(),
                "recentRuns": runs,
                "totalFindings": total_findings,
                "bySeverity": by_severity
                    .iter()
                    .map(|(severity, count)| (severity.as_str().to_string(), *count))
                    .collect::<std::collections::BTreeMap<String, usize>>(),
                "byVerdict": by_verdict
                    .iter()
                    .cloned()
                    .collect::<std::collections::BTreeMap<String, usize>>(),
                "truePositive": tp,
                "falsePositive": fp,
                "tpRate": tp_rate,
                "analysisHistory": {
                    "entries": analysis_summary.total_entries,
                    "findingsCovered": analysis_summary.findings_covered,
                    "byAgentType": analysis_summary.by_agent_type
                        .iter()
                        .cloned()
                        .collect::<std::collections::BTreeMap<String, usize>>(),
                    "totalCostUsd": analysis_summary.total_cost_usd,
                    "refusalEntries": analysis_summary.refusal_entries,
                },
            }))?
        );
        return Ok(());
    }

    println!("Kuzushi metrics");
    println!("Target:                 {}", workspace.root().display());
    println!("Total runs (recent):    {total_runs}");
    println!("Total findings (db):    {total_findings}");
    if !by_severity.is_empty() {
        let line = by_severity
            .iter()
            .map(|(severity, count)| format!("{:>9} {count}", severity.as_str()))
            .collect::<Vec<_>>()
            .join(" · ");
        println!("By severity:            {line}");
    }
    if !by_verdict.is_empty() {
        let line = by_verdict
            .iter()
            .map(|(verdict, count)| format!("{verdict} {count}"))
            .collect::<Vec<_>>()
            .join(" · ");
        println!("By verdict:             {line}");
    }
    println!(
        "TP: {tp} · FP: {fp} · TP rate: {}",
        tp_rate
            .map(|rate| format!("{:.1}%", rate * 100.0))
            .unwrap_or_else(|| "n/a".to_string())
    );
    if analysis_summary.total_entries > 0 {
        println!();
        println!(
            "Analysis history:       {} entr(y|ies) across {} finding(s){}",
            analysis_summary.total_entries,
            analysis_summary.findings_covered,
            if analysis_summary.refusal_entries > 0 {
                format!(" · {} ⚠ refusal(s)", analysis_summary.refusal_entries)
            } else {
                String::new()
            }
        );
        if !analysis_summary.by_agent_type.is_empty() {
            let line = analysis_summary
                .by_agent_type
                .iter()
                .map(|(agent, count)| format!("{agent} {count}"))
                .collect::<Vec<_>>()
                .join(" · ");
            println!("By agent type:          {line}");
        }
        if analysis_summary.total_cost_usd > 0.0 {
            println!(
                "Total recorded cost:    ${:.4}",
                analysis_summary.total_cost_usd
            );
        }
    }
    if !runs.is_empty() {
        println!();
        println!("Recent runs:");
        println!("  {:<32} {:<10} {:>10}  {}", "id", "status", "findings", "started");
        for run in &runs {
            println!(
                "  {:<32} {:<10} {:>10}  {}",
                run.id,
                run.status,
                run.findings_count,
                run.started_at
            );
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
struct AnalysisSummary {
    total_entries: usize,
    findings_covered: usize,
    by_agent_type: Vec<(String, usize)>,
    total_cost_usd: f64,
    refusal_entries: usize,
}

fn aggregate_analysis_history(store: &FindingStore) -> Result<AnalysisSummary> {
    let report = store.list_findings_filtered(&FindingListFilter::default())?;
    let mut summary = AnalysisSummary::default();
    let mut by_agent: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for finding in &report.findings {
        let history = store.get_analysis_history(&finding.fingerprint)?;
        if history.is_empty() {
            continue;
        }
        summary.findings_covered += 1;
        summary.total_entries += history.len();
        for entry in history {
            *by_agent.entry(entry.agent_type.clone()).or_default() += 1;
            summary.total_cost_usd += entry.cost_usd;
            if entry.refusal.refused {
                summary.refusal_entries += 1;
            }
        }
    }
    summary.by_agent_type = by_agent.into_iter().collect();
    Ok(summary)
}

fn verdict_count(by_verdict: &[(String, usize)], target: &str) -> usize {
    by_verdict
        .iter()
        .find(|(verdict, _)| verdict == target)
        .map(|(_, count)| *count)
        .unwrap_or(0)
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
    let workspace = match target.as_deref() {
        Some(target) => Some(WorkspaceTarget::new(target)?),
        None if tool.starts_with("findings:")
            || tool.starts_with("context:")
            || tool.starts_with("recon:")
            || tool.starts_with("vendor-assessment:")
            || tool.starts_with("chrome-rce:")
            || tool.starts_with("vuln-scout:")
            || tool.starts_with("tob:")
            || tool.starts_with("shinsa:")
            || tool.starts_with("prompt-armor:")
            || tool.starts_with("x-ray:")
            || tool.starts_with("threat-model:")
            || tool.starts_with("randori:")
            || tool.starts_with("variant:")
            || tool.starts_with("ndiff:")
            || tool.starts_with("systems-hunt:")
            || tool == "carlini-threat-hunt:run"
            || tool == "agentic-sast:scan"
            || tool == "taint-iris:hunt"
            || tool == "taint-iris-next:hunt"
            || tool == "triage:run"
            || tool == "verify:finding"
            || tool == "patch:finding"
            || tool == "context-lite:index"
            || matches!(
                tool.as_str(),
                "sast:scan" | "semgrep:scan" | "codeql:scan" | "iac-scan:scan"
            ) =>
        {
            Some(WorkspaceTarget::new(".")?)
        }
        None => None,
    };
    let config = load_config_for_target(workspace.as_ref().map(WorkspaceTarget::root))?;
    let store = workspace
        .as_ref()
        .filter(|_| {
            tool.starts_with("findings:")
                || tool == "triage:run"
                || tool == "verify:finding"
                || tool == "patch:finding"
                || tool == "agentic-sast:scan"
                || tool == "carlini-threat-hunt:run"
                || tool.starts_with("chrome-rce:")
                || tool == "vuln-scout:audit"
                || tool == "tob:audit"
                || matches!(
                    tool.as_str(),
                    "shinsa:scan"
                        | "shinsa:quick-check"
                        | "shinsa:nist-scan"
                        | "shinsa:nist-quick-check"
                        | "prompt-armor:scan"
                        | "prompt-armor:analyze"
                        | "prompt-armor:attack"
                )
                || tool.starts_with("variant:")
                || tool == "ndiff:hunt-variants"
                || tool.starts_with("systems-hunt:")
                || tool == "taint-iris:hunt"
                || tool == "taint-iris-next:hunt"
                || matches!(
                    tool.as_str(),
                    "sast:scan" | "semgrep:scan" | "codeql:scan" | "iac-scan:scan"
                )
        })
        .map(|workspace| FindingStore::open(workspace.findings_db_path()))
        .transpose()?;
    let input = serde_json::from_str(&input).context("--input must be JSON")?;
    let registry = ModuleRegistry::with_v2_builtins();
    let runtime = if matches!(
        tool.as_str(),
        "triage:run"
            | "verify:finding"
            | "patch:finding"
            | "agentic-sast:scan"
            | "carlini-threat-hunt:run"
            | "vendor-assessment:assess"
            | "vuln-scout:audit"
            | "tob:audit"
            | "shinsa:scan"
            | "shinsa:quick-check"
            | "shinsa:nist-scan"
            | "shinsa:nist-quick-check"
            | "prompt-armor:scan"
            | "prompt-armor:analyze"
            | "prompt-armor:attack"
            | "variant:lift-pattern"
            | "variant:hunt"
            | "ndiff:extract-fix-pattern"
            | "ndiff:hunt-variants"
            | "systems-hunt:systems-invariant-extract"
            | "systems-hunt:systems-trigger-synth"
            | "systems-hunt:systems-hunt"
            | "systems-hunt:deep-semantic-cwe-select"
            | "systems-hunt:deep-semantic-hunt"
            | "taint-iris:hunt"
            | "taint-iris-next:hunt"
    ) {
        Some(PiAgentCoreRuntime::from_config(
            &config,
            std::env::current_dir()?,
        )?)
    } else if tool == "sast:scan" && wants_sast_runtime(&input) {
        Some(PiAgentCoreRuntime::from_config(
            &config,
            std::env::current_dir()?,
        )?)
    } else if matches!(
        tool.as_str(),
        "threat-model:build" | "randori:pasta" | "x-ray:run" | "x-ray:x-ray"
    ) {
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
        spend: None,
        executor: None,
    };
    let output = registry.execute_tool_with_runtime(
        &tool,
        input,
        &ctx,
        runtime.as_ref().map(|runtime| runtime as &dyn AgentRuntime),
    )?;
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
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
    fn plain_flag_suppresses_tty_startup_progress() {
        assert!(plain_output_requested(true));
        assert!(!should_emit_shell_startup_progress(true));
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

use std::env;
use std::fs;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use kuzushi_core::config::write_default_config;
use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::{
    build_pr_comment, load_config_for_target, AgentRuntime, FindingListFilter, FindingStore,
    ModuleRegistry, PrCommentInput, WorkspaceTarget,
};
use kuzushi_openai::PiAgentCoreRuntime;
use kuzushi_tui::run_shell;

#[derive(Debug, Parser)]
#[command(name = "kuzushi")]
#[command(about = "Kuzushi security copilot", version)]
struct Cli {
    #[arg(long, global = true)]
    target: Option<PathBuf>,

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
        #[arg(long, value_delimiter = ',')]
        tasks: Vec<String>,
        #[arg(long)]
        triage: bool,
        #[arg(long)]
        json: bool,
        /// Emit one line per pipeline event in a deterministic, grep-friendly format.
        #[arg(long, conflicts_with = "json")]
        ci: bool,
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
    let command = cli.command.unwrap_or(Command::Shell { target: None });

    match command {
        Command::Shell { target } => {
            let target = target.or(cli.target);
            if should_emit_shell_startup_progress() {
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
            run_shell(config, workspace.as_ref())
        }
        Command::Scan {
            target,
            tasks,
            triage,
            json,
            ci,
        } => scan_command(target, tasks, triage, json, ci).await,
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

fn should_emit_shell_startup_progress() -> bool {
    io::stdin().is_terminal()
        && io::stdout().is_terminal()
        && io::stderr().is_terminal()
        && std::env::var_os("KUZUSHI_PLAIN").is_none()
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
    tasks: Vec<String>,
    triage: bool,
    json: bool,
    ci: bool,
) -> Result<()> {
    let workspace = WorkspaceTarget::new(&target)?;
    let config = load_config_for_target(Some(workspace.root()))?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let registry = ModuleRegistry::with_v2_builtins();
    let input = serde_json::json!({
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
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
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
                "triage": data.get("triage").cloned(),
            })
        );
    } else {
        if let Some(output) = result.get("output").and_then(serde_json::Value::as_str) {
            println!("{output}");
        }
    }

    Ok(())
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
}

fn wants_sast_runtime(input: &serde_json::Value) -> bool {
    input
        .get("triage")
        .or_else(|| input.get("aiTriage"))
        .or_else(|| input.get("ai_triage"))
        .or_else(|| input.get("verify"))
        .or_else(|| input.get("autoPatch"))
        .or_else(|| input.get("auto_patch"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
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

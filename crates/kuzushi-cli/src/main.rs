use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use kuzushi_core::config::write_default_config;
use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::{
    load_config_for_target, AgentRuntime, FindingListFilter, FindingStore, ModuleRegistry,
    WorkspaceTarget,
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
    /// Execute a native tool descriptor-backed command.
    Run {
        tool: String,
        #[arg(long, default_value = "{}")]
        input: String,
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
        } => scan_command(target, tasks, triage, json).await,
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
        Command::Run { tool, input } => run_tool_command(tool, input, cli.target),
    }
}

async fn scan_command(target: PathBuf, tasks: Vec<String>, triage: bool, json: bool) -> Result<()> {
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
    let result = registry.execute_tool_with_runtime(
        "sast:scan",
        input,
        &ctx,
        runtime.as_ref().map(|runtime| runtime as &dyn AgentRuntime),
    )?;
    let data = result
        .get("data")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

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

fn findings_command(target: Option<PathBuf>, filter: FindingListFilter, json: bool) -> Result<()> {
    let target = target.unwrap_or_else(|| PathBuf::from("."));
    let workspace = WorkspaceTarget::new(target)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let report = store.list_findings_filtered(&filter)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if report.findings.is_empty() {
        println!(
            "no findings found at {}",
            workspace.findings_db_path().display()
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

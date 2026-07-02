use crate::application::scan::scan_command;
use crate::command::Command;
use crate::mcp::mcp_command;
use crate::presentation::{shell_startup_progress_messages, should_emit_shell_startup_progress};
use anyhow::{Context, Result};
use kuzushi_core::{
    load_config_for_target, DynamicModuleLoadOptions, ModuleRegistry, WorkspaceTarget,
};
use kuzushi_tui::run_shell_with_plain;
use std::path::PathBuf;

mod catalog;
mod reporting;
mod run_command;

pub(crate) async fn dispatch_command(
    command: Command,
    default_target: Option<PathBuf>,
    plain: bool,
    load: Vec<String>,
    allow_untrusted_module: bool,
) -> Result<()> {
    match command {
        Command::Shell { target } => {
            dispatch_shell_command(target, default_target, plain, load, allow_untrusted_module)
        }
        scan @ Command::Scan { .. } => dispatch_scan_command(scan, default_target).await,
        other => {
            dispatch_non_scan_command(other, default_target, load, allow_untrusted_module).await
        }
    }
}

async fn dispatch_scan_command(command: Command, default_target: Option<PathBuf>) -> Result<()> {
    let Command::Scan {
        target,
        mode,
        tasks,
        triage,
        json,
        ci,
        budget,
        since,
        include_worktree,
        fail_on,
        sarif,
    } = command
    else {
        unreachable!("non-scan command routed to scan dispatcher")
    };
    let target = required_scan_target(target, default_target)?;
    let gate = crate::application::scan_gate::ScanGatePolicy {
        fail_on: fail_on.map(crate::command::FailOnArg::as_severity),
        sarif,
    };
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
        gate,
    )
    .await
}

fn required_scan_target(
    target: Option<PathBuf>,
    default_target: Option<PathBuf>,
) -> Result<PathBuf> {
    target.or(default_target).context(
        "scan needs a target: pass `kuzushi scan <path>` or the global `--target <path>` (use `.` for the current directory).",
    )
}

fn dispatch_shell_command(
    target: Option<PathBuf>,
    default_target: Option<PathBuf>,
    plain: bool,
    load: Vec<String>,
    allow_untrusted_module: bool,
) -> Result<()> {
    let target = target.or(default_target);
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
    let mut registry = ModuleRegistry::with_v2_builtins();
    load_dynamic_modules(&mut registry, &config, &load, allow_untrusted_module)?;
    run_shell_with_plain(config, workspace.as_ref(), plain, registry)
}

async fn dispatch_non_scan_command(
    command: Command,
    default_target: Option<PathBuf>,
    load: Vec<String>,
    allow_untrusted_module: bool,
) -> Result<()> {
    match command {
        Command::Findings { .. }
        | Command::Finding { .. }
        | Command::Runs { .. }
        | Command::Suppress { .. }
        | Command::Suppressions { .. }
        | Command::Permissions { .. }
        | Command::Doctor { .. }
        | Command::PrComment(_) => reporting::dispatch_reporting_command(command, default_target),
        Command::Config { .. }
        | Command::Auth { .. }
        | Command::Modules { .. }
        | Command::Tools { .. } => catalog::dispatch_catalog_command(command, default_target),
        Command::Run { .. } => {
            run_command::dispatch_run_command(command, default_target, load, allow_untrusted_module)
        }
        Command::Mcp { command } => mcp_command(command).await,
        Command::Demo { json } => crate::application::demo::demo_command(json).await,
        Command::Shell { .. } | Command::Scan { .. } => unreachable!("handled before dispatch"),
    }
}

pub(crate) fn load_dynamic_modules(
    registry: &mut ModuleRegistry,
    config: &kuzushi_core::V2Config,
    specifiers: &[String],
    allow_untrusted_module: bool,
) -> Result<()> {
    let options = DynamicModuleLoadOptions {
        allow_untrusted: allow_untrusted_module,
        trusted_specifiers: config.operator.trusted_modules.clone(),
    };
    for specifier in specifiers {
        registry.load_dynamic_module(specifier, &options)?;
    }
    Ok(())
}

fn target_or_default(target: Option<PathBuf>, default_target: &Option<PathBuf>) -> Option<PathBuf> {
    target.or_else(|| default_target.clone())
}

use crate::application::scan::scan_command;
use crate::command::Command;
use crate::mcp::mcp_command;
use crate::presentation::{shell_startup_progress_messages, should_emit_shell_startup_progress};
use crate::support::{require_cli_target, target_or_global};
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
) -> Result<()> {
    match command {
        Command::Shell { target } => dispatch_shell_command(target, default_target, plain, load),
        scan @ Command::Scan { .. } => dispatch_scan_command(scan, default_target).await,
        other => dispatch_non_scan_command(other, default_target, load).await,
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
    let target = require_cli_target("scan", target, default_target)?;
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

fn dispatch_shell_command(
    target: Option<PathBuf>,
    default_target: Option<PathBuf>,
    plain: bool,
    load: Vec<String>,
) -> Result<()> {
    let target = target_or_global(target, default_target);
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
    load_dynamic_modules(&mut registry, &load)?;
    run_shell_with_plain(config, workspace.as_ref(), plain, registry)
}

async fn dispatch_non_scan_command(
    command: Command,
    default_target: Option<PathBuf>,
    load: Vec<String>,
) -> Result<()> {
    match command {
        Command::Findings { .. }
        | Command::Finding { .. }
        | Command::Decision { .. }
        | Command::Runs { .. }
        | Command::Export { .. }
        | Command::Suppress { .. }
        | Command::Suppressions { .. }
        | Command::Permissions { .. }
        | Command::Doctor { .. }
        | Command::PrComment(_) => reporting::dispatch_reporting_command(command, default_target),
        Command::Config { .. }
        | Command::Auth { .. }
        | Command::Modules { .. }
        | Command::Kwp { .. }
        | Command::Tools { .. } => catalog::dispatch_catalog_command(command, default_target),
        Command::Run { .. } => run_command::dispatch_run_command(command, default_target, load),
        Command::Mcp { command } => mcp_command(command).await,
        Command::Demo { json } => crate::application::demo::demo_command(json).await,
        Command::Shell { .. } | Command::Scan { .. } => unreachable!("handled before dispatch"),
    }
}

pub(crate) fn load_dynamic_modules(
    registry: &mut ModuleRegistry,
    specifiers: &[String],
) -> Result<()> {
    let options = DynamicModuleLoadOptions {
        lockfile_path: Some(kuzushi_core::default_dynamic_lockfile_path()),
    };
    for specifier in specifiers {
        registry.load_dynamic_module(specifier, &options)?;
    }
    Ok(())
}

fn target_or_default(target: Option<PathBuf>, default_target: &Option<PathBuf>) -> Option<PathBuf> {
    target.or_else(|| default_target.clone())
}

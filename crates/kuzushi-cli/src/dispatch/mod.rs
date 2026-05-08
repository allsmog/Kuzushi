use crate::command::Command;
use crate::mcp::mcp_command;
use crate::scan::scan_command;
use crate::terminal::{shell_startup_progress_messages, should_emit_shell_startup_progress};
use anyhow::{Context, Result};
use kuzushi_core::{load_config_for_target, WorkspaceTarget};
use kuzushi_tui::run_shell_with_plain;
use std::path::PathBuf;

mod catalog;
mod reporting;
mod run_command;

pub(crate) async fn dispatch_command(
    command: Command,
    default_target: Option<PathBuf>,
    plain: bool,
) -> Result<()> {
    match command {
        Command::Shell { target } => dispatch_shell_command(target, default_target, plain),
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
        other => dispatch_non_scan_command(other, default_target).await,
    }
}

fn dispatch_shell_command(
    target: Option<PathBuf>,
    default_target: Option<PathBuf>,
    plain: bool,
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
    run_shell_with_plain(config, workspace.as_ref(), plain)
}

async fn dispatch_non_scan_command(
    command: Command,
    default_target: Option<PathBuf>,
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
        Command::Run { .. } => run_command::dispatch_run_command(command, default_target),
        Command::Mcp { command } => mcp_command(command).await,
        Command::Shell { .. } | Command::Scan { .. } => unreachable!("handled before dispatch"),
    }
}

fn target_or_default(target: Option<PathBuf>, default_target: &Option<PathBuf>) -> Option<PathBuf> {
    target.or_else(|| default_target.clone())
}

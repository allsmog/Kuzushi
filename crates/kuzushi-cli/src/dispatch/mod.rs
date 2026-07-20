use crate::application::scan::scan_command;
use crate::command::Command;
use crate::mcp::mcp_command;
use crate::presentation::{shell_startup_progress_messages, should_emit_shell_startup_progress};
use crate::support::{require_cli_target, target_or_global};
use anyhow::{Context, Result};
use kuzushi_core::{
    load_config_for_target, DynamicModuleLoadOptions, ModuleRegistry, WorkspaceTarget,
};
use kuzushi_tui::{run_shell_with_context, ShellLaunchContext, ShellTargetSource};
use std::path::PathBuf;

mod catalog;
mod reporting;
mod run_command;

pub(crate) async fn dispatch_command(
    command: Command,
    default_target: Option<PathBuf>,
    plain: bool,
    load: Vec<String>,
    no_session_persistence: bool,
    argv: Vec<String>,
) -> Result<()> {
    reject_session_persistence_flag_for_command(&command, no_session_persistence)?;
    reject_dynamic_load_for_command(&command, &load)?;
    match command {
        Command::Shell { target } => dispatch_shell_command(
            target,
            default_target,
            plain,
            load,
            no_session_persistence,
            argv,
        ),
        scan @ Command::Scan { .. } => dispatch_scan_command(scan, default_target).await,
        other => dispatch_non_scan_command(other, default_target, load).await,
    }
}

fn reject_session_persistence_flag_for_command(
    command: &Command,
    no_session_persistence: bool,
) -> Result<()> {
    if !no_session_persistence || matches!(command, Command::Shell { .. }) {
        return Ok(());
    }
    anyhow::bail!(
        "--no-session-persistence/--ephemeral is supported only by the shell; this command uses its existing run or reporting artifact contract"
    )
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
        shard,
        shard_manifest,
        paths,
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
    let scope = crate::application::scan::ScanScopeArgs {
        shard,
        shard_manifest,
        paths,
    };
    scan_command(
        target,
        mode,
        tasks,
        triage,
        json,
        ci,
        budget,
        scope,
        since,
        include_worktree,
        gate,
    )
    .await
}

fn reject_dynamic_load_for_command(command: &Command, specifiers: &[String]) -> Result<()> {
    if specifiers.is_empty() || matches!(command, Command::Shell { .. } | Command::Run { .. }) {
        return Ok(());
    }
    if matches!(command, Command::Scan { .. }) {
        anyhow::bail!(
            "--load is supported by shell and `kuzushi run`, not `kuzushi scan`. Next: invoke the trusted dynamic tool with `kuzushi --load <specifier> run <module:tool>`."
        );
    }
    anyhow::bail!(
        "--load is supported only by shell and `kuzushi run`; this command does not load dynamic modules. Next: remove `--load`, or invoke the trusted tool with `kuzushi --load <specifier> run <module:tool>`."
    )
}

#[cfg(test)]
mod tests {
    use super::{
        reject_dynamic_load_for_command, reject_session_persistence_flag_for_command,
        shell_target_source,
    };
    use crate::command::{Command, SessionsCommand};
    use kuzushi_tui::ShellTargetSource;
    use std::path::PathBuf;

    fn dynamic_specifier() -> Vec<String> {
        vec!["file:///tmp/module.mjs".to_string()]
    }

    #[test]
    fn scan_rejects_dynamic_load_instead_of_silently_discarding_it() {
        let command = Command::Scan {
            target: None,
            mode: None,
            tasks: Vec::new(),
            triage: None,
            json: false,
            ci: false,
            budget: None,
            shard: None,
            shard_manifest: None,
            paths: Vec::new(),
            since: None,
            include_worktree: false,
            fail_on: None,
            sarif: None,
        };
        let error = reject_dynamic_load_for_command(&command, &dynamic_specifier())
            .unwrap_err()
            .to_string();

        assert!(error.contains("not `kuzushi scan`"), "{error}");
        assert!(error.contains("kuzushi --load <specifier> run"), "{error}");
    }

    #[test]
    fn metadata_doctor_and_findings_commands_reject_dynamic_load() {
        let commands = [
            Command::Modules { json: false },
            Command::Doctor { json: false },
            Command::Sessions {
                command: SessionsCommand::List { json: false },
            },
            Command::Findings {
                limit: 50,
                severity: Vec::new(),
                verdict: Vec::new(),
                decision: Vec::new(),
                completeness: Vec::new(),
                status: Vec::new(),
                confidence: Vec::new(),
                state: Vec::new(),
                name: None,
                file_path: None,
                vuln_source: Vec::new(),
                json: false,
            },
        ];

        for command in commands {
            let error = reject_dynamic_load_for_command(&command, &dynamic_specifier())
                .unwrap_err()
                .to_string();
            assert!(error.contains("supported only by shell"), "{error}");
        }
    }

    #[test]
    fn shell_and_run_are_the_only_dynamic_load_surfaces() {
        let shell = Command::Shell { target: None };
        let run = Command::Run {
            tool: "example:run".to_string(),
            input: "{}".to_string(),
            options: Vec::new(),
            autonomy: None,
            run_id: None,
        };

        assert!(reject_dynamic_load_for_command(&shell, &dynamic_specifier()).is_ok());
        assert!(reject_dynamic_load_for_command(&run, &dynamic_specifier()).is_ok());
        assert!(reject_dynamic_load_for_command(&Command::Modules { json: false }, &[]).is_ok());
    }

    #[test]
    fn session_persistence_opt_out_is_shell_only() {
        assert!(reject_session_persistence_flag_for_command(
            &Command::Shell { target: None },
            true
        )
        .is_ok());

        let error =
            reject_session_persistence_flag_for_command(&Command::Modules { json: false }, true)
                .unwrap_err()
                .to_string();
        assert!(error.contains("supported only by the shell"), "{error}");
        assert!(reject_session_persistence_flag_for_command(
            &Command::Modules { json: false },
            false
        )
        .is_ok());
    }

    #[test]
    fn shell_target_provenance_precedes_target_resolution() {
        let shell = PathBuf::from("/shell");
        let global = PathBuf::from("/global");

        assert_eq!(
            shell_target_source(Some(&shell), Some(&global)),
            ShellTargetSource::ShellFlag
        );
        assert_eq!(
            shell_target_source(None, Some(&global)),
            ShellTargetSource::GlobalFlag
        );
        assert_eq!(shell_target_source(None, None), ShellTargetSource::None);
    }
}

fn dispatch_shell_command(
    target: Option<PathBuf>,
    default_target: Option<PathBuf>,
    plain: bool,
    load: Vec<String>,
    no_session_persistence: bool,
    argv: Vec<String>,
) -> Result<()> {
    let target_source = shell_target_source(target.as_ref(), default_target.as_ref());
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
    load_dynamic_modules(&mut registry, &config, &load)?;
    run_shell_with_context(
        config,
        workspace.as_ref(),
        plain,
        registry,
        ShellLaunchContext {
            argv,
            target_source,
            session_persistence: !no_session_persistence,
        },
    )
}

fn shell_target_source(
    shell_target: Option<&PathBuf>,
    global_target: Option<&PathBuf>,
) -> ShellTargetSource {
    if shell_target.is_some() {
        ShellTargetSource::ShellFlag
    } else if global_target.is_some() {
        ShellTargetSource::GlobalFlag
    } else {
        ShellTargetSource::None
    }
}

/// `kuzushi ci` owns its documented exit-code contract (0/1/2), so nonzero
/// outcomes exit the process here instead of surfacing as anyhow errors
/// (which the top level would map to a generic failure exit).
fn dispatch_ci_command(
    target: Option<PathBuf>,
    fail_on: crate::command::FailOnArg,
    update_baseline: bool,
    summary: Option<PathBuf>,
    default_target: Option<PathBuf>,
) -> Result<()> {
    let options = crate::application::ci::CiOptions {
        fail_on: fail_on.as_severity(),
        update_baseline,
        summary_path: summary,
    };
    let result = crate::support::require_cli_target("ci", target, default_target)
        .and_then(|target| crate::application::ci::ci_command(target, options));
    let code = crate::application::ci::ci_process_exit(result);
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
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
        Command::Ci {
            target,
            fail_on,
            update_baseline,
            summary,
        } => dispatch_ci_command(target, fail_on, update_baseline, summary, default_target),
        Command::Sessions { command } => {
            crate::application::sessions::sessions_command(command, default_target)
        }
        Command::Config { .. }
        | Command::Auth { .. }
        | Command::Modules { .. }
        | Command::Kwp { .. }
        | Command::Tools { .. } => catalog::dispatch_catalog_command(command, default_target),
        Command::Run { .. } => run_command::dispatch_run_command(command, default_target, load),
        Command::Campaign { command } => {
            crate::application::campaign_run::campaign_command(command, default_target).await
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
) -> Result<()> {
    let options = DynamicModuleLoadOptions {
        trusted_specifiers: config.operator.trusted_modules.clone(),
        lockfile_path: Some(kuzushi_core::default_dynamic_lockfile_path()),
    };
    for specifier in specifiers {
        registry.load_dynamic_module(specifier, &options)?;
    }
    Ok(())
}

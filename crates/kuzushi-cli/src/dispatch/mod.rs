use crate::application::scan::scan_command;
use crate::command::Command;
use crate::mcp::mcp_command;
use crate::presentation::{shell_startup_progress_messages, should_emit_shell_startup_progress};
use crate::support::{require_cli_target, resolve_cli_target};
use anyhow::{Context, Result};
use kuzushi_core::{DynamicModuleLoadOptions, ModuleRegistry, WorkspaceTarget};
use kuzushi_tui::{
    run_shell_with_context_and_config_diagnostics, ShellLaunchContext, ShellTargetSource,
};
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
        Command::Shell {} => dispatch_shell_command(
            default_target,
            plain,
            load,
            ShellSessionFlags {
                no_session_persistence,
                argv,
            },
        ),
        scan @ Command::Scan(_) => dispatch_scan_command(scan, default_target).await,
        investigate @ Command::Investigate(_) => {
            dispatch_investigate_command(investigate, default_target).await
        }
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
    let request = scan_dispatch_request(command, default_target)?;
    anyhow::ensure!(
        request.trials != 1 || request.workers == 1,
        "--workers only applies when --trials is at least 2"
    );
    if request.trials != 1 {
        return crate::application::scan_batch::scan_batch_command(request).await;
    }
    dispatch_single_scan(request).await
}

fn scan_dispatch_request(
    command: Command,
    default_target: Option<PathBuf>,
) -> Result<crate::application::scan_batch::ScanBatchRequest> {
    let Command::Scan(args) = command else {
        unreachable!("non-scan command routed to scan dispatcher")
    };
    let target = require_cli_target("scan", args.target, default_target)?;
    Ok(crate::application::scan_batch::ScanBatchRequest {
        target,
        mode: args.mode,
        tasks: args.tasks,
        triage: args.triage,
        json: args.json,
        ci: args.ci,
        budget: args.budget,
        scope: scan_scope(args.shard, args.shard_manifest, args.paths),
        since: args.since,
        include_worktree: args.include_worktree,
        gate: scan_gate(args.fail_on, args.sarif),
        trials: args.trials,
        workers: args.workers,
    })
}

fn scan_scope(
    shard: Option<String>,
    shard_manifest: Option<PathBuf>,
    paths: Vec<String>,
) -> crate::application::scan::ScanScopeArgs {
    crate::application::scan::ScanScopeArgs {
        shard,
        shard_manifest,
        paths,
    }
}

fn scan_gate(
    fail_on: Option<crate::command::FailOnArg>,
    sarif: Option<PathBuf>,
) -> crate::application::scan_gate::ScanGatePolicy {
    crate::application::scan_gate::ScanGatePolicy {
        fail_on: fail_on.map(crate::command::FailOnArg::as_severity),
        sarif,
    }
}

async fn dispatch_single_scan(
    request: crate::application::scan_batch::ScanBatchRequest,
) -> Result<()> {
    scan_command(
        request.target,
        request.mode,
        request.tasks,
        request.triage,
        request.json,
        request.ci,
        request.budget,
        request.scope,
        request.since,
        request.include_worktree,
        request.gate,
    )
    .await
}

async fn dispatch_investigate_command(
    command: Command,
    default_target: Option<PathBuf>,
) -> Result<()> {
    let Command::Investigate(args) = command else {
        unreachable!("non-investigate command routed to investigate dispatcher")
    };
    crate::application::investigate::investigate_command(investigate_request(args, default_target)?)
        .await
}

fn investigate_request(
    args: crate::command::InvestigateArgs,
    default_target: Option<PathBuf>,
) -> Result<crate::application::investigate::InvestigateRequest> {
    let target = require_cli_target("investigate", args.target, default_target)?;
    let gate = crate::application::scan_gate::ScanGatePolicy {
        fail_on: args.fail_on.map(crate::command::FailOnArg::as_severity),
        sarif: args.sarif,
    };
    Ok(crate::application::investigate::InvestigateRequest {
        target,
        profile: args.profile,
        plan: args.plan,
        json: args.json,
        ci: args.ci,
        scope: crate::application::scan::ScanScopeArgs {
            shard: args.shard,
            shard_manifest: args.shard_manifest,
            paths: args.paths,
        },
        gate,
    })
}

fn reject_dynamic_load_for_command(command: &Command, specifiers: &[String]) -> Result<()> {
    if specifiers.is_empty() || matches!(command, Command::Shell { .. } | Command::Run { .. }) {
        return Ok(());
    }
    if matches!(command, Command::Scan(_) | Command::Investigate(_)) {
        anyhow::bail!(
            "--load is supported by shell and `kuzushi run`, not scan or investigate. Next: invoke the trusted dynamic tool with `kuzushi --load <specifier> run <module:tool>`."
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
    use crate::command::{Command, InvestigateArgs, SessionsCommand};
    use kuzushi_tui::ShellTargetSource;
    use std::path::PathBuf;

    fn dynamic_specifier() -> Vec<String> {
        vec!["file:///tmp/module.mjs".to_string()]
    }

    #[test]
    fn scan_rejects_dynamic_load_instead_of_silently_discarding_it() {
        let command = Command::Scan(crate::command::ScanArgs {
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
            trials: 1,
            workers: 1,
        });
        let error = reject_dynamic_load_for_command(&command, &dynamic_specifier())
            .unwrap_err()
            .to_string();

        assert!(error.contains("not scan or investigate"), "{error}");
        assert!(error.contains("kuzushi --load <specifier> run"), "{error}");
    }

    #[test]
    fn investigate_rejects_dynamic_load_instead_of_ignoring_it() {
        let command = Command::Investigate(InvestigateArgs {
            target: None,
            profile: "standard".to_string(),
            plan: false,
            json: false,
            ci: false,
            shard: None,
            shard_manifest: None,
            paths: Vec::new(),
            fail_on: None,
            sarif: None,
        });
        let error = reject_dynamic_load_for_command(&command, &dynamic_specifier())
            .unwrap_err()
            .to_string();

        assert!(error.contains("not scan or investigate"), "{error}");
    }

    #[test]
    fn metadata_doctor_and_findings_commands_reject_dynamic_load() {
        let commands = [
            Command::Modules {
                json: false,
                all: false,
            },
            Command::Doctor { json: false },
            Command::Sessions {
                command: SessionsCommand::List { json: false },
            },
            Command::Findings {
                command: None,
                scope: Vec::new(),
                scope_record: Vec::new(),
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
        let shell = Command::Shell {};
        let run = Command::Run {
            tool: "example:run".to_string(),
            input: "{}".to_string(),
            options: Vec::new(),
            autonomy: None,
            run_id: None,
        };

        assert!(reject_dynamic_load_for_command(&shell, &dynamic_specifier()).is_ok());
        assert!(reject_dynamic_load_for_command(&run, &dynamic_specifier()).is_ok());
        assert!(reject_dynamic_load_for_command(
            &Command::Modules {
                json: false,
                all: false,
            },
            &[]
        )
        .is_ok());
    }

    #[test]
    fn session_persistence_opt_out_is_shell_only() {
        assert!(reject_session_persistence_flag_for_command(&Command::Shell {}, true).is_ok());

        let error = reject_session_persistence_flag_for_command(
            &Command::Modules {
                json: false,
                all: false,
            },
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("supported only by the shell"), "{error}");
        assert!(reject_session_persistence_flag_for_command(
            &Command::Modules {
                json: false,
                all: false,
            },
            false
        )
        .is_ok());
    }

    #[test]
    fn shell_target_provenance_records_the_single_cli_target_control() {
        let global = PathBuf::from("/global");

        assert_eq!(
            shell_target_source(Some(&global)),
            ShellTargetSource::GlobalFlag
        );
        assert_eq!(shell_target_source(None), ShellTargetSource::None);
    }
}

/// The launch flags only the interactive shell accepts.
pub(crate) struct ShellSessionFlags {
    pub(crate) no_session_persistence: bool,
    pub(crate) argv: Vec<String>,
}

fn dispatch_shell_command(
    default_target: Option<PathBuf>,
    plain: bool,
    load: Vec<String>,
    flags: ShellSessionFlags,
) -> Result<()> {
    let target_source = shell_target_source(default_target.as_ref());
    let target = resolve_cli_target(None, default_target)?;
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
    let loaded_config = crate::application::config_diagnostics::load_cli_config_with_diagnostics(
        workspace.as_ref().map(WorkspaceTarget::root),
    )?;
    let config = loaded_config.config;
    let mut registry = ModuleRegistry::with_v2_builtins();
    load_dynamic_modules(&mut registry, &config, &load)?;
    run_shell_with_context_and_config_diagnostics(
        config,
        workspace.as_ref(),
        plain,
        registry,
        ShellLaunchContext {
            argv: flags.argv,
            target_source,
            session_persistence: !flags.no_session_persistence,
        },
        loaded_config.diagnostics,
    )
}

fn shell_target_source(global_target: Option<&PathBuf>) -> ShellTargetSource {
    if global_target.is_some() {
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
        crate::application::config_diagnostics::exit_after_runtime_diagnostics(code);
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
        | Command::Proof { .. }
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
        Command::ReviewYield { command } => {
            crate::application::review_yield::review_yield_command(command, default_target)
        }
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
        Command::Mcp { command } => mcp_command(command, default_target).await,
        Command::Demo { json } => crate::application::demo::demo_command(json).await,
        Command::Shell { .. } | Command::Scan(_) | Command::Investigate(_) => {
            unreachable!("handled before dispatch")
        }
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

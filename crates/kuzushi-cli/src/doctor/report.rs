use super::{
    check_auth_env, check_container_runtime, check_findings_db, check_model_config,
    check_offense_sandbox, check_revng_image, check_scanner_binary,
    deterministic_capability_checks, DoctorCheck, DoctorReport,
};
use kuzushi_core::{load_config_for_target, WorkspaceTarget};
use std::fs;
use std::path::PathBuf;

pub(crate) fn build_doctor_report(target: PathBuf) -> DoctorReport {
    let mut checks = Vec::new();
    let workspace = resolve_doctor_workspace(&target, &mut checks);
    let config = resolve_doctor_config(workspace.as_ref(), &mut checks);
    record_state_checks(workspace.as_ref(), &mut checks);

    checks.push(check_scanner_binary("semgrep"));
    checks.push(check_scanner_binary("codeql"));
    checks.extend(deterministic_capability_checks());
    checks.push(check_container_runtime());
    checks.push(check_offense_sandbox());
    checks.push(check_revng_image());

    record_config_checks(config.as_ref(), &mut checks);

    DoctorReport { target, checks }
}

fn resolve_doctor_workspace(
    target: &PathBuf,
    checks: &mut Vec<DoctorCheck>,
) -> Option<WorkspaceTarget> {
    match WorkspaceTarget::new(target) {
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
    }
}

fn resolve_doctor_config(
    workspace: Option<&WorkspaceTarget>,
    checks: &mut Vec<DoctorCheck>,
) -> Option<kuzushi_core::V2Config> {
    match load_config_for_target(workspace.map(WorkspaceTarget::root)) {
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
    }
}

fn record_state_checks(workspace: Option<&WorkspaceTarget>, checks: &mut Vec<DoctorCheck>) {
    if let Some(workspace) = workspace {
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
}

fn record_config_checks(config: Option<&kuzushi_core::V2Config>, checks: &mut Vec<DoctorCheck>) {
    if let Some(config) = config {
        checks.push(check_model_config(config));
        checks.push(check_auth_env(config));
        checks.push(super::bridge::check_bridge_command(config));
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
            "LangGraph bridge",
            "config did not load; bridge command was not checked",
            "Fix `kuzushi config show` errors, then rerun `kuzushi doctor`.",
        ));
    }
}

pub(crate) fn check_state_dir(workspace: &WorkspaceTarget) -> DoctorCheck {
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

use crate::command::KwpCommand;
use anyhow::{bail, Context, Result};
use kuzushi_core::worker_protocol::{
    kwp_audit_log_integrity, kwp_audit_log_path, kwp_bus_log_path, read_kwp_audit_log,
    read_kwp_bus_log, Grant, KuzushiLockfile,
};
use kuzushi_core::{
    approve_dynamic_module, default_dynamic_lockfile_path, inspect_dynamic_module,
    revoke_dynamic_module, WorkspaceTarget,
};
use serde_json::json;
use std::path::{Path, PathBuf};

pub(crate) fn kwp_command(command: KwpCommand) -> Result<()> {
    match command {
        KwpCommand::Approve {
            specifier,
            grant,
            lockfile,
            version,
            json,
        } => kwp_approve_command(specifier, grant, lockfile, version, json),
        KwpCommand::Revoke {
            digest,
            lockfile,
            json,
        } => kwp_revoke_command(digest, lockfile, json),
        KwpCommand::Inspect {
            specifier,
            lockfile,
            json,
        } => kwp_inspect_command(specifier, lockfile, json),
        KwpCommand::Audit {
            lockfile,
            target,
            run_id,
            json,
        } => kwp_audit_command(lockfile, target, run_id, json),
    }
}

fn kwp_approve_command(
    specifier: String,
    grant_path: Option<PathBuf>,
    lockfile: Option<PathBuf>,
    version: String,
    emit_json: bool,
) -> Result<()> {
    let grant = read_grant(grant_path.as_deref())?;
    let lockfile = lockfile_path(lockfile);
    let entry = approve_dynamic_module(&specifier, grant, &version, &lockfile)?;
    if emit_json {
        println!("{}", serde_json::to_string_pretty(&entry)?);
    } else {
        println!(
            "approved {} for {} in {}",
            entry.digest.0,
            entry.module_id.0,
            lockfile.display()
        );
    }
    Ok(())
}

fn kwp_revoke_command(digest: String, lockfile: Option<PathBuf>, emit_json: bool) -> Result<()> {
    let lockfile = lockfile_path(lockfile);
    let entry = revoke_dynamic_module(&digest, &lockfile)?;
    if emit_json {
        println!("{}", serde_json::to_string_pretty(&entry)?);
    } else {
        println!("revoked {} in {}", entry.digest.0, lockfile.display());
    }
    Ok(())
}

fn kwp_inspect_command(
    specifier: String,
    lockfile: Option<PathBuf>,
    emit_json: bool,
) -> Result<()> {
    let lockfile = lockfile_path(lockfile);
    let inspection = inspect_dynamic_module(&specifier, &lockfile)?;
    if emit_json {
        println!("{}", serde_json::to_string_pretty(&inspection)?);
    } else {
        println!(
            "{} digest={} approved={} revoked={}",
            inspection.specifier, inspection.digest, inspection.approved, inspection.revoked
        );
    }
    Ok(())
}

fn kwp_audit_command(
    lockfile: Option<PathBuf>,
    target: Option<PathBuf>,
    run_id: Option<String>,
    emit_json: bool,
) -> Result<()> {
    let lockfile_path = lockfile_path(lockfile);
    let lockfile = KuzushiLockfile::read_json_or_default(&lockfile_path)?;
    let approved = lockfile
        .modules
        .values()
        .filter(|entry| !entry.revoked)
        .count();
    let revoked = lockfile
        .modules
        .values()
        .filter(|entry| entry.revoked)
        .count();
    let run_audit = kwp_run_audit_json(target, run_id)?;
    let report = json!({
        "lockfilePath": lockfile_path.display().to_string(),
        "approved": approved,
        "revoked": revoked,
        "modules": lockfile.modules,
        "runAudit": run_audit,
    });
    if emit_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if let Some(run_audit) = report.get("runAudit").filter(|value| !value.is_null()) {
        println!(
            "{} approved={} revoked={} kwpAuditRecords={} kwpBusRecords={} integrity={} audit={}",
            lockfile_path.display(),
            approved,
            revoked,
            run_audit
                .get("recordCount")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            run_audit
                .pointer("/bus/recordCount")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            kwp_integrity_label(run_audit),
            run_audit
                .get("path")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
        );
    } else {
        println!(
            "{} approved={} revoked={}",
            lockfile_path.display(),
            approved,
            revoked
        );
    }
    Ok(())
}

fn kwp_integrity_label(run_audit: &serde_json::Value) -> &'static str {
    if run_audit
        .pointer("/integrity/ok")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        "ok"
    } else {
        "failed"
    }
}

fn kwp_run_audit_json(
    target: Option<PathBuf>,
    run_id: Option<String>,
) -> Result<serde_json::Value> {
    match (target, run_id) {
        (None, None) => Ok(serde_json::Value::Null),
        (Some(_), None) => bail!("--target requires --run-id for `kuzushi kwp audit`"),
        (None, Some(_)) => bail!("--run-id requires --target for `kuzushi kwp audit`"),
        (Some(target), Some(run_id)) => {
            let workspace = WorkspaceTarget::new(target)?;
            let path = kwp_audit_log_path(workspace.root(), &run_id);
            let bus_path = kwp_bus_log_path(workspace.root(), &run_id);
            let records =
                read_kwp_audit_log(workspace.root(), &run_id).map_err(anyhow::Error::from)?;
            let integrity = kwp_audit_log_integrity(&records).map_err(anyhow::Error::from)?;
            let bus_records = if bus_path.exists() {
                read_kwp_bus_log(workspace.root(), &run_id).map_err(anyhow::Error::from)?
            } else {
                Vec::new()
            };
            Ok(json!({
                "target": workspace.root().display().to_string(),
                "runId": run_id,
                "path": path.display().to_string(),
                "recordCount": records.len(),
                "integrity": integrity,
                "records": records,
                "bus": {
                    "path": bus_path.display().to_string(),
                    "recordCount": bus_records.len(),
                    "records": bus_records,
                },
            }))
        }
    }
}

fn read_grant(path: Option<&Path>) -> Result<Grant> {
    let Some(path) = path else {
        return Ok(Grant::default());
    };
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("could not read grant file {}", path.display()))?;
    serde_json::from_str(&text)
        .or_else(|_| toml::from_str(&text).map_err(anyhow::Error::from))
        .with_context(|| format!("grant file {} is not valid JSON or TOML", path.display()))
}

fn lockfile_path(path: Option<PathBuf>) -> PathBuf {
    path.unwrap_or_else(default_dynamic_lockfile_path)
}

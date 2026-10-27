use super::direct_scan_receipt::{DirectScanPolicy, DirectScanReceipt};
use super::*;
use crate::dep_hygiene::ConfiguredCargoAuditScanner;
use crate::workspace::source_snapshot::SourceSnapshot;

const STUDY_KEYS: [(&str, &str, &str); 6] = [
    ("cargoAuditBinary", "binary", "cargo_audit_binary"),
    (
        "cargoAuditAdvisoryDb",
        "advisoryDb",
        "cargo_audit_advisory_db",
    ),
    ("cargoAuditOffline", "offline", "cargo_audit_offline"),
    (
        "cargoAuditAllowStale",
        "allowStale",
        "cargo_audit_allow_stale",
    ),
    ("cargoAuditTimeoutMs", "timeoutMs", "cargo_audit_timeout_ms"),
    (
        "cargoAuditMaxLockfileBytes",
        "maxLockfileBytes",
        "cargo_audit_max_lockfile_bytes",
    ),
];

pub(in crate::modules) fn cargo_audit_study_options() -> Vec<OptionSpec> {
    cargo_audit_options()
        .into_iter()
        .filter_map(|mut option| {
            let (name, _, alias) = STUDY_KEYS.iter().find(|(_, key, _)| *key == option.name)?;
            option.name = (*name).into();
            option.aliases = vec![(*alias).into()];
            option.default = None;
            option.advanced = true;
            Some(option)
        })
        .collect()
}

pub(in crate::modules) fn cargo_audit_settings(input: &Value) -> Value {
    let options = STUDY_KEYS
        .iter()
        .filter_map(|(parent, child, _)| {
            input
                .get(parent)
                .filter(|v| !v.is_null())
                .map(|v| ((*child).into(), v.clone()))
        })
        .collect::<serde_json::Map<_, _>>();
    Value::Object(options)
}

pub(in crate::modules) fn cargo_audit_options() -> Vec<OptionSpec> {
    use crate::dep_hygiene::cargo_audit::config::*;
    vec![
        target_option(),
        binary_option("Standalone cargo-audit executable. The Cargo shim is never invoked.").default(json!("cargo-audit")),
        opt("advisoryDb", OptionType::Path, "Operator advisory database directory; omit to use cargo-audit's operator-home database.").external_read().aliases(&["advisory_db"]).advanced(),
        opt("offline", OptionType::Bool, "Disable database updates and yanked-package network checks.").default(json!(false)),
        opt("allowStale", OptionType::Bool, "Explicitly permit an old advisory database. Findings retain the scan source receipt; database freshness is not implied.").default(json!(false)).aliases(&["allow_stale"]).advanced(),
        opt("timeoutMs", OptionType::Int, "Time allowance across this job's lockfile captures and audits. Whole-repository source authentication is separate.").default(json!(DEFAULT_TIMEOUT_MS)).integer_range(1,MAX_TIMEOUT_MS as i64).aliases(&["timeout_ms"]).advanced(),
        opt("maxLockfileBytes", OptionType::Int, "Maximum captured Cargo.lock bytes; oversized input fails before execution.").default(json!(DEFAULT_LOCKFILE_BYTES)).integer_range(1,MAX_LOCKFILE_BYTES as i64).aliases(&["max_lockfile_bytes"]).advanced(),
    ]
}

pub(in crate::modules) fn run_cargo_audit_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let scanner = ConfiguredCargoAuditScanner::from_tool_input(&input)?;
    let source_workspace = crate::workspace::source_snapshot::workspace_source_owner(ctx, &target)?;
    let source = SourceSnapshot::capture(ctx, "cargo-audit:scan", source_workspace.root())?;
    let receipt = DirectScanReceipt::capture(ctx, &target, DirectScanPolicy::CargoAudit)?;
    let (output, findings) = source.bind_result(analyze(&target, &scanner, ctx))?;
    let settlement_source = source.clone();
    let output = source.finish(ctx, "cargo-audit:scan", source_workspace.root(), output);
    let result = settlement_source.bind_result(receipt.finish(ctx, &findings, output))?;
    Ok(with_inspection_receipts(
        result,
        scanner.inspection_receipts(),
    ))
}

fn analyze(
    target: &Path,
    scanner: &ConfiguredCargoAuditScanner,
    ctx: &ToolExecutionContext<'_>,
) -> Result<(Value, Vec<Finding>)> {
    let mut findings = match ctx.with_cancellation(|cancel| scanner.scan(target, cancel)) {
        Ok(findings) => findings,
        Err(error) => {
            return Ok((
                failed_tool_output("cargo-audit:scan", target, error),
                Vec::new(),
            ))
        }
    };
    rebase_findings(target, scanner, ctx, &mut findings)?;
    Ok((cargo_audit_output(target, findings.clone(), None), findings))
}

fn rebase_findings(
    target: &Path,
    scanner: &ConfiguredCargoAuditScanner,
    ctx: &ToolExecutionContext<'_>,
    findings: &mut [Finding],
) -> Result<()> {
    let Some(workspace) = ctx.workspace else {
        return Ok(());
    };
    let prefix = target
        .strip_prefix(workspace.root())
        .context("Cargo discovery target must stay inside its workspace")?;
    for finding in findings {
        let file = crate::workspace::inventory::repo_relative(
            Path::new(""),
            &prefix.join(&finding.file_path),
        );
        scanner.rebind_scoped_finding(finding, file);
    }
    Ok(())
}

pub(super) fn cargo_audit_output(
    target: &Path,
    findings: Vec<Finding>,
    persisted: Option<Value>,
) -> Value {
    crate::scan::completed_scan_tool_json(
        format!("cargo-audit: {} advisory findings in selected Cargo.lock. Nested lockfiles and source reachability were not inspected.",findings.len()),
        json!({"target":target,"count":findings.len(),"coreFindings":findings,"findings":findings,"persisted":persisted}),
    )
}

#[cfg(test)]
mod tests;

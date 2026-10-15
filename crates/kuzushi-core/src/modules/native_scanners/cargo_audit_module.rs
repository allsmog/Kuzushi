use super::*;
use crate::dep_hygiene::ConfiguredCargoAuditScanner;

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
    let result = crate::workspace::source_snapshot::run_source_bound_tool(
        ctx,
        "cargo-audit:scan",
        &target,
        || run_started_audit(&target, &scanner, ctx),
    )?;
    Ok(with_inspection_receipts(
        result,
        scanner.inspection_receipts(),
    ))
}

fn run_started_audit(
    target: &Path,
    scanner: &ConfiguredCargoAuditScanner,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let findings = match ctx.with_cancellation(|cancel| scanner.scan(target, cancel)) {
        Ok(findings) => findings,
        Err(error) => return Ok(failed_tool_output("cargo-audit:scan", target, error)),
    };
    let persisted = persist_iac_findings(target, &findings, ctx)?;
    Ok(cargo_audit_output(target, findings, persisted))
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

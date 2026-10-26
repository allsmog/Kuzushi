//! Bind policy results to verified source before persisting coverage or gaps.
use super::register_modules::{emit_scan_done, emit_scan_start};
use super::*;
use crate::module_result::tool_result_status;
use crate::run_artifacts::{PhaseStageOutcome, ScanFindingDelta};
use crate::run_lifecycle::RunItemStatus;
use crate::workflow_attempts::PhaseTargetSnapshot;
use crate::workspace::source_snapshot::SourceSnapshot;
use std::time::Instant;

mod receipt;

const TOOL: &str = "license-scan:scan";

pub(super) fn run(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let options = options(&input)?;
    let started = Instant::now();
    let target_snapshot = PhaseTargetSnapshot::capture(&target);
    let source_workspace = crate::workspace::source_snapshot::workspace_source_owner(ctx, &target)?;
    let snapshot = SourceSnapshot::capture(ctx, TOOL, source_workspace.root())?;
    emit_scan_start(ctx, "license-scan", &target);
    let (output, findings) = snapshot.bind_result(scan(&target, options, ctx))?;
    let settlement_snapshot = snapshot.clone();
    let output = snapshot.finish(ctx, TOOL, source_workspace.root(), output);
    let receipt = receipt::LicenseScanReceipt {
        options,
        started,
        target_snapshot,
    };
    settlement_snapshot.bind_result(finish(ctx, &findings, output, receipt))
}

fn scan(
    target: &Path,
    options: LicenseScanOptions,
    ctx: &ToolExecutionContext<'_>,
) -> Result<(Value, Vec<Finding>)> {
    let mut report =
        match ctx.with_cancellation(|cancel| scan_licenses_with_options(target, cancel, options)) {
            Ok(report) => report,
            Err(error) => {
                return Ok((
                    failed_tool_output(TOOL, target, anyhow::anyhow!("{error:#}")),
                    Vec::new(),
                ))
            }
        };
    rebase_report(&mut report, target, ctx)?;
    let findings = report
        .findings
        .iter()
        .map(|finding| finding.to_core_finding())
        .collect::<Vec<_>>();
    let mut output = report.to_tool_json();
    output["data"]["coreFindings"] = json!(findings);
    Ok((output, findings))
}

fn rebase_report(
    report: &mut crate::license_scan::LicenseScanReport,
    target: &Path,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    let Some(workspace) = ctx.workspace else {
        return Ok(());
    };
    let prefix = target
        .strip_prefix(workspace.root())
        .context("License discovery target must stay inside its workspace")?;
    for finding in &mut report.findings {
        finding.rebase_path(prefix);
    }
    Ok(())
}

fn finish(
    ctx: &ToolExecutionContext<'_>,
    findings: &[Finding],
    mut output: Value,
    receipt: receipt::LicenseScanReceipt,
) -> Result<Value> {
    let Some(status) = scan_persistence_status(tool_result_status(&output)) else {
        return Ok(output);
    };
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(output);
    };
    workspace.ensure_state_dir()?;
    let run_id = ctx.finding_run_id();
    let (added, updated) = crate::findings::commit_observed_findings_with_counts(
        store,
        ctx.run_observation().as_ref(),
        &run_id,
        workspace.root(),
        findings,
        status,
    )?;
    let stage = receipt::publish_committed(
        workspace,
        store,
        &run_id,
        status,
        ScanFindingDelta { added, updated },
        receipt,
    )?;
    output["data"]["persisted"] =
        json!({"runId":run_id,"findingsDb":workspace.findings_db_path().display().to_string()});
    output["data"]["phaseStages"] = json!([stage]);
    emit_scan_done(ctx, "license-scan", findings.len());
    Ok(output)
}

fn options(input: &Value) -> Result<LicenseScanOptions> {
    // Compatibility aliases have already been canonicalized by prepared dispatch.
    let require_source_spdx_headers = input
        .get("requireSourceSpdxHeaders")
        .map(|value| {
            value
                .as_bool()
                .context("license-scan: requireSourceSpdxHeaders must be a boolean")
        })
        .transpose()?
        .unwrap_or(false);
    Ok(LicenseScanOptions {
        require_source_spdx_headers,
    })
}

#[cfg(test)]
mod tests;

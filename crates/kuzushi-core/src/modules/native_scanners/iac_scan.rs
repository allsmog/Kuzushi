//! Direct IaC analysis and source-bound observation settlement.
use super::direct_scan_receipt::{DirectScanPolicy, DirectScanReceipt};
use super::register_modules::emit_scan_start;
use super::*;
use crate::scan::ScanCancellation;
use crate::workspace::source_snapshot::SourceSnapshot;

pub(super) fn run_iac_scan(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    run_with_scanner(input, ctx, scan_iac)
}

fn run_with_scanner(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    scan: impl FnOnce(
        &Path,
        &IacScanOptions,
        &ScanCancellation,
    ) -> Result<crate::iac_scan::IacScanReport>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let source_workspace = crate::workspace::source_snapshot::workspace_source_owner(ctx, &target)?;
    let source = SourceSnapshot::capture(ctx, "iac-scan:scan", source_workspace.root())?;
    let kind = IacScanOptions::from_tool_input(&input)?.kind;
    let receipt = DirectScanReceipt::capture(ctx, &target, DirectScanPolicy::Iac(kind))?;
    let (output, findings) = source.bind_result(analyze(&target, &input, ctx, scan))?;
    let settlement_source = source.clone();
    let output = source.finish(ctx, "iac-scan:scan", source_workspace.root(), output);
    let output = settlement_source.bind_result(receipt.finish(ctx, &findings, output))?;
    Ok(output)
}

fn analyze(
    target: &Path,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    scan: impl FnOnce(
        &Path,
        &IacScanOptions,
        &ScanCancellation,
    ) -> Result<crate::iac_scan::IacScanReport>,
) -> Result<(Value, Vec<Finding>)> {
    emit_scan_start(ctx, "iac-scan", target);
    let options = IacScanOptions::from_tool_input(input)?;
    let mut report = match ctx.with_cancellation(|cancel| scan(target, &options, cancel)) {
        Ok(report) => report,
        Err(error) => {
            return Ok((
                failed_tool_output("iac-scan:scan", target, error),
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
    report: &mut crate::iac_scan::IacScanReport,
    target: &Path,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    let Some(workspace) = ctx.workspace else {
        return Ok(());
    };
    let prefix = target
        .strip_prefix(workspace.root())
        .context("IaC discovery target must stay inside its workspace")?;
    report.inspected_files = report.inspected_files.take().map(|files| {
        files
            .into_iter()
            .map(|file| {
                crate::workspace::inventory::repo_relative(Path::new(""), &prefix.join(file))
            })
            .collect()
    });
    for finding in &mut report.findings {
        finding.rebase_path(prefix);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

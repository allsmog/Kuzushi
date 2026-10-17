//! Settle source verification before committing direct Semgrep observations.
use super::register_modules::{emit_scan_coverage_gaps, emit_scan_done, emit_scan_start};
use super::*;
use crate::module_result::tool_result_status;
use crate::workspace::source_snapshot::SourceSnapshot;

const TOOL: &str = "semgrep:scan";

pub(super) fn run_semgrep_scan(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let scanner = crate::scan::ConfiguredSemgrepScanner::from_tool_input(&input)?;
    if let Err(error) = scanner.preflight() {
        return Ok(failed_tool_output(TOOL, &target, error));
    }
    let source = SourceSnapshot::capture(ctx, TOOL, &target)?;
    let (output, report) = source.bind_result(analyze(&target, &scanner, &input, ctx))?;
    let settlement_source = source.clone();
    let output = source.finish(ctx, TOOL, &target, output);
    let result = match report {
        Some(report) => finish(&target, &input, ctx, report, output),
        None => Ok(output),
    };
    let result = settlement_source.bind_result(result)?;
    Ok(with_inspection_receipts(
        result,
        scanner.inspection_receipts(),
    ))
}

fn analyze(
    target: &Path,
    scanner: &crate::scan::ConfiguredSemgrepScanner,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<(Value, Option<SemgrepScanReport>)> {
    emit_scan_start(ctx, "semgrep", target);
    let outcome =
        match ctx.with_cancellation(|cancel| scanner.scan_outcome_with_cancel(target, cancel)) {
            Ok(outcome) => outcome,
            Err(error) => return Ok((failed_tool_output(TOOL, target, error), None)),
        };
    let mut findings = outcome.findings;
    emit_scan_coverage_gaps(ctx, "semgrep", &outcome.scan_errors);
    if whitebox_static_profile_requested(input)? {
        let state =
            whitebox_static_proof_state_from_input(input)?.unwrap_or(StaticProofState::SignalOnly);
        mark_whitebox_static_findings(&mut findings, state)?;
    }
    let report = SemgrepScanReport::new(target.display().to_string(), findings, None)
        .with_scan_errors(outcome.scan_errors);
    Ok((report.to_tool_json(), Some(report)))
}

fn finish(
    target: &Path,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    mut report: SemgrepScanReport,
    mut output: Value,
) -> Result<Value> {
    let status = scan_persistence_status(tool_result_status(&output))
        .context("Semgrep observations require a completed or partial outcome")?;
    report.persisted = persist_semgrep_findings(
        target,
        &report.findings,
        ctx,
        whitebox_static_profile_requested(input)?,
        status,
    )?;
    if let Some(persisted) = &report.persisted {
        output["data"]["persisted"] = json!(persisted);
    }
    output["output"] = json!(report.output());
    emit_scan_done(ctx, "semgrep", report.count);
    Ok(output)
}

//! Settle source authentication before publishing auxiliary query observations.
use super::register_modules::{emit_scan_coverage_gaps, emit_scan_done, emit_scan_start};
use super::*;
use crate::workspace::source_snapshot::SourceSnapshot;

const TOOL: &str = "codeql:scan";
struct PendingCodeqlObservations {
    report: CodeqlScanReport,
    sarif_documents: Vec<String>,
}

const REVIEW_LIMIT: &str = "CodeQL query observations require independent review; selected queries do not establish complete repository coverage or finding validity";

pub(super) fn run(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let scanner = CodeqlScanner::from_tool_input(&input)?;
    if let Err(error) = scanner.preflight() {
        return Ok(failed_tool_output(TOOL, &target, error));
    }
    run_with_analysis(&target, &input, ctx, || {
        ctx.with_cancellation(|cancel| scanner.scan_with_artifacts(&target, cancel))
    })
}

fn run_with_analysis(
    target: &Path,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    analyze: impl FnOnce() -> Result<ScanEngineOutput>,
) -> Result<Value> {
    let source = SourceSnapshot::capture(ctx, TOOL, target)?;
    emit_scan_start(ctx, "codeql", target);
    let report = match source.bind_result(analyze()) {
        Ok(output) => source.bind_result(report(target, output, input))?,
        Err(error) => {
            return Ok(source.finish(
                ctx,
                TOOL,
                target,
                failed_tool_output(
                    TOOL,
                    target,
                    crate::modules::support::contextualize_source_failure(TOOL, error),
                ),
            ))
        }
    };
    emit_scan_coverage_gaps(ctx, "codeql", &report.report.scan_errors);
    let settlement_source = source.clone();
    let output = source.finish(ctx, TOOL, target, report.report.to_tool_json());
    settlement_source.bind_result(finish(target, input, ctx, report, output))
}

fn report(
    target: &Path,
    mut output: ScanEngineOutput,
    input: &Value,
) -> Result<PendingCodeqlObservations> {
    if whitebox_static_profile_requested(input)? {
        let state =
            whitebox_static_proof_state_from_input(input)?.unwrap_or(StaticProofState::SignalOnly);
        mark_whitebox_static_findings(&mut output.findings, state)?;
    }
    output.scan_errors.push(REVIEW_LIMIT.into());
    let sarif_documents = output.codeql_sarif_documents;
    let report = CodeqlScanReport::new(target.display().to_string(), output.findings, None)
        .with_sarif_documents(sarif_documents.clone())
        .with_scan_errors(output.scan_errors);
    Ok(PendingCodeqlObservations {
        report,
        sarif_documents,
    })
}

fn finish(
    target: &Path,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    pending: PendingCodeqlObservations,
    mut output: Value,
) -> Result<Value> {
    let PendingCodeqlObservations {
        mut report,
        sarif_documents,
    } = pending;
    let status = scan_persistence_status(crate::tool_result_status(&output))
        .context("CodeQL observations need a complete or partial outcome")?;
    let index = verified_evidence_requested(input, &output)?;
    report.persisted = persist_codeql_findings(
        target,
        &report.findings,
        ctx,
        &sarif_documents,
        index,
        status,
    )?;
    if let Some(persisted) = &report.persisted {
        super::observation_snapshot::publish(ctx, &persisted.run_id)?;
        output["data"]["persisted"] = json!(persisted);
    }
    output["output"] = json!(report.output());
    disclose_omitted_evidence(
        &mut output,
        whitebox_static_profile_requested(input)? && !index,
    );
    emit_scan_done(ctx, "codeql", report.count);
    Ok(output)
}

fn disclose_omitted_evidence(output: &mut Value, omitted: bool) {
    if !omitted {
        return;
    }
    let reason = "Final source verification did not succeed; static evidence was not indexed.";
    output["data"]["staticEvidenceOmitted"] = json!(reason);
    let body = output["output"].as_str().unwrap_or_default();
    output["output"] = json!(format!("{body}\n  {reason}"));
}

fn verified_evidence_requested(input: &Value, output: &Value) -> Result<bool> {
    Ok(whitebox_static_profile_requested(input)?
        && output
            .pointer("/data/sourceCheckCurrent")
            .and_then(Value::as_bool)
            == Some(true))
}

#[cfg(test)]
mod tests;

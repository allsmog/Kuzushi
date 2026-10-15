use super::register_modules::{emit_scan_done, emit_scan_start};
use super::*;
use crate::sbom_scan::{
    scan_sbom_with_options, InspectedSbomReport, SbomInspectionError, SbomScanOptions,
    DEFAULT_SBOM_TOTAL_BYTES, MAX_SBOM_FILE_BYTES, MAX_SBOM_TOTAL_BYTES,
};

pub(super) fn options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        opt("maxFileBytes", OptionType::Int,
            "Maximum bytes captured from one dependency input. Oversized inputs stop inventory without publishing components.")
            .integer_range(1,MAX_SBOM_FILE_BYTES as i64).default(json!(MAX_SBOM_FILE_BYTES)).advanced(),
        opt("maxTotalBytes", OptionType::Int,
            "Maximum source bytes captured and retained in memory for this inventory. Default 64 MiB; upper limit 512 MiB. Parser stages reuse captured bytes. Raising this limit increases memory use.")
            .integer_range(1,MAX_SBOM_TOTAL_BYTES as i64).default(json!(DEFAULT_SBOM_TOTAL_BYTES)),
    ]
}

pub(super) fn execute(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let options = SbomScanOptions::from_tool_input(&input)?;
    emit_scan_start(ctx, "sbom-scan", &target);
    match ctx.with_cancellation(|cancel| scan_sbom_with_options(&target, cancel, &options)) {
        Ok(result) => {
            emit_scan_done(ctx, "sbom-scan", result.report.components.len());
            inspected_output(result)
        }
        Err(error) => failed_output(&target, error),
    }
}

fn inspected_output(result: InspectedSbomReport) -> Result<Value> {
    let mut output = result.report.to_tool_json();
    output["output"] = json!(format!("{}\nCaptured dependency inputs: {} files; {} source bytes read / {} allowed.\nParsers reuse captured bytes. Source freshness and complete repository coverage remain unverified.",
        result.report.output(), result.inspection.captured_files,
        result.inspection.source_bytes_read, result.inspection.limits.max_total_bytes));
    output["data"]["inspection"] = serde_json::to_value(result.inspection)?;
    Ok(output)
}

fn failed_output(target: &Path, error: anyhow::Error) -> Result<Value> {
    let inspection = error
        .downcast_ref::<SbomInspectionError>()
        .map(|error| serde_json::to_value(&error.inspection))
        .transpose()?;
    let mut output = failed_tool_output("sbom-scan:scan", target, anyhow::anyhow!("{error:#}"));
    output["data"]["inspection"] = inspection.unwrap_or(Value::Null);
    Ok(output)
}

#[cfg(test)]
mod tests;

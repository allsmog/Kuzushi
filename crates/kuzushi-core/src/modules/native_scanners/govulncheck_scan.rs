//! Bind experimental Go observations to source before committing their status.
use super::register_modules::{emit_scan_done, emit_scan_start};
use super::*;
use crate::workspace::source_snapshot::SourceSnapshot;

const TOOL: &str = "govulncheck:scan";

pub(super) fn run(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    run_with_scanner(input, ctx, &GovulncheckScanner)
}

fn run_with_scanner(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    scanner: &dyn ScanEngine,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    if let Err(error) = scanner.preflight() {
        return Ok(failed_tool_output(TOOL, &target, error));
    }
    let source = SourceSnapshot::capture(ctx, TOOL, &target)?;
    let (output, findings) = source.bind_result(analyze(&target, ctx, scanner))?;
    let settlement_source = source.clone();
    let output = source.finish(ctx, TOOL, &target, output);
    settlement_source.bind_result(finish(&target, ctx, &findings, output))
}

fn analyze(
    target: &Path,
    ctx: &ToolExecutionContext<'_>,
    scanner: &dyn ScanEngine,
) -> Result<(Value, Vec<Finding>)> {
    emit_scan_start(ctx, "govulncheck", target);
    let mut findings = match ctx.with_cancellation(|cancel| scanner.scan(target, cancel)) {
        Ok(findings) => findings,
        Err(error) => return Ok((failed_tool_output(TOOL, target, error), Vec::new())),
    };
    rebase_findings(target, ctx, &mut findings)?;
    let output = output(target, findings.clone(), None);
    Ok((output, findings))
}

fn finish(
    target: &Path,
    ctx: &ToolExecutionContext<'_>,
    findings: &[Finding],
    mut output: Value,
) -> Result<Value> {
    let Some(status) = scan_persistence_status(crate::tool_result_status(&output)) else {
        return Ok(output);
    };
    let origin = ctx.workspace.map_or(target, |workspace| workspace.root());
    let persisted = persist_native_findings_with_status(origin, findings, ctx, status)?;
    if let Some(committed) = &persisted {
        let run = committed["runId"]
            .as_str()
            .context("Committed Go observation run is unavailable")?;
        super::observation_snapshot::publish(ctx, run)?;
    }
    output["data"]["persisted"] = json!(persisted);
    emit_scan_done(ctx, "govulncheck", findings.len());
    Ok(output)
}

fn rebase_findings(
    target: &Path,
    ctx: &ToolExecutionContext<'_>,
    findings: &mut [Finding],
) -> Result<()> {
    let Some(workspace) = ctx.workspace else {
        return Ok(());
    };
    let prefix = target
        .strip_prefix(workspace.root())
        .context("Go discovery target must stay inside its workspace")?;
    for finding in findings {
        let path = prefix
            .join(&finding.file_path)
            .to_string_lossy()
            .replace('\\', "/");
        GovulncheckScanner.rebind_scoped_finding(finding, path);
    }
    Ok(())
}

fn output(target: &Path, findings: Vec<Finding>, persisted: Option<Value>) -> Value {
    crate::scan::completed_scan_tool_json(
        format!("govulncheck: {} advisory signal{} under {}; source loading, network and coverage remain experimental", findings.len(), if findings.len() == 1 { "" } else { "s" }, target.display()),
        json!({"target":target,"count":findings.len(),"coreFindings":findings,"findings":findings,"persisted":persisted}),
    )
}

#[cfg(test)]
mod tests;

use super::prelude::*;
use super::*;

pub(in crate::modules) fn register_modules(registry: &mut ModuleRegistry) {
    registry.register(semgrep_module());
    registry.register(codeql_module());
    registry.register(iac_scan_module());
}

pub(in crate::modules) fn execute_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    match name {
        "semgrep:scan" => run_semgrep_scan(input, ctx),
        "codeql:scan" => run_codeql_scan(input, ctx),
        "iac-scan:scan" => run_iac_scan(input, ctx),
        other => anyhow::bail!("native scanner tool {other:?} has no executor mapping"),
    }
}

pub(in crate::modules) fn run_semgrep_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let scanner = SemgrepScanner::from_tool_input(&input)?;
    let mut findings = scanner.scan_with_cancel(&target, &ScanCancellation::default())?;
    let index_static_evidence = whitebox_static_profile_requested(&input)?;
    if index_static_evidence {
        mark_whitebox_static_findings(&mut findings, StaticProofState::SignalOnly)?;
    }
    let persisted = persist_semgrep_findings(&target, &findings, ctx, index_static_evidence)?;
    Ok(SemgrepScanReport::new(target.display().to_string(), findings, persisted).to_tool_json())
}

pub(in crate::modules) fn run_codeql_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let scanner = CodeqlScanner::from_tool_input(&input)?;
    let mut output = scanner.scan_with_artifacts(&target, &ScanCancellation::default())?;
    let index_static_evidence = whitebox_static_profile_requested(&input)?;
    if index_static_evidence {
        mark_whitebox_static_findings(&mut output.findings, StaticProofState::SignalOnly)?;
    }
    let persisted = persist_codeql_findings(
        &target,
        &output.findings,
        ctx,
        &output.codeql_sarif_documents,
        index_static_evidence,
    )?;
    Ok(
        CodeqlScanReport::new(target.display().to_string(), output.findings, persisted)
            .to_tool_json(),
    )
}

pub(in crate::modules) fn run_iac_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let options = IacScanOptions::from_tool_input(&input)?;
    let report = scan_iac(&target, &options, &ScanCancellation::default())?;
    let findings = report
        .findings
        .iter()
        .map(|finding| finding.to_core_finding())
        .collect::<Vec<_>>();
    let persisted = persist_iac_findings(&target, &findings, ctx)?;
    let mut output = report.to_tool_json();
    if let Some(persisted) = persisted {
        output["data"]["persisted"] = json!(persisted);
    }
    Ok(output)
}

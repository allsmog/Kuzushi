use super::*;

pub(in crate::modules) fn register_modules(registry: &mut ModuleRegistry) {
    registry.register(semgrep_module());
    registry.register(codeql_module());
    registry.register(iac_scan_module());
    registry.register(exploit_chain_module());
}

pub(in crate::modules) fn execute_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    match name {
        "semgrep:scan" => run_semgrep_scan(input, ctx),
        "codeql:scan" => run_codeql_scan(input, ctx),
        "iac-scan:scan" => run_iac_scan(input, ctx),
        "exploit-chain:scan" => run_exploit_chain_scan(input, ctx, runtime),
        other => anyhow::bail!("native scanner tool {other:?} has no executor mapping"),
    }
}

pub(in crate::modules) fn run_semgrep_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    emit_scan_start(ctx, "semgrep", &target);
    let scanner = SemgrepScanner::from_tool_input(&input)?;
    let mut findings = match scanner.scan_with_cancel(&target, &ScanCancellation::default()) {
        Ok(findings) => findings,
        Err(error) => return Ok(failed_tool_output("semgrep:scan", &target, error)),
    };
    let index_static_evidence = whitebox_static_profile_requested(&input)?;
    if index_static_evidence {
        mark_whitebox_static_findings(&mut findings, StaticProofState::SignalOnly)?;
    }
    let persisted = persist_semgrep_findings(&target, &findings, ctx, index_static_evidence)?;
    emit_scan_done(ctx, "semgrep", findings.len());
    Ok(SemgrepScanReport::new(target.display().to_string(), findings, persisted).to_tool_json())
}

pub(in crate::modules) fn run_codeql_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    emit_scan_start(ctx, "codeql", &target);
    let scanner = CodeqlScanner::from_tool_input(&input)?;
    let mut output = match scanner.scan_with_artifacts(&target, &ScanCancellation::default()) {
        Ok(output) => output,
        Err(error) => return Ok(failed_tool_output("codeql:scan", &target, error)),
    };
    let index_static_evidence = whitebox_static_profile_requested(&input)?;
    if index_static_evidence {
        mark_whitebox_static_findings(&mut output.findings, StaticProofState::SignalOnly)?;
    }
    let finding_count = output.findings.len();
    let findings = output.findings;
    let sarif_documents = output.codeql_sarif_documents;
    let persisted =
        persist_codeql_findings(&target, &findings, ctx, &sarif_documents, index_static_evidence)?;
    emit_scan_done(ctx, "codeql", finding_count);
    Ok(
        CodeqlScanReport::new(target.display().to_string(), findings, persisted)
            .with_sarif_documents(sarif_documents)
            .to_tool_json(),
    )
}

fn emit_scan_start(ctx: &ToolExecutionContext<'_>, scanner: &str, target: &Path) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "scan",
                format!("{scanner} start · target={}", target.display()),
            )
            .emit();
    }
}

fn emit_scan_done(ctx: &ToolExecutionContext<'_>, scanner: &str, findings: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "scan",
                format!("{scanner} complete · {findings} findings"),
            )
            .emit();
    }
}

pub(in crate::modules) fn run_iac_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    emit_scan_start(ctx, "iac-scan", &target);
    let options = IacScanOptions::from_tool_input(&input)?;
    let report = match scan_iac(&target, &options, &ScanCancellation::default()) {
        Ok(report) => report,
        Err(error) => return Ok(failed_tool_output("iac-scan:scan", &target, error)),
    };
    let findings = report
        .findings
        .iter()
        .map(|finding| finding.to_core_finding())
        .collect::<Vec<_>>();
    let persisted = persist_iac_findings(&target, &findings, ctx)?;
    emit_scan_done(ctx, "iac-scan", findings.len());
    let mut output = report.to_tool_json();
    output["data"]["coreFindings"] = json!(findings);
    if let Some(persisted) = persisted {
        output["data"]["persisted"] = json!(persisted);
    }
    Ok(output)
}

pub(in crate::modules) fn run_exploit_chain_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    emit_scan_start(ctx, "exploit-chain", &target);
    let scanner = ExploitChainScanner::from_tool_input(&input)?;
    let runtime = require_exploit_chain_runtime(runtime)?;
    let model = require_exploit_chain_model(ctx)?;
    let report: ExploitChainReport = scan_exploit_chains_with_runtime(
        &target,
        &ScanCancellation::default(),
        scanner.max_evidence,
        Some(runtime),
        Some(model.as_str()),
    )?;
    let persisted = persist_exploit_chain_findings(&target, &report, ctx)?;
    emit_scan_done(ctx, "exploit-chain", report.findings.len());
    Ok(exploit_chain_output(report, &target, persisted))
}

fn require_exploit_chain_runtime(
    runtime: Option<&dyn AgentRuntime>,
) -> Result<&dyn AgentRuntime> {
    runtime.ok_or_else(|| {
        anyhow::anyhow!(
            "exploit-chain:scan requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies."
        )
    })
}

fn require_exploit_chain_model(ctx: &ToolExecutionContext<'_>) -> Result<String> {
    crate::runtime::require_configured_model("exploit-chain:scan", ctx.config.model.as_deref())
}

fn persist_exploit_chain_findings(
    target: &Path,
    report: &ExploitChainReport,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<GenericPersistedRun>> {
    persist_tool_findings(
        "exploit-chain",
        target,
        &report.findings,
        ctx.workspace,
        ctx.findings_store,
    )
}

fn exploit_chain_output(
    report: ExploitChainReport,
    target: &Path,
    persisted: Option<GenericPersistedRun>,
) -> Value {
    let mut output = report.to_tool_json();
    output["data"]["persisted"] = json!(persisted);
    output["output"] = json!(format!(
        "exploit-chain:scan found {} chain candidate{} under {}",
        report.count,
        if report.count == 1 { "" } else { "s" },
        target.display()
    ));
    output
}

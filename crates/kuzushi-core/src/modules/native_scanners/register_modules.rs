use super::*;

use crate::modules::registry::ToolExecutor;

pub(in crate::modules) fn register_modules(registry: &mut ModuleRegistry, executor: ToolExecutor) {
    registry.register(semgrep_module().with_executor(executor));
    registry.register(codeql_module().with_executor(executor));
    registry.register(iac_scan_module().with_executor(executor));
    registry.register(cargo_audit_module().with_executor(executor));
    registry.register(govulncheck_module().with_executor(executor));
    registry.register(license_scan_module().with_executor(executor));
    registry.register(sbom_scan_module().with_executor(executor));
    registry.register(exploit_chain_module().with_executor(executor).deferred());
    registry.register(android_apk_module().with_executor(executor));
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
        "cargo-audit:scan" => run_cargo_audit_scan(input, ctx),
        "govulncheck:scan" => run_govulncheck_scan(input, ctx),
        "license-scan:scan" => run_license_scan(input, ctx),
        "sbom-scan:scan" => run_sbom_scan(input, ctx),
        "exploit-chain:scan" => run_exploit_chain_scan(input, ctx, runtime),
        "android-apk:check-env" => run_android_apk_check_env(input, ctx),
        "android-apk:prepare" => run_android_apk_prepare(input, ctx),
        "android-apk:manifest-scan" => run_manifest_scan(input, ctx),
        "android-apk:network-security-config" => run_network_security_config_scan(input, ctx),
        "android-apk:fileprovider-scan" => run_fileprovider_scan(input, ctx),
        "android-apk:code-scan" => run_code_scan(input, ctx),
        "android-apk:sast-handoff" => run_sast_handoff(input, ctx),
        "android-apk:native-libs" => run_native_libs_scan(input, ctx),
        "android-apk:hybrid-detect" => run_hybrid_detect(input, ctx),
        "android-apk:scan" => run_android_apk_scan(input, ctx),
        other => anyhow::bail!("native scanner tool {other:?} has no executor mapping"),
    }
}

pub(in crate::modules) fn run_semgrep_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let scanner = SemgrepScanner::from_tool_input(&input)?;
    if let Err(error) = scanner.preflight() {
        return Ok(failed_tool_output("semgrep:scan", &target, error));
    }
    crate::workspace::source_snapshot::run_source_bound_tool(ctx, "semgrep:scan", &target, || {
        run_started_semgrep_scan(&target, &scanner, &input, ctx)
    })
}

fn run_started_semgrep_scan(
    target: &Path,
    scanner: &SemgrepScanner,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    emit_scan_start(ctx, "semgrep", &target);
    let outcome =
        match ctx.with_cancellation(|cancel| scanner.scan_outcome_with_cancel(&target, cancel)) {
            Ok(outcome) => outcome,
            Err(error) => return Ok(failed_tool_output("semgrep:scan", &target, error)),
        };
    let mut findings = outcome.findings;
    emit_scan_coverage_gaps(ctx, "semgrep", &outcome.scan_errors);
    let index_static_evidence = whitebox_static_profile_requested(input)?;
    if index_static_evidence {
        let static_proof_state =
            whitebox_static_proof_state_from_input(input)?.unwrap_or(StaticProofState::SignalOnly);
        mark_whitebox_static_findings(&mut findings, static_proof_state)?;
    }
    let persisted = persist_semgrep_findings(
        &target,
        &findings,
        ctx,
        index_static_evidence,
        &outcome.scan_errors,
    )?;
    emit_scan_done(ctx, "semgrep", findings.len());
    Ok(
        SemgrepScanReport::new(target.display().to_string(), findings, persisted)
            .with_scan_errors(outcome.scan_errors)
            .to_tool_json(),
    )
}

fn emit_scan_coverage_gaps(ctx: &ToolExecutionContext<'_>, scanner: &str, scan_errors: &[String]) {
    if scan_errors.is_empty() {
        return;
    }
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "scan",
                format!(
                    "{scanner} reported {} scan error{} · coverage incomplete",
                    scan_errors.len(),
                    if scan_errors.len() == 1 { "" } else { "s" },
                ),
            )
            .emit();
    }
}

pub(in crate::modules) fn run_codeql_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let scanner = CodeqlScanner::from_tool_input(&input)?;
    if let Err(error) = scanner.preflight() {
        return Ok(failed_tool_output("codeql:scan", &target, error));
    }
    crate::workspace::source_snapshot::run_source_bound_tool(ctx, "codeql:scan", &target, || {
        run_started_codeql_scan(&target, &scanner, &input, ctx)
    })
}

fn run_started_codeql_scan(
    target: &Path,
    scanner: &CodeqlScanner,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    emit_scan_start(ctx, "codeql", &target);
    let mut output =
        match ctx.with_cancellation(|cancel| scanner.scan_with_artifacts(&target, cancel)) {
            Ok(output) => output,
            Err(error) => return Ok(failed_tool_output("codeql:scan", &target, error)),
        };
    let index_static_evidence = whitebox_static_profile_requested(input)?;
    if index_static_evidence {
        let static_proof_state =
            whitebox_static_proof_state_from_input(input)?.unwrap_or(StaticProofState::SignalOnly);
        mark_whitebox_static_findings(&mut output.findings, static_proof_state)?;
    }
    persist_and_report_codeql_scan(&target, output, ctx, index_static_evidence)
}

fn persist_and_report_codeql_scan(
    target: &Path,
    output: ScanEngineOutput,
    ctx: &ToolExecutionContext<'_>,
    index_static_evidence: bool,
) -> Result<Value> {
    let ScanEngineOutput {
        findings,
        codeql_sarif_documents,
        scan_errors,
    } = output;
    emit_scan_coverage_gaps(ctx, "codeql", &scan_errors);
    let persisted = persist_codeql_findings(
        target,
        &findings,
        ctx,
        &codeql_sarif_documents,
        index_static_evidence,
        &scan_errors,
    )?;
    emit_scan_done(ctx, "codeql", findings.len());
    Ok(
        CodeqlScanReport::new(target.display().to_string(), findings, persisted)
            .with_sarif_documents(codeql_sarif_documents)
            .with_scan_errors(scan_errors)
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
    let report = match ctx.with_cancellation(|cancel| scan_iac(&target, &options, cancel)) {
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

pub(in crate::modules) fn run_cargo_audit_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    emit_scan_start(ctx, "cargo-audit", &target);
    let scanner = CargoAuditScanner;
    let findings = match ctx.with_cancellation(|cancel| scanner.scan(&target, cancel)) {
        Ok(findings) => findings,
        Err(error) => return Ok(failed_tool_output("cargo-audit:scan", &target, error)),
    };
    let persisted = persist_iac_findings(&target, &findings, ctx)?;
    emit_scan_done(ctx, "cargo-audit", findings.len());
    Ok(cargo_audit_output(&target, findings, persisted))
}

pub(in crate::modules) fn run_govulncheck_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let scanner = GovulncheckScanner;
    if let Err(error) = scanner.preflight() {
        return Ok(failed_tool_output("govulncheck:scan", &target, error));
    }
    emit_scan_start(ctx, "govulncheck", &target);
    let findings = match ctx.with_cancellation(|cancel| scanner.scan(&target, cancel)) {
        Ok(findings) => findings,
        Err(error) => return Ok(failed_tool_output("govulncheck:scan", &target, error)),
    };
    let persisted = persist_iac_findings(&target, &findings, ctx)?;
    emit_scan_done(ctx, "govulncheck", findings.len());
    Ok(govulncheck_output(&target, findings, persisted))
}

fn govulncheck_output(target: &Path, findings: Vec<Finding>, persisted: Option<Value>) -> Value {
    crate::scan::completed_scan_tool_json(
        govulncheck_summary(target, findings.len()),
        json!({
            "target": target.display().to_string(),
            "count": findings.len(),
            "coreFindings": findings,
            "findings": findings,
            "persisted": persisted,
        }),
    )
}

fn govulncheck_summary(target: &Path, count: usize) -> String {
    format!(
        "govulncheck: {count} reachable vulnerability finding{} under {}",
        if count == 1 { "" } else { "s" },
        target.display()
    )
}

fn cargo_audit_output(target: &Path, findings: Vec<Finding>, persisted: Option<Value>) -> Value {
    crate::scan::completed_scan_tool_json(
        cargo_audit_summary(target, findings.len()),
        json!({
            "target": target.display().to_string(),
            "count": findings.len(),
            "coreFindings": findings,
            "findings": findings,
            "persisted": persisted,
        }),
    )
}

fn cargo_audit_summary(target: &Path, count: usize) -> String {
    format!(
        "cargo-audit: {count} advisory finding{} under {}",
        if count == 1 { "" } else { "s" },
        target.display()
    )
}

pub(in crate::modules) fn run_sbom_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    emit_scan_start(ctx, "sbom-scan", &target);
    let report = match ctx.with_cancellation(|cancel| scan_sbom(&target, cancel)) {
        Ok(report) => report,
        Err(error) => return Ok(failed_tool_output("sbom-scan:scan", &target, error)),
    };
    emit_scan_done(ctx, "sbom-scan", report.components.len());
    Ok(report.to_tool_json())
}

pub(in crate::modules) fn run_license_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let options = license_scan_options_from_input(&input)?;
    emit_scan_start(ctx, "license-scan", &target);
    let report = match ctx
        .with_cancellation(|cancel| scan_licenses_with_options(&target, cancel, options))
    {
        Ok(report) => report,
        Err(error) => return Ok(failed_tool_output("license-scan:scan", &target, error)),
    };
    let findings = report
        .findings
        .iter()
        .map(|finding| finding.to_core_finding())
        .collect::<Vec<_>>();
    let persisted = persist_iac_findings(&target, &findings, ctx)?;
    emit_scan_done(ctx, "license-scan", findings.len());
    let mut output = report.to_tool_json();
    output["data"]["coreFindings"] = json!(findings);
    if let Some(persisted) = persisted {
        output["data"]["persisted"] = json!(persisted);
    }
    Ok(output)
}

fn license_scan_options_from_input(input: &Value) -> Result<LicenseScanOptions> {
    Ok(LicenseScanOptions {
        require_source_spdx_headers: optional_bool_input(
            input,
            &[
                "requireSourceSpdxHeaders",
                "require_source_spdx_headers",
                "requireSpdxHeaders",
                "require_spdx_headers",
            ],
        )?,
    })
}

fn optional_bool_input(input: &Value, keys: &[&str]) -> Result<bool> {
    for key in keys {
        let Some(value) = input.get(*key) else {
            continue;
        };
        return value
            .as_bool()
            .ok_or_else(|| anyhow::anyhow!("license-scan: {key} must be a boolean"));
    }
    Ok(false)
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
    let model = require_exploit_chain_model(&input, ctx)?;
    let report: ExploitChainReport = ctx.with_cancellation(|cancel| {
        scan_exploit_chains_with_runtime(
            &target,
            cancel,
            scanner.max_evidence,
            Some(runtime),
            Some(model.as_str()),
        )
    })?;
    let persisted = persist_exploit_chain_findings(&target, &report, ctx)?;
    emit_scan_done(ctx, "exploit-chain", report.findings.len());
    Ok(exploit_chain_output(report, &target, persisted))
}

fn require_exploit_chain_runtime(runtime: Option<&dyn AgentRuntime>) -> Result<&dyn AgentRuntime> {
    runtime.ok_or_else(|| {
        anyhow::anyhow!(
            "exploit-chain:scan requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies."
        )
    })
}

fn require_exploit_chain_model(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<String> {
    resolve_tool_model("exploit-chain:scan", input, ctx)
}

fn persist_exploit_chain_findings(
    target: &Path,
    report: &ExploitChainReport,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<GenericPersistedRun>> {
    persist_tool_findings(ctx, target, &report.findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_codeql_reported_gaps_reach_the_partial_ledger() {
        let root = tempfile::tempdir().unwrap();
        let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = crate::V2Config::default();
        let trace = crate::run_artifacts::TraceHandle::jsonl(root.path(), "codeql-gap");
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: Some(&trace),
            cancellation: None,
            authorization: Default::default(),
        };
        let output = ScanEngineOutput {
            findings: vec![],
            codeql_sarif_documents: vec![],
            scan_errors: vec!["go: labeled missing database".into()],
        };
        let report = persist_and_report_codeql_scan(root.path(), output, &ctx, false).unwrap();
        assert_eq!(
            crate::tool_result_status(&report),
            crate::ToolResultStatus::Partial
        );
        assert_eq!(
            report["data"]["scanErrors"][0],
            "go: labeled missing database"
        );
        assert_eq!(
            store.run_status("codeql-gap").unwrap().as_deref(),
            Some("partial")
        );
    }

    #[test]
    fn cargo_audit_output_preserves_static_proof_state_on_core_findings() {
        let finding = Finding::new_tool(
            "cargo-audit",
            "RUSTSEC-2099-0001",
            "Cargo.lock",
            1,
            None,
            crate::findings::Severity::High,
            "advisory finding",
        )
        .with_static_proof_state(StaticProofState::SignalOnly);

        let output = cargo_audit_output(Path::new("/repo"), vec![finding], None);

        assert_eq!(output["status"], json!("completed"));
        assert_eq!(
            output["data"]["coreFindings"][0]["tool"],
            json!("cargo-audit")
        );
        assert_eq!(
            output["data"]["coreFindings"][0]["staticProofState"],
            json!("signal_only")
        );
        assert_eq!(
            output["data"]["findings"][0]["staticProofState"],
            json!("signal_only")
        );
    }
}

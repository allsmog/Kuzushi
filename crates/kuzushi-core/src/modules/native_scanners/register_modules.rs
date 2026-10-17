use super::*;

#[cfg(test)]
use super::cargo_audit_module::cargo_audit_output;
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
        "codeql:scan" => super::codeql_scan::run(input, ctx),
        "iac-scan:scan" => run_iac_scan(input, ctx),
        "cargo-audit:scan" => run_cargo_audit_scan(input, ctx),
        "govulncheck:scan" => super::govulncheck_scan::run(input, ctx),
        "license-scan:scan" => super::license_scan::run(input, ctx),
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

pub(super) fn emit_scan_coverage_gaps(
    ctx: &ToolExecutionContext<'_>,
    scanner: &str,
    scan_errors: &[String],
) {
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

pub(super) fn emit_scan_start(ctx: &ToolExecutionContext<'_>, scanner: &str, target: &Path) {
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

pub(super) fn emit_scan_done(ctx: &ToolExecutionContext<'_>, scanner: &str, findings: usize) {
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

pub(in crate::modules) fn run_sbom_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    super::sbom::execute(input, ctx)
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

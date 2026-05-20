use super::*;

impl ModuleRegistry {
    pub(in crate::modules) fn dispatch_catalog_tool(&self, name: &str) -> ToolDispatchResult {
        match name {
            "catalog:modules" => Some(Ok(json!(self
                .modules()
                .map(|builtin| builtin.metadata())
                .collect::<Vec<_>>()))),
            "catalog:tools" => Some(Ok(json!(self.tools().collect::<Vec<_>>()))),
            _ => None,
        }
    }

    pub(in crate::modules) fn dispatch_module_recommender_tool(
        &self,
        name: &str,
        input: &Value,
        ctx: &ToolExecutionContext<'_>,
    ) -> ToolDispatchResult {
        match name {
            "module-recommender:recommend" => Some(
                crate::capabilities::module_recommender::execute_module_recommender_tool(
                    input.clone(),
                    ctx,
                    visible_tool_names(self),
                ),
            ),
            _ => None,
        }
    }
}

fn visible_tool_names(registry: &ModuleRegistry) -> Vec<String> {
    registry.tools().map(|tool| tool.name.clone()).collect()
}

pub(in crate::modules) fn dispatch_context_workspace_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> ToolDispatchResult {
    match name {
        "context:build" | "context-lite:index" => {
            Some(context::build_context_snapshot(input.clone(), ctx))
        }
        "config:show" => Some(Ok(json!(ctx.config))),
        "router:show" => Some(router_show_tool(input.clone(), ctx)),
        "workspace:status" => Some(Ok(workspace_status_json(ctx))),
        "workspace:export-findings" => Some(export_workspace_findings_tool(input.clone(), ctx)),
        "findings:list" => Some(list_findings_tool(input, ctx)),
        "report:build" => Some(build_report_tool(input, ctx)),
        _ => None,
    }
}

pub(in crate::modules) fn workspace_status_json(ctx: &ToolExecutionContext<'_>) -> Value {
    json!({
        "ok": ctx.workspace.is_some(),
        "output": workspace_status_output(ctx),
        "root": ctx.workspace.map(|workspace| workspace.root().display().to_string()),
        "stateDir": ctx.workspace.map(|workspace| workspace.state_dir().display().to_string()),
        "findingsDb": ctx.workspace.map(|workspace| workspace.findings_db_path().display().to_string()),
        "runtime": ctx.config.runtime.kind,
        "model": ctx.config.model,
    })
}

pub(in crate::modules) fn list_findings_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let filter = FindingListFilter::from_tool_input(input)?;
    let store = ctx
        .findings_store
        .context("findings:list requires a findings store")?;
    Ok(store.list_findings_filtered(&filter)?.to_tool_json())
}

pub(in crate::modules) fn build_report_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    let run_id = string_input_any(input, &["runId", "run_id"]);
    Ok(crate::report::build_run_report(&target, run_id.as_deref())?.to_tool_json())
}

pub(in crate::modules) fn dispatch_native_security_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "dep-hygiene:check" => Some(run_dep_hygiene_tool(input, ctx)),
        "secret-scan:scan" => Some(run_secret_scan_tool(input, ctx)),
        "semgrep:scan"
        | "codeql:scan"
        | "iac-scan:scan"
        | "exploit-chain:scan"
        | "android-apk:check-env"
        | "android-apk:prepare"
        | "android-apk:manifest-scan"
        | "android-apk:network-security-config"
        | "android-apk:fileprovider-scan"
        | "android-apk:webview-scan"
        | "android-apk:sast-handoff"
        | "android-apk:native-libs"
        | "android-apk:hybrid-detect"
        | "android-apk:scan" => Some(native_scanners::execute_tool(
            name,
            input.clone(),
            ctx,
            runtime,
        )),
        "sast:scan" => Some(run_sast_scan(input.clone(), ctx, runtime)),
        _ => None,
    }
}

pub(in crate::modules) fn run_dep_hygiene_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "check",
                format!("dep-hygiene start · target={}", target.display()),
            )
            .emit();
    }
    let report = match check_dependency_hygiene(&target) {
        Ok(report) => report,
        Err(error) => return Ok(failed_tool_output("dep-hygiene:check", &target, error)),
    };
    let store_result = store_dep_hygiene_findings(&report, ctx)?;
    if let Some(trace) = ctx.trace {
        let _ = trace.step("done", "check", "dep-hygiene complete").emit();
    }
    Ok(output_with_core_findings(report.to_tool_json(), store_result))
}

pub(in crate::modules) fn run_secret_scan_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "scan",
                format!("secret-scan start · target={}", target.display()),
            )
            .emit();
    }
    let options = SecretScanOptions::from_tool_input(input)?;
    let report = match scan_for_secrets(&target, &options, &ScanCancellation::default()) {
        Ok(report) => report,
        Err(error) => return Ok(failed_tool_output("secret-scan:scan", &target, error)),
    };
    let store_result = store_secret_scan_findings(&report, ctx)?;
    if let Some(trace) = ctx.trace {
        let _ = trace.step("done", "scan", "secret-scan complete").emit();
    }
    Ok(output_with_core_findings(report.to_tool_json(), store_result))
}

struct StoredCoreFindings {
    core_findings: Vec<crate::findings::Finding>,
    persisted: Option<crate::findings::GenericPersistedRun>,
}

fn store_dep_hygiene_findings(
    report: &crate::dep_hygiene::DepHygieneReport,
    ctx: &ToolExecutionContext<'_>,
) -> Result<StoredCoreFindings> {
    let target = std::path::Path::new(&report.target);
    let findings = report
        .findings
        .iter()
        .map(|finding| finding.to_core_finding(target))
        .collect::<Vec<_>>();
    let persisted = crate::findings::persist_tool_findings(
        "dep-hygiene",
        target,
        &findings,
        ctx.workspace,
        ctx.findings_store,
    )?;
    Ok(StoredCoreFindings {
        core_findings: findings,
        persisted,
    })
}

fn store_secret_scan_findings(
    report: &crate::secret_scan::SecretScanReport,
    ctx: &ToolExecutionContext<'_>,
) -> Result<StoredCoreFindings> {
    let target = std::path::Path::new(&report.target);
    let findings = report
        .findings
        .iter()
        .map(|finding| finding.to_core_finding())
        .collect::<Vec<_>>();
    let persisted = crate::findings::persist_tool_findings(
        "secret-scan",
        target,
        &findings,
        ctx.workspace,
        ctx.findings_store,
    )?;
    Ok(StoredCoreFindings {
        core_findings: findings,
        persisted,
    })
}

fn output_with_core_findings(mut output: Value, store_result: StoredCoreFindings) -> Value {
    output["data"]["coreFindings"] = json!(store_result.core_findings);
    if let Some(persisted) = store_result.persisted {
        output["data"]["persisted"] = json!(persisted);
    }
    output
}

pub(in crate::modules) fn dispatch_agentic_security_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "agentic-sast:scan" => Some(run_agentic_sast_tool(input, ctx, runtime)),
        "variant:lift-pattern" => Some(run_variant_lift_pattern(input.clone(), ctx, runtime)),
        "variant:hunt" => Some(run_variant_hunt(input.clone(), ctx, runtime)),
        "ndiff:fetch-cve" => Some(run_ndiff_fetch_cve(input.clone())),
        "ndiff:extract-fix-pattern" => {
            Some(run_ndiff_extract_fix_pattern(input.clone(), ctx, runtime))
        }
        "ndiff:hunt-variants" => Some(run_ndiff_hunt_variants(input.clone(), ctx, runtime)),
        "carlini-threat-hunt:run" | "offense-review:threat-hunt" => {
            Some(run_carlini_threat_hunt(input.clone(), ctx, runtime))
        }
        "pipeline:taint-cwe-select" => Some(run_taint_cwe_select(input.clone(), ctx, runtime)),
        "taint-iris:hunt" => Some(run_taint_iris_tool(input, ctx, runtime)),
        "taint-iris-next:hunt" => Some(run_taint_iris_next_tool(input, ctx, runtime)),
        "taint-iris-next:dataflow-plan" => Some(run_taint_iris_next_plan_tool(input, ctx)),
        "taint-iris-next:source-sink-trace" => Some(run_taint_iris_next_trace_tool(input, ctx)),
        "taint-iris-next:finding-review" => {
            Some(run_taint_iris_next_review_tool(input, ctx, runtime))
        }
        "taint-iris-next:catalog" => Some(run_taint_iris_next_catalog_tool(input, ctx, runtime)),
        "taint-iris-next:codeql-db" => {
            Some(run_taint_iris_next_codeql_db_tool(input, ctx, runtime))
        }
        _ => None,
    }
}

pub(in crate::modules) fn run_agentic_sast_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    Ok(run_agentic_sast_report(input, ctx, runtime)?.to_tool_json())
}

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

pub(in crate::modules) fn dispatch_native_security_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "dep-hygiene:check" => Some(run_dep_hygiene_tool(input, ctx)),
        "secret-scan:scan" => Some(run_secret_scan_tool(input, ctx)),
        "semgrep:scan" | "codeql:scan" | "iac-scan:scan" => {
            Some(native_scanners::execute_tool(name, input.clone(), ctx))
        }
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
    let report = check_dependency_hygiene(&target)?;
    if let Some(trace) = ctx.trace {
        let _ = trace.step("done", "check", "dep-hygiene complete").emit();
    }
    Ok(report.to_tool_json())
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
    let report = scan_for_secrets(&target, &options, &ScanCancellation::default())?;
    if let Some(trace) = ctx.trace {
        let _ = trace.step("done", "scan", "secret-scan complete").emit();
    }
    Ok(report.to_tool_json())
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
        "carlini-threat-hunt:run" => Some(run_carlini_threat_hunt(input.clone(), ctx, runtime)),
        "pipeline:taint-cwe-select" => Some(run_taint_cwe_select(input.clone(), ctx, runtime)),
        "taint-iris:hunt" => Some(run_taint_iris_tool(input, ctx, runtime)),
        "taint-iris-next:hunt" => Some(run_taint_iris_next_tool(input, ctx, runtime)),
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

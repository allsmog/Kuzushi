use super::*;

pub(crate) fn router_show_tool(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let paths = tool_context_config_paths(ctx, None)?;
    let router = load_router_for_paths(&paths);
    let options = persistent_tool_options_for_paths(&paths)?;
    let roles = router_role_rows(&input, ctx, &router, &options);
    Ok(router_show_response(
        ctx.config.model.clone(),
        &router,
        roles,
    ))
}

fn load_router_for_paths(paths: &crate::config::ConfigPaths) -> crate::agent_router::AgentRouter {
    crate::agent_router::AgentRouter::load(paths).unwrap_or_default()
}

fn router_role_rows(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    router: &crate::agent_router::AgentRouter,
    options: &crate::options::ToolOptionStore,
) -> Vec<Value> {
    crate::agent_router::AgentRole::all()
        .iter()
        .map(|role| router_role_row(input, ctx, router, options, *role))
        .collect()
}

fn router_role_row(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    router: &crate::agent_router::AgentRouter,
    options: &crate::options::ToolOptionStore,
    role: crate::agent_router::AgentRole,
) -> Value {
    let key = role.option_store_key();
    let option_override = router_option_override(input, options, &key);
    let toml_route = router.route(role).cloned();
    let effective = option_override
        .clone()
        .or_else(|| toml_route.as_ref().map(|r| r.primary.clone()))
        .or_else(|| router.default_model().map(str::to_string))
        .or_else(|| ctx.config.model.clone());
    json!({
        "role": role.as_key(),
        "optionKey": key,
        "operatorOverride": option_override,
        "tomlPrimary": toml_route.as_ref().map(|r| r.primary.clone()),
        "tomlFallbacks": toml_route.as_ref().map(|r| r.fallbacks.clone()).unwrap_or_default(),
        "effective": effective,
    })
}

fn router_option_override(
    input: &Value,
    options: &crate::options::ToolOptionStore,
    key: &str,
) -> Option<String> {
    router_input_option_override(input, key).or_else(|| router_stored_option_override(options, key))
}

fn router_input_option_override(input: &Value, key: &str) -> Option<String> {
    input
        .as_object()
        .and_then(|obj| obj.get(key))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn router_stored_option_override(
    options: &crate::options::ToolOptionStore,
    key: &str,
) -> Option<String> {
    options
        .values_for(
            crate::options::OptionScope::Global,
            &crate::options::OptionTarget::All,
        )?
        .get(key)?
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod router_show_tests {
    use super::*;

    #[test]
    fn router_option_override_reads_global_setg_value() {
        let mut options = crate::options::ToolOptionStore::new();
        options.set_value(
            crate::options::OptionScope::Global,
            crate::options::OptionTarget::All,
            "MODEL_DEEP_AUDITOR",
            json!("openai:setg-model"),
        );

        assert_eq!(
            router_option_override(&json!({}), &options, "MODEL_DEEP_AUDITOR").as_deref(),
            Some("openai:setg-model")
        );
    }

    #[test]
    fn router_input_override_beats_stored_value() {
        let mut options = crate::options::ToolOptionStore::new();
        options.set_value(
            crate::options::OptionScope::Global,
            crate::options::OptionTarget::All,
            "MODEL_DEEP_AUDITOR",
            json!("openai:setg-model"),
        );

        assert_eq!(
            router_option_override(
                &json!({"MODEL_DEEP_AUDITOR": "anthropic:input-model"}),
                &options,
                "MODEL_DEEP_AUDITOR",
            )
            .as_deref(),
            Some("anthropic:input-model")
        );
    }
}

fn router_show_response(
    config_model: Option<String>,
    router: &crate::agent_router::AgentRouter,
    roles: Vec<Value>,
) -> Value {
    let summary = format!(
        "router:show resolved {} role route{}",
        roles.len(),
        if roles.len() == 1 { "" } else { "s" }
    );
    let data = json!({
        "configModel": config_model,
        "tomlDefaultModel": router.default_model(),
        "roles": roles,
    });
    crate::module_result::completed_output_result(summary.clone(), summary, data)
}

pub(crate) fn run_full_mode_hunt_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let cfg = full_mode_config_from_input(&input, ctx)?;
    run_full_mode_hunt_config(ctx, runtime, cfg)
}

fn run_full_mode_hunt_config(
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    cfg: crate::capabilities::full_mode_multi::FullModeConfig,
) -> Result<Value> {
    if cfg.dry_run {
        return full_mode_dry_run_response(&cfg, ctx);
    }

    run_live_full_mode_hunt(ctx, runtime, cfg)
}

struct FullModeRuntimeContext<'a> {
    routed: crate::agent_router::RoutedRuntime<'a>,
    limiter: Option<crate::spend::SpendLimiter>,
}

fn run_live_full_mode_hunt(
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    cfg: crate::capabilities::full_mode_multi::FullModeConfig,
) -> Result<Value> {
    let report = complete_live_full_mode_report(ctx, runtime, &cfg)?;
    Ok(crate::capabilities::full_mode_multi::report_to_tool_json(
        &report,
    ))
}

fn complete_live_full_mode_report(
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    cfg: &crate::capabilities::full_mode_multi::FullModeConfig,
) -> Result<crate::capabilities::full_mode_multi::FullModeReport> {
    let runtime_context = prepare_full_mode_runtime_context(ctx, runtime)?;
    run_live_full_mode_with_context(ctx, &runtime_context, cfg)
}

fn run_live_full_mode_with_context(
    ctx: &ToolExecutionContext<'_>,
    runtime_context: &FullModeRuntimeContext<'_>,
    cfg: &crate::capabilities::full_mode_multi::FullModeConfig,
) -> Result<crate::capabilities::full_mode_multi::FullModeReport> {
    let mut report = run_live_full_mode_report(cfg, ctx, runtime_context)?;
    apply_full_mode_auto_triage(ctx, runtime_context, cfg, &mut report)?;
    Ok(report)
}

fn prepare_full_mode_runtime_context<'a>(
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<FullModeRuntimeContext<'a>> {
    let routed = required_full_mode_routed_runtime(runtime, ctx)?;
    let limiter = full_mode_spend_limiter(ctx)?;
    Ok(FullModeRuntimeContext { routed, limiter })
}

fn required_full_mode_routed_runtime<'a>(
    runtime: Option<&'a dyn AgentRuntime>,
    ctx: &ToolExecutionContext<'_>,
) -> Result<crate::agent_router::RoutedRuntime<'a>> {
    let runtime = required_full_mode_runtime(runtime)?;
    full_mode_routed_runtime(runtime, ctx)
}

fn run_live_full_mode_report(
    cfg: &crate::capabilities::full_mode_multi::FullModeConfig,
    ctx: &ToolExecutionContext<'_>,
    runtime_context: &FullModeRuntimeContext<'_>,
) -> Result<crate::capabilities::full_mode_multi::FullModeReport> {
    let report = crate::capabilities::full_mode_multi::run(
        &runtime_context.routed,
        runtime_context.limiter.as_ref(),
        cfg,
    )?;
    persist_full_mode_report(ctx, &report)?;
    Ok(report)
}

fn apply_full_mode_auto_triage(
    ctx: &ToolExecutionContext<'_>,
    runtime_context: &FullModeRuntimeContext<'_>,
    cfg: &crate::capabilities::full_mode_multi::FullModeConfig,
    report: &mut crate::capabilities::full_mode_multi::FullModeReport,
) -> Result<()> {
    if !cfg.auto_triage {
        return Ok(());
    }

    // Auto-triage hook: when enabled, run deep-audit on every persisted
    // HIGH+CRITICAL finding using the same routed runtime + spend limiter
    // the chunk pass used. The verdict is saved back into the findings
    // store so a later `findings --triage` query reflects it.
    let extra = auto_triage_full_mode_findings(cfg, ctx, &runtime_context.routed, report)?;
    report.cost_usd += extra;
    Ok(())
}

fn auto_triage_full_mode_findings(
    cfg: &crate::capabilities::full_mode_multi::FullModeConfig,
    ctx: &ToolExecutionContext<'_>,
    routed: &crate::agent_router::RoutedRuntime<'_>,
    report: &crate::capabilities::full_mode_multi::FullModeReport,
) -> Result<f64> {
    use crate::spend::SpendLimiter;

    let Some((workspace, store)) = auto_triage_resources(ctx)? else {
        return Ok(0.0);
    };
    let spend = SpendLimiter::open(workspace.findings_db_path())?;
    let audit_cfg = auto_triage_config(cfg, workspace.root());

    Ok(report
        .findings
        .iter()
        .map(|finding| {
            auto_triage_candidate_cost(finding, routed, Some(&spend), &audit_cfg, store, workspace)
        })
        .sum())
}

fn auto_triage_resources<'a>(
    ctx: &'a ToolExecutionContext<'a>,
) -> Result<
    Option<(
        &'a crate::workspace::WorkspaceTarget,
        &'a crate::findings::FindingStore,
    )>,
> {
    let workspace = ctx.workspace.ok_or_else(|| {
        anyhow::anyhow!(crate::workspace::active_workspace_required_message(
            "autoTriage"
        ))
    })?;
    Ok(ctx.findings_store.map(|store| (workspace, store)))
}

fn auto_triage_config(
    cfg: &crate::capabilities::full_mode_multi::FullModeConfig,
    workspace_root: &std::path::Path,
) -> crate::capabilities::deep_auditor::DeepAuditConfig {
    use crate::capabilities::deep_auditor::{
        DeepAuditConfig, DEFAULT_MAX_STEPS, DEFAULT_PASSES, DEFAULT_TEMPERATURE,
    };
    let max_steps = cfg
        .auto_triage_max_steps
        .unwrap_or(DEFAULT_MAX_STEPS.min(12));
    let deposit_usd = cfg.auto_triage_deposit_usd.unwrap_or(1.0);
    DeepAuditConfig {
        workspace_root: workspace_root.to_path_buf(),
        max_steps,
        deposit_usd,
        system_prompt: None,
        include_static_evidence: true,
        temperature: DEFAULT_TEMPERATURE,
        passes: DEFAULT_PASSES,
    }
}

fn auto_triage_candidate_cost(
    finding: &crate::findings::Finding,
    routed: &crate::agent_router::RoutedRuntime<'_>,
    spend: Option<&crate::spend::SpendLimiter>,
    audit_cfg: &crate::capabilities::deep_auditor::DeepAuditConfig,
    store: &crate::findings::FindingStore,
    workspace: &crate::workspace::WorkspaceTarget,
) -> f64 {
    use crate::capabilities::deep_auditor::run_deep_auditor;

    if !matches!(
        finding.severity,
        crate::findings::Severity::High | crate::findings::Severity::Critical
    ) {
        return 0.0;
    }
    run_deep_auditor(routed, spend, audit_cfg, finding)
        .map(|outcome| {
            persist_auto_triage_outcome(finding, store, workspace, &outcome);
            outcome.cost_usd
        })
        .unwrap_or(0.0)
}

fn persist_auto_triage_outcome(
    finding: &crate::findings::Finding,
    store: &crate::findings::FindingStore,
    workspace: &crate::workspace::WorkspaceTarget,
    outcome: &crate::capabilities::deep_auditor::DeepAuditOutcome,
) {
    use crate::capabilities::deep_auditor::save_evidence;

    if let Some(id) = finding.id {
        let _ = store.save_triage(id, &outcome.triage);
        let _ = save_evidence(&workspace.findings_db_path(), id, &outcome.evidence);
    }
}

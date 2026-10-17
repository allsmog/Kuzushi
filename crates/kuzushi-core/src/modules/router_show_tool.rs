use super::*;

pub(crate) fn router_show_tool(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let paths = tool_context_config_paths(ctx, None)?;
    let router = load_router_for_paths(&paths)?;
    let options = persistent_tool_options_for_paths(&paths)?;
    let roles = router_role_rows(&input, ctx, &router, &options);
    Ok(router_show_response(
        ctx.config.model.clone(),
        &router,
        roles,
    ))
}

fn load_router_for_paths(
    paths: &crate::config::ConfigPaths,
) -> Result<crate::agent_router::AgentRouter> {
    crate::agent_router::AgentRouter::load(paths).with_context(|| {
        format!(
            "router:show could not load operator model routing from {}",
            crate::agent_router::AgentRouter::operator_models_path(paths).display()
        )
    })
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
    use std::fs;

    #[test]
    fn readable_routing_retains_selected_models_and_their_override_source() {
        let role = json!({"role":"triage", "effective":"openai:operator-role", "operatorOverride":"openai:operator-role"});
        let result = router_show_response(
            Some("openai:operator-config".into()),
            &crate::agent_router::AgentRouter::empty(),
            vec![role.clone()],
        );
        let output = result["output"].as_str().unwrap();
        assert!(output.contains("Config model: openai:operator-config"));
        assert!(output.contains("triage: openai:operator-role (operator override)"));
        assert!(output.contains("credentials and provider acceptance are not verified"));
        assert_eq!(result["data"]["roles"][0], role);
        assert_eq!(
            route_override_label(&json!({"tomlPrimary":"openai:role"})),
            " (models.toml role)"
        );
        assert_eq!(route_override_label(&json!({})), "");
    }

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

    #[test]
    fn malformed_models_file_is_reported_with_its_path() {
        let temp = tempfile::tempdir().unwrap();
        let models = crate::workspace::workspace_models_path(temp.path());
        fs::create_dir_all(models.parent().unwrap()).unwrap();
        fs::write(&models, "[roles.deep_auditor\nprimary = nope").unwrap();
        let paths = crate::config::ConfigPaths {
            home_dir: temp.path().to_path_buf(),
            target_dir: None,
        };

        let error = load_router_for_paths(&paths).unwrap_err().to_string();

        assert!(error.contains("router:show"), "{error}");
        assert!(error.contains(&models.display().to_string()), "{error}");
    }

    #[test]
    fn unreadable_models_path_is_reported_instead_of_defaulting() {
        let temp = tempfile::tempdir().unwrap();
        let models = crate::workspace::workspace_models_path(temp.path());
        fs::create_dir_all(&models).unwrap();
        let paths = crate::config::ConfigPaths {
            home_dir: temp.path().to_path_buf(),
            target_dir: None,
        };

        let error = load_router_for_paths(&paths).unwrap_err().to_string();

        assert!(error.contains("router:show"), "{error}");
        assert!(error.contains(&models.display().to_string()), "{error}");
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
    let output = format!("{summary}\nConfigured routing only; credentials and provider acceptance are not verified.\nConfig model: {}\n{}",
        config_model.as_deref().unwrap_or("unconfigured"),
        roles.iter().map(router_role_summary).collect::<Vec<_>>().join("\n"),
    );
    let data = json!({
        "configModel": config_model,
        "tomlDefaultModel": router.default_model(),
        "roles": roles,
    });
    crate::module_result::completed_output_result(summary, output, data)
}

fn router_role_summary(role: &Value) -> String {
    format!(
        "  {}: {}{}",
        role["role"].as_str().unwrap_or("unknown role"),
        role["effective"].as_str().unwrap_or("unconfigured"),
        route_override_label(role),
    )
}

fn route_override_label(role: &Value) -> &'static str {
    [
        ("operatorOverride", " (operator override)"),
        ("tomlPrimary", " (models.toml role)"),
    ]
    .into_iter()
    .find(|(field, _)| role[*field].is_string())
    .map(|(_, label)| label)
    .unwrap_or("")
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
    let mut report = with_full_mode_planning_observer(ctx, |progress, canceled| {
        crate::capabilities::full_mode_multi::run_with_observer(
            &runtime_context.routed,
            runtime_context.limiter.as_ref(),
            cfg,
            progress,
            canceled,
        )
    })?;
    persist_full_mode_report(ctx, &mut report)?;
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
    report.observed_cost_usd = crate::runtime::RuntimeCost::checked_sum(
        [report.observed_cost_usd, extra.observed_usd()],
        "full-mode scan plus auto-triage cost",
    )?
    .usd();
    if let (Some(cost_usd), Some(extra_cost_usd)) = (report.cost_usd, extra.exact_usd()) {
        report.cost_usd = Some(
            crate::runtime::RuntimeCost::checked_sum(
                [cost_usd, extra_cost_usd],
                "full-mode exact scan plus auto-triage cost",
            )?
            .usd(),
        );
    } else if !extra.is_complete() {
        report.cost_usd = None;
        report.unresolved_provider_spend = true;
    }
    Ok(())
}

fn auto_triage_full_mode_findings(
    cfg: &crate::capabilities::full_mode_multi::FullModeConfig,
    ctx: &ToolExecutionContext<'_>,
    routed: &crate::agent_router::RoutedRuntime<'_>,
    report: &crate::capabilities::full_mode_multi::FullModeReport,
) -> Result<crate::runtime::RuntimeCostReport> {
    use crate::spend::SpendLimiter;

    let (workspace, store) = auto_triage_resources(ctx)?;
    let spend = SpendLimiter::open(workspace.findings_db_path())?;
    let audit_cfg = auto_triage_config(cfg, workspace.root());

    report.findings.iter().try_fold(
        crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO),
        |cost, finding| {
            cost.checked_add(
                auto_triage_candidate_cost(finding, routed, Some(&spend), &audit_cfg, &store)?,
                "full-mode auto-triage fan-out cost",
            )
        },
    )
}

fn auto_triage_resources<'a>(
    ctx: &'a ToolExecutionContext<'a>,
) -> Result<(
    &'a crate::workspace::WorkspaceTarget,
    crate::findings::FindingStore,
)> {
    let workspace = ctx.workspace.ok_or_else(|| {
        anyhow::anyhow!(crate::workspace::active_workspace_required_message(
            "autoTriage"
        ))
    })?;
    let store = crate::findings::FindingStore::open(workspace.findings_db_path())
        .context("autoTriage could not open the persisted findings store")?;
    Ok((workspace, store))
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
        taint_tools: crate::capabilities::deep_auditor::TaintToolPolicy::Available,
        reviewed_refutation_context: None,
        threat_model_context: None,
    }
}

fn auto_triage_candidate_cost(
    finding: &crate::findings::Finding,
    routed: &crate::agent_router::RoutedRuntime<'_>,
    spend: Option<&crate::spend::SpendLimiter>,
    audit_cfg: &crate::capabilities::deep_auditor::DeepAuditConfig,
    store: &crate::findings::FindingStore,
) -> Result<crate::runtime::RuntimeCostReport> {
    use crate::capabilities::deep_auditor::run_deep_auditor;

    if !auto_triage_severity(finding.severity) {
        return Ok(crate::runtime::RuntimeCostReport::known(
            crate::runtime::RuntimeCost::ZERO,
        ));
    }
    let finding_id = persisted_auto_triage_finding_id(finding)?;
    let outcome = run_deep_auditor(routed, spend, audit_cfg, finding).with_context(|| {
        format!(
            "autoTriage deep audit failed for finding {}",
            finding.fingerprint
        )
    })?;
    persist_auto_triage_outcome(finding_id, store, &outcome).with_context(|| {
        format!(
            "autoTriage could not persist outcome for finding {}",
            finding.fingerprint
        )
    })?;
    deep_audit_cost_report(&outcome)
}

fn auto_triage_severity(severity: crate::findings::Severity) -> bool {
    matches!(
        severity,
        crate::findings::Severity::High | crate::findings::Severity::Critical
    )
}

fn persisted_auto_triage_finding_id(finding: &crate::findings::Finding) -> Result<i64> {
    finding.id.ok_or_else(|| {
        anyhow::anyhow!(
            "autoTriage finding {} was not assigned a persisted id",
            finding.fingerprint
        )
    })
}

fn deep_audit_cost_report(
    outcome: &crate::capabilities::deep_auditor::DeepAuditOutcome,
) -> Result<crate::runtime::RuntimeCostReport> {
    let observed = crate::runtime::RuntimeCost::from_usd(
        outcome.cost_usd,
        "full-mode auto-triage observed cost",
    )?;
    Ok(if outcome.cost_usd_exact {
        crate::runtime::RuntimeCostReport::known(observed)
    } else {
        crate::runtime::RuntimeCostReport::incomplete(observed)
    })
}

fn persist_auto_triage_outcome(
    finding_id: i64,
    store: &crate::findings::FindingStore,
    outcome: &crate::capabilities::deep_auditor::DeepAuditOutcome,
) -> Result<()> {
    use crate::capabilities::deep_auditor::record_evidence;

    store.record_auto_triage(finding_id, &outcome.triage)?;
    record_evidence(store, finding_id, &outcome.evidence)
}

#[cfg(test)]
mod auto_triage_persistence_tests {
    use super::*;

    #[test]
    fn auto_triage_persistence_reports_a_missing_finding_id() {
        let store = crate::findings::FindingStore::open_in_memory().unwrap();
        let outcome = crate::capabilities::deep_auditor::DeepAuditOutcome {
            triage: crate::findings::TriageOutcome::default(),
            evidence: Vec::new(),
            cost_usd: 0.0,
            cost_usd_exact: true,
            steps_used: 1,
            truncated: false,
            consensus_split: false,
        };

        let error = persist_auto_triage_outcome(42, &store, &outcome)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("missing projected finding id 42"),
            "unexpected error: {error}"
        );
    }
}

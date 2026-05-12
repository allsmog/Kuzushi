use super::*;

pub(crate) fn router_show_tool(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    use crate::agent_router::{AgentRole, AgentRouter};
    use crate::config::ConfigPaths;

    // Load models.toml if present. Best-effort — missing file = empty router.
    let target = ctx
        .workspace
        .map(|workspace| workspace.root().to_path_buf());
    let router = ConfigPaths::from_target(target.as_deref())
        .ok()
        .and_then(|paths| AgentRouter::load(&paths).ok())
        .unwrap_or_default();

    let mut roles = Vec::with_capacity(AgentRole::all().len());
    for role in AgentRole::all() {
        let key = role.option_store_key();
        // Operator override merged via effective_tool_input lives in `input`.
        let option_override = input
            .as_object()
            .and_then(|obj| obj.get(&key))
            .and_then(Value::as_str)
            .map(str::to_string);

        let toml_route = router.route(*role).cloned();

        let effective = option_override
            .clone()
            .or_else(|| toml_route.as_ref().map(|r| r.primary.clone()))
            .or_else(|| router.default_model().map(str::to_string))
            .or_else(|| ctx.config.model.clone());

        roles.push(json!({
            "role": role.as_key(),
            "optionKey": key,
            "operatorOverride": option_override,
            "tomlPrimary": toml_route.as_ref().map(|r| r.primary.clone()),
            "tomlFallbacks": toml_route.as_ref().map(|r| r.fallbacks.clone()).unwrap_or_default(),
            "effective": effective,
        }));
    }

    Ok(json!({
        "ok": true,
        "configModel": ctx.config.model,
        "tomlDefaultModel": router.default_model(),
        "roles": roles,
    }))
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

struct FullModeRuntimeContext {
    routed: crate::agent_router::RoutedRuntime,
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
    runtime_context: &FullModeRuntimeContext,
    cfg: &crate::capabilities::full_mode_multi::FullModeConfig,
) -> Result<crate::capabilities::full_mode_multi::FullModeReport> {
    let mut report = run_live_full_mode_report(cfg, ctx, runtime_context)?;
    apply_full_mode_auto_triage(ctx, runtime_context, cfg, &mut report)?;
    Ok(report)
}

fn prepare_full_mode_runtime_context(
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<FullModeRuntimeContext> {
    let routed = required_full_mode_routed_runtime(runtime, ctx)?;
    let limiter = full_mode_spend_limiter(ctx)?;
    Ok(FullModeRuntimeContext { routed, limiter })
}

fn required_full_mode_routed_runtime(
    runtime: Option<&dyn AgentRuntime>,
    ctx: &ToolExecutionContext<'_>,
) -> Result<crate::agent_router::RoutedRuntime> {
    let runtime = required_full_mode_runtime(runtime)?;
    full_mode_routed_runtime(runtime, ctx)
}

fn run_live_full_mode_report(
    cfg: &crate::capabilities::full_mode_multi::FullModeConfig,
    ctx: &ToolExecutionContext<'_>,
    runtime_context: &FullModeRuntimeContext,
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
    runtime_context: &FullModeRuntimeContext,
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
    routed: &crate::agent_router::RoutedRuntime,
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
    let workspace = ctx
        .workspace
        .ok_or_else(|| anyhow::anyhow!("autoTriage requires a workspace target"))?;
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
    routed: &crate::agent_router::RoutedRuntime,
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

pub(crate) fn full_mode_config_from_input(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<crate::capabilities::full_mode_multi::FullModeConfig> {
    Ok(crate::capabilities::full_mode_multi::FullModeConfig {
        workspace_root: resolve_tool_target(input, ctx)?,
        max_tokens_per_chunk: full_mode_max_tokens(input),
        deposit_usd_per_chunk: full_mode_deposit(input),
        include_extensions: Vec::new(),
        language: full_mode_language(input)?,
        dry_run: full_mode_dry_run(input),
        scope_files: full_mode_scope_files(input, ctx)?,
        failed_chunk_ids: full_mode_failed_chunk_ids(input)?,
        auto_triage: input
            .get("autoTriage")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        auto_triage_max_steps: input
            .get("autoTriageMaxSteps")
            .and_then(Value::as_u64)
            .map(|v| v as u32),
        auto_triage_deposit_usd: input.get("autoTriageDepositUsd").and_then(Value::as_f64),
    })
}

pub(crate) fn full_mode_language(
    input: &Value,
) -> Result<crate::capabilities::full_mode_multi::FullModeLanguage> {
    match input
        .get("language")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("c") | None => Ok(crate::capabilities::full_mode_multi::FullModeLanguage::C),
        Some("unknown") => Ok(crate::capabilities::full_mode_multi::FullModeLanguage::Unknown),
        Some(other) => anyhow::bail!("full-mode:hunt: unknown language {other:?}"),
    }
}

pub(crate) fn full_mode_max_tokens(input: &Value) -> usize {
    input
        .get("maxTokensPerChunk")
        .and_then(Value::as_u64)
        .map(|v| v as usize)
        .unwrap_or(12_000)
}

pub(crate) fn full_mode_deposit(input: &Value) -> f64 {
    input
        .get("depositUsdPerChunk")
        .and_then(Value::as_f64)
        .unwrap_or(2.0)
}

pub(crate) fn full_mode_failed_chunk_ids(input: &Value) -> Result<Option<Vec<u32>>> {
    let Some(raw) = input.get("failedChunkIds") else {
        return Ok(None);
    };
    let mut ids = match raw {
        Value::String(csv) => csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(parse_failed_chunk_id)
            .collect::<Result<Vec<_>>>()?,
        Value::Array(values) => values
            .iter()
            .map(parse_failed_chunk_id_value)
            .collect::<Result<Vec<_>>>()?,
        other => anyhow::bail!(
            "full-mode:hunt failedChunkIds must be a comma-separated string or array, got {other}"
        ),
    };
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ids))
    }
}

fn parse_failed_chunk_id(raw: &str) -> Result<u32> {
    raw.parse::<u32>()
        .map_err(|_| anyhow::anyhow!("full-mode:hunt failedChunkIds has non-integer value {raw:?}"))
}

fn parse_failed_chunk_id_value(value: &Value) -> Result<u32> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| {
                anyhow::anyhow!("full-mode:hunt failedChunkIds has out-of-range value {number}")
            }),
        Value::String(raw) => parse_failed_chunk_id(raw.trim()),
        other => anyhow::bail!("full-mode:hunt failedChunkIds has invalid array value {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::full_mode_failed_chunk_ids;
    use serde_json::json;

    #[test]
    fn parses_csv_failed_chunk_ids() {
        let input = json!({"failedChunkIds": "3, 7, 7, 11"});
        assert_eq!(
            full_mode_failed_chunk_ids(&input).expect("csv parse should succeed"),
            Some(vec![3, 7, 11])
        );
    }

    #[test]
    fn parses_array_failed_chunk_ids() {
        let input = json!({"failedChunkIds": [11, "3", 7, "7"]});
        assert_eq!(
            full_mode_failed_chunk_ids(&input).expect("array parse should succeed"),
            Some(vec![3, 7, 11])
        );
    }
}

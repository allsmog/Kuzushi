use super::*;

pub(crate) fn run_deep_audit_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let run = prepare_deep_audit(&input, ctx, runtime)?;
    let routed = deep_audit_routed_runtime(run.runtime, ctx, run.workspace.root())?;
    let spend = deep_audit_spend_limiter(ctx, run.workspace)?;
    let cfg = deep_audit_config(run.workspace, &run.options);
    let outcome = crate::capabilities::deep_auditor::run_deep_auditor(
        &routed,
        Some(&spend),
        &cfg,
        &run.finding,
    )?;
    persist_deep_audit_outcome(&run, &outcome)?;
    Ok(deep_audit_response(&run.finding, outcome))
}

struct DeepAuditRun<'a> {
    runtime: &'a dyn AgentRuntime,
    workspace: &'a crate::WorkspaceTarget,
    store: FindingStore,
    finding: crate::findings::Finding,
    options: DeepAuditOptions,
}

struct DeepAuditOptions {
    max_steps: u32,
    deposit_usd: f64,
    temperature: f32,
    passes: u32,
}

fn prepare_deep_audit<'a>(
    input: &Value,
    ctx: &'a ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<DeepAuditRun<'a>> {
    let runtime = required_deep_audit_runtime(runtime)?;
    let workspace = required_deep_audit_workspace(ctx)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let finding = deep_audit_finding(input, &store)?;
    Ok(DeepAuditRun {
        runtime,
        workspace,
        store,
        finding,
        options: deep_audit_options(input),
    })
}

fn required_deep_audit_runtime(runtime: Option<&dyn AgentRuntime>) -> Result<&dyn AgentRuntime> {
    runtime.ok_or_else(|| anyhow::anyhow!("deep-audit:run requires an agent runtime; none configured"))
}

fn required_deep_audit_workspace<'a>(
    ctx: &ToolExecutionContext<'a>,
) -> Result<&'a crate::WorkspaceTarget> {
    ctx.workspace
        .ok_or_else(|| anyhow::anyhow!("deep-audit:run requires a workspace target"))
}

fn deep_audit_finding(
    input: &Value,
    store: &FindingStore,
) -> Result<crate::findings::Finding> {
    let fingerprint = input
        .get("findingFingerprint")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("deep-audit:run: findingFingerprint is required"))?;
    store
        .get_finding_by_reference(fingerprint)?
        .ok_or_else(|| anyhow::anyhow!("deep-audit:run: no finding for {fingerprint:?}"))
}

fn deep_audit_options(input: &Value) -> DeepAuditOptions {
    DeepAuditOptions {
        max_steps: read_deep_audit_u32(input, "maxSteps", 24),
        deposit_usd: input.get("depositUsd").and_then(Value::as_f64).unwrap_or(1.0),
        temperature: deep_audit_temperature(input),
        passes: read_deep_audit_u32(input, "passes", crate::capabilities::deep_auditor::DEFAULT_PASSES).max(1),
    }
}

fn read_deep_audit_u32(input: &Value, key: &str, default: u32) -> u32 {
    input
        .get(key)
        .and_then(Value::as_u64)
        .map(|v| v as u32)
        .unwrap_or(default)
}

fn deep_audit_temperature(input: &Value) -> f32 {
    input
        .get("temperature")
        .and_then(Value::as_f64)
        .map(|v| v.clamp(0.0, 2.0) as f32)
        .unwrap_or(crate::capabilities::deep_auditor::DEFAULT_TEMPERATURE)
}

fn deep_audit_routed_runtime<'a>(
    runtime: &'a dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    root: &std::path::Path,
) -> Result<crate::agent_router::RoutedRuntime<'a>> {
    use crate::agent_router::{AgentRouter, RoutedRuntime};
    use crate::config::ConfigPaths;
    use std::sync::Arc;

    let paths = ConfigPaths {
        home_dir: dirs::home_dir().unwrap_or_default(),
        target_dir: Some(root.to_path_buf()),
    };
    let router = Arc::new(AgentRouter::load(&paths)?);
    Ok(RoutedRuntime::borrowed(
        runtime,
        router,
        ctx.config.model.clone(),
    ))
}

fn deep_audit_spend_limiter(
    ctx: &ToolExecutionContext<'_>,
    workspace: &crate::WorkspaceTarget,
) -> Result<crate::spend::SpendLimiter> {
    crate::spend::SpendLimiter::open_with_hard_ceiling(
        workspace.findings_db_path(),
        ctx.config.operator.spend_hard_ceiling_usd,
    )
}

fn deep_audit_config(
    workspace: &crate::WorkspaceTarget,
    options: &DeepAuditOptions,
) -> crate::capabilities::deep_auditor::DeepAuditConfig {
    crate::capabilities::deep_auditor::DeepAuditConfig {
        workspace_root: workspace.root().to_path_buf(),
        max_steps: options.max_steps,
        deposit_usd: options.deposit_usd,
        system_prompt: None,
        include_static_evidence: true,
        temperature: options.temperature,
        passes: options.passes,
    }
}

fn persist_deep_audit_outcome(
    run: &DeepAuditRun<'_>,
    outcome: &crate::capabilities::deep_auditor::DeepAuditOutcome,
) -> Result<()> {
    let Some(id) = run.finding.id else {
        return Ok(());
    };
    run.store.save_triage(id, &outcome.triage)?;
    crate::capabilities::deep_auditor::save_evidence(
        &run.workspace.findings_db_path(),
        id,
        &outcome.evidence,
    )
}

fn deep_audit_response(
    finding: &crate::findings::Finding,
    outcome: crate::capabilities::deep_auditor::DeepAuditOutcome,
) -> Value {
    let summary = format!("deep-audit:run {}", outcome.triage.verdict.as_str());
    let data = json!({
        "findingId": finding.id,
        "fingerprint": finding.fingerprint,
        "verdict": outcome.triage.verdict,
        "confidence": outcome.triage.confidence,
        "rationale": outcome.triage.rationale,
        "stepsUsed": outcome.steps_used,
        "truncated": outcome.truncated,
        "costUsd": outcome.cost_usd,
        "evidence": outcome.evidence,
    });
    let mut result = crate::module_result::completed_output_result(summary.clone(), summary, data);
    result["costUsd"] = json!(outcome.cost_usd);
    result
}

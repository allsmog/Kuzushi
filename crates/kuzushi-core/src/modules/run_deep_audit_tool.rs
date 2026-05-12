use super::*;

pub(crate) fn run_deep_audit_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    use crate::agent_router::{AgentRouter, RoutedRuntime};
    use crate::capabilities::deep_auditor::{
        run_deep_auditor, save_evidence, DeepAuditConfig, DEFAULT_PASSES, DEFAULT_TEMPERATURE,
    };
    use crate::config::ConfigPaths;
    use crate::spend::SpendLimiter;
    use std::sync::Arc;

    let runtime = runtime.ok_or_else(|| {
        anyhow::anyhow!("deep-audit:run requires an agent runtime; none configured")
    })?;
    let workspace = ctx
        .workspace
        .ok_or_else(|| anyhow::anyhow!("deep-audit:run requires a workspace target"))?;
    let store = FindingStore::open(workspace.findings_db_path())?;

    let fingerprint = input
        .get("findingFingerprint")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("deep-audit:run: findingFingerprint is required"))?;
    let finding = store
        .get_finding_by_reference(fingerprint)?
        .ok_or_else(|| anyhow::anyhow!("deep-audit:run: no finding for {fingerprint:?}"))?;
    let max_steps = input
        .get("maxSteps")
        .and_then(Value::as_u64)
        .map(|v| v as u32)
        .unwrap_or(24);
    let deposit_usd = input
        .get("depositUsd")
        .and_then(Value::as_f64)
        .unwrap_or(1.0);
    let temperature = input
        .get("temperature")
        .and_then(Value::as_f64)
        .map(|v| v.clamp(0.0, 2.0) as f32)
        .unwrap_or(DEFAULT_TEMPERATURE);
    let passes = input
        .get("passes")
        .and_then(Value::as_u64)
        .map(|v| v.max(1) as u32)
        .unwrap_or(DEFAULT_PASSES);

    let paths = ConfigPaths {
        home_dir: dirs::home_dir().unwrap_or_default(),
        target_dir: Some(workspace.root().to_path_buf()),
    };
    let router = Arc::new(AgentRouter::load(&paths)?);
    let inner_arc: Arc<dyn AgentRuntime> = unsafe_clone_runtime_ref(runtime);
    let routed = RoutedRuntime::new(inner_arc, router, ctx.config.model.clone());
    let spend = SpendLimiter::open_with_hard_ceiling(
        workspace.findings_db_path(),
        ctx.config.operator.spend_hard_ceiling_usd,
    )?;

    let cfg = DeepAuditConfig {
        workspace_root: workspace.root().to_path_buf(),
        max_steps,
        deposit_usd,
        system_prompt: None,
        include_static_evidence: true,
        temperature,
        passes,
    };
    let outcome = run_deep_auditor(&routed, Some(&spend), &cfg, &finding)?;

    if let Some(id) = finding.id {
        store.save_triage(id, &outcome.triage)?;
        save_evidence(&workspace.findings_db_path(), id, &outcome.evidence)?;
    }

    Ok(json!({
        "ok": true,
        "data": {
            "findingId": finding.id,
            "fingerprint": finding.fingerprint,
            "verdict": outcome.triage.verdict,
            "confidence": outcome.triage.confidence,
            "rationale": outcome.triage.rationale,
            "stepsUsed": outcome.steps_used,
            "truncated": outcome.truncated,
            "costUsd": outcome.cost_usd,
            "evidence": outcome.evidence,
        },
    }))
}

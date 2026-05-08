use super::*;

pub(crate) fn full_mode_config_paths(ctx: &ToolExecutionContext<'_>) -> crate::config::ConfigPaths {
    let target_dir = ctx
        .workspace
        .map(|workspace| workspace.root().to_path_buf());
    crate::config::ConfigPaths {
        home_dir: dirs::home_dir().unwrap_or_default(),
        target_dir,
    }
}

pub(crate) fn full_mode_spend_limiter(
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<crate::spend::SpendLimiter>> {
    ctx.workspace
        .map(|w| crate::spend::SpendLimiter::open(w.findings_db_path()))
        .transpose()
}

pub(crate) fn persist_full_mode_report(
    ctx: &ToolExecutionContext<'_>,
    report: &crate::full_mode_multi::FullModeReport,
) -> Result<()> {
    let Some(workspace) = ctx.workspace else {
        return Ok(());
    };
    let store = FindingStore::open(workspace.findings_db_path())?;
    let scan_id = format!("full-mode-{}", uuid::Uuid::new_v4());
    store.insert_scan_run(&scan_id, workspace.root(), "running")?;
    for finding in &report.findings {
        let _ = store.insert_finding(&scan_id, finding)?;
    }
    store.complete_scan_run(&scan_id, "completed", report.findings.len())?;
    Ok(())
}

pub(crate) fn run_classifier_score_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    use crate::agent_router::{AgentRouter, RoutedRuntime};
    use crate::classifier_gate::{ClassifierConfig, LikelyVulnClassifier};
    use crate::config::ConfigPaths;
    use std::sync::Arc;

    let runtime = runtime.ok_or_else(|| {
        anyhow::anyhow!("classifier-gate:score requires an agent runtime; none configured")
    })?;
    let workspace = ctx
        .workspace
        .ok_or_else(|| anyhow::anyhow!("classifier-gate:score requires a workspace target"))?;
    let store = FindingStore::open(workspace.findings_db_path())?;

    let fingerprint = input
        .get("findingFingerprint")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("classifier-gate:score: findingFingerprint is required"))?;
    let finding = store
        .get_finding_by_reference(fingerprint)?
        .ok_or_else(|| anyhow::anyhow!("classifier-gate:score: no finding for {fingerprint:?}"))?;
    let target_percentile = input
        .get("targetPercentile")
        .and_then(Value::as_f64)
        .map(|v| v as f32)
        .unwrap_or(0.80);

    let paths = ConfigPaths {
        home_dir: dirs::home_dir().unwrap_or_default(),
        target_dir: Some(workspace.root().to_path_buf()),
    };
    let router = Arc::new(AgentRouter::load(&paths)?);
    let inner_arc: Arc<dyn AgentRuntime> = unsafe_clone_runtime_ref(runtime);
    let routed = RoutedRuntime::new(inner_arc, router, ctx.config.model.clone());

    let cfg = ClassifierConfig {
        target_percentile,
        state_db: Some(workspace.findings_db_path()),
        ..Default::default()
    };
    let gate = LikelyVulnClassifier::new(&routed, cfg)?;
    let score = gate.score(&finding, workspace.root())?;
    let should_audit = gate.should_deep_audit(score);
    let threshold = gate.current_threshold();
    let n = gate.samples_seen();

    if !should_audit {
        if let Some(id) = finding.id {
            let outcome = gate.skip_outcome(score);
            store.save_triage(id, &outcome)?;
        }
    }

    Ok(json!({
        "ok": true,
        "data": {
            "findingId": finding.id,
            "fingerprint": finding.fingerprint,
            "score": score,
            "shouldDeepAudit": should_audit,
            "threshold": threshold,
            "samplesSeen": n,
        },
    }))
}

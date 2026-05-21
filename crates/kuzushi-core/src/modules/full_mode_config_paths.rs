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
        .map(|w| {
            crate::spend::SpendLimiter::open_with_hard_ceiling(
                w.findings_db_path(),
                ctx.config.operator.spend_hard_ceiling_usd,
            )
        })
        .transpose()
}

pub(crate) fn persist_full_mode_report(
    ctx: &ToolExecutionContext<'_>,
    report: &crate::capabilities::full_mode_multi::FullModeReport,
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
    let run = prepare_classifier_score(&input, ctx, runtime)?;
    let routed = classifier_routed_runtime(run.runtime, ctx, run.workspace.root())?;
    let gate = classifier_gate(&routed, run.workspace, run.target_percentile)?;
    let score = gate.score(&run.finding, run.workspace.root())?;
    let should_audit = gate.should_deep_audit(score);
    let threshold = gate.current_threshold();
    let n = gate.samples_seen();
    save_classifier_skip_if_needed(&run, &gate, score, should_audit)?;
    Ok(classifier_score_response(
        &run.finding,
        score,
        should_audit,
        threshold,
        n,
    ))
}

struct ClassifierScoreRun<'a> {
    runtime: &'a dyn AgentRuntime,
    workspace: &'a crate::WorkspaceTarget,
    store: FindingStore,
    finding: crate::findings::Finding,
    target_percentile: f32,
}

fn prepare_classifier_score<'a>(
    input: &Value,
    ctx: &'a ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<ClassifierScoreRun<'a>> {
    let runtime = required_classifier_runtime(runtime)?;
    let workspace = required_classifier_workspace(ctx)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let finding = classifier_finding(input, &store)?;
    Ok(ClassifierScoreRun {
        runtime,
        workspace,
        store,
        finding,
        target_percentile: classifier_target_percentile(input),
    })
}

fn required_classifier_runtime(runtime: Option<&dyn AgentRuntime>) -> Result<&dyn AgentRuntime> {
    runtime.ok_or_else(|| {
        anyhow::anyhow!("classifier-gate:score requires an agent runtime; none configured")
    })
}

fn required_classifier_workspace<'a>(
    ctx: &ToolExecutionContext<'a>,
) -> Result<&'a crate::WorkspaceTarget> {
    ctx.workspace
        .ok_or_else(|| anyhow::anyhow!("classifier-gate:score requires a workspace target"))
}

fn classifier_finding(
    input: &Value,
    store: &FindingStore,
) -> Result<crate::findings::Finding> {
    let fingerprint = input
        .get("findingFingerprint")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("classifier-gate:score: findingFingerprint is required"))?;
    store
        .get_finding_by_reference(fingerprint)?
        .ok_or_else(|| anyhow::anyhow!("classifier-gate:score: no finding for {fingerprint:?}"))
}

fn classifier_target_percentile(input: &Value) -> f32 {
    input
        .get("targetPercentile")
        .and_then(Value::as_f64)
        .map(|v| v as f32)
        .unwrap_or(0.80)
}

fn classifier_routed_runtime<'a>(
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

fn classifier_gate<'a>(
    runtime: &'a crate::agent_router::RoutedRuntime<'a>,
    workspace: &crate::WorkspaceTarget,
    target_percentile: f32,
) -> Result<crate::capabilities::classifier_gate::LikelyVulnClassifier<'a>> {
    use crate::capabilities::classifier_gate::{ClassifierConfig, LikelyVulnClassifier};

    let cfg = ClassifierConfig {
        target_percentile,
        state_db: Some(workspace.findings_db_path()),
        ..Default::default()
    };
    LikelyVulnClassifier::new(runtime, cfg)
}

fn save_classifier_skip_if_needed(
    run: &ClassifierScoreRun<'_>,
    gate: &crate::capabilities::classifier_gate::LikelyVulnClassifier<'_>,
    score: f32,
    should_audit: bool,
) -> Result<()> {
    let Some(id) = run.finding.id.filter(|_| !should_audit) else {
        return Ok(());
    };
    let outcome = gate.skip_outcome(score);
    run.store.save_triage(id, &outcome)
}

fn classifier_score_response(
    finding: &crate::findings::Finding,
    score: f32,
    should_audit: bool,
    threshold: f32,
    samples_seen: usize,
) -> Value {
    let summary = format!(
        "classifier-gate:score {:.3} ({})",
        score,
        if should_audit { "audit" } else { "skip" }
    );
    let data = json!({
        "findingId": finding.id,
        "fingerprint": finding.fingerprint,
        "score": score,
        "shouldDeepAudit": should_audit,
        "threshold": threshold,
        "samplesSeen": samples_seen,
    });
    crate::module_result::completed_output_result(summary.clone(), summary, data)
}
